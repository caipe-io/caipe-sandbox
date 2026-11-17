import copy
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

SPEC = importlib.util.spec_from_file_location(
    "keycloak_mcp", Path(__file__).parents[1] / "integrations/keycloak/configure-mcp.py"
)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)
RESOURCE = "https://sandbox.example.com/apps/sandbox/api/mcp"
ISSUER = "https://idp.example.com/realms/example"


class Realm:
    def __init__(self):
        self.scopes = [
            {
                "id": "other",
                "name": "other:access",
                "attributes": {},
                "protocolMappers": [
                    {
                        "name": "other-audience",
                        "config": {"included.custom.audience": "https://other.example.com/mcp"},
                    }
                ],
            }
        ]
        self.optional = ["other"]
        self.components = [
            {"id": "consent", "providerId": "consent-required", "subType": "anonymous"},
            {"id": "full-scope", "providerId": "scope", "subType": "anonymous"},
            {
                "id": "allowed",
                "providerId": "allowed-client-templates",
                "subType": "anonymous",
                "config": {
                    "allowed-client-scopes": ["openid", "other:access"],
                    "allow-default-scopes": ["false"],
                },
            },
            {
                "id": "hosts",
                "providerId": "trusted-hosts",
                "subType": "anonymous",
                "config": {
                    "trusted-hosts": ["localhost"],
                    "host-sending-registration-request-must-match": ["false"],
                },
            },
            {
                "id": "limit",
                "providerId": "max-clients",
                "subType": "anonymous",
                "config": {"max-clients": ["100"]},
            },
        ]
        self.writes = []
        self.fail_assignment_once = False

    def __call__(self, path, method="GET", data=None):
        if method != "GET":
            self.writes.append((path, method))
        data = copy.deepcopy(data)
        if path == "client-scopes":
            if method == "POST":
                data["id"] = str(len(self.scopes))
                for i, mapper in enumerate(data["protocolMappers"]):
                    mapper["id"] = str(i)
                self.scopes.append(data)
            return copy.deepcopy(self.scopes)
        if path == "components?type=" + setup.POLICIES:
            return copy.deepcopy(self.components)
        if path.startswith("components/") and method == "PUT":
            current = next(c for c in self.components if c["id"] == path.split("/")[1])
            current.update(data)
            return None
        if path.startswith("default-optional-client-scopes"):
            if method == "PUT":
                if self.fail_assignment_once:
                    self.fail_assignment_once = False
                    raise HTTPError(path, 503, "Temporary failure", None, None)
                self.optional.append(path.split("/")[1])
            return [copy.deepcopy(s) for s in self.scopes if s["id"] in self.optional]
        parts = path.split("/")
        if parts[0] != "client-scopes":
            raise AssertionError("Unexpected API operation: " + path)
        scope = next(s for s in self.scopes if s["id"] == parts[1])
        if len(parts) == 2 and method == "PUT":
            scope.update(data)
            return None
        if method == "POST":
            scope["protocolMappers"].append({**data, "id": str(len(scope["protocolMappers"]))})
        elif method == "PUT":
            current = next(m for m in scope["protocolMappers"] if m["id"] == parts[-1])
            current.update(data)
        return copy.deepcopy(scope["protocolMappers"])


class KeycloakMCPTests(unittest.TestCase):
    def test_default_preview_is_read_only_without_registration_policy_changes(self):
        realm = Realm()
        before = copy.deepcopy(realm.__dict__)
        changes = setup.configure(realm, RESOURCE)
        self.assertTrue(any("Create sandbox:mcp" in change for change in changes))
        self.assertFalse(any("allow-list" in change for change in changes))
        self.assertEqual(realm.__dict__, before)

    def test_apply_preserves_other_applications_and_shared_policies(self):
        realm = Realm()
        other = copy.deepcopy(realm.scopes[0])
        guards = copy.deepcopy(realm.components)
        setup.configure(realm, RESOURCE, apply=True)
        self.assertEqual(realm.scopes[0], other)
        self.assertEqual(realm.components, guards)
        owned = realm.scopes[1]
        self.assertEqual(owned["attributes"][setup.OWNER], RESOURCE)
        audience = next(m for m in owned["protocolMappers"] if m["name"] == "sandbox-audience")
        self.assertEqual(audience["config"]["included.custom.audience"], RESOURCE)
        verified = next(
            m for m in owned["protocolMappers"] if m["name"] == "sandbox-email_verified"
        )
        self.assertEqual(verified["config"]["user.attribute"], "emailVerified")
        writes = list(realm.writes)
        self.assertEqual(setup.configure(realm, RESOURCE, apply=True), [])
        self.assertEqual(realm.writes, writes)

    def test_retry_finishes_partial_setup_without_creating_duplicate_scopes(self):
        realm = Realm()
        realm.fail_assignment_once = True
        with self.assertRaises(HTTPError):
            setup.configure(realm, RESOURCE, apply=True)
        self.assertEqual(len(realm.scopes), 2)
        setup.configure(realm, RESOURCE, apply=True)
        self.assertEqual(len(realm.scopes), 2)
        self.assertEqual(setup.configure(realm, RESOURCE), [])

    def test_owned_updates_preserve_operator_mappers_and_attributes(self):
        realm = Realm()
        setup.configure(realm, RESOURCE, apply=True)
        owned = realm.scopes[1]
        owned["attributes"]["operator"] = "preserve"
        custom = {"id": "custom", "name": "custom-group-mapper", "config": {"claim.name": "groups"}}
        owned["protocolMappers"].append(copy.deepcopy(custom))
        owned["protocolMappers"][0]["config"]["included.custom.audience"] = (
            "https://wrong.example.com/mcp"
        )
        setup.configure(realm, RESOURCE, apply=True)
        self.assertEqual(owned["protocolMappers"][-1], custom)
        self.assertEqual(owned["attributes"]["operator"], "preserve")
        self.assertEqual(
            owned["protocolMappers"][0]["config"]["included.custom.audience"], RESOURCE
        )

    def test_unmanaged_or_differently_bound_scopes_fail_before_writes(self):
        for attributes in ({}, {setup.OWNER: "https://different.example.com/api/mcp"}):
            with self.subTest(attributes=attributes):
                realm = Realm()
                realm.scopes.append(
                    {"id": "conflict", "name": "sandbox:mcp", "attributes": attributes}
                )
                with self.assertRaisesRegex(ValueError, "not owned"):
                    setup.configure(realm, RESOURCE, apply=True)
                self.assertEqual(realm.writes, [])

    def test_missing_consent_policy_does_not_enable_or_reconfigure_dcr(self):
        realm = Realm()
        realm.components.pop(0)
        with self.assertRaisesRegex(ValueError, "does not enable DCR"):
            setup.configure(realm, RESOURCE, apply=True, configure_dcr=True)
        self.assertEqual(realm.writes, [])

    def test_missing_openid_registration_permission_fails_before_writes(self):
        realm = Realm()
        realm.components[2]["config"]["allowed-client-scopes"].remove("openid")
        with self.assertRaisesRegex(ValueError, "does not permit openid"):
            setup.configure(realm, RESOURCE, apply=True, configure_dcr=True)
        self.assertEqual(realm.writes, [])

    def test_absent_scope_allowlist_is_not_replaced_with_a_new_shared_policy(self):
        realm = Realm()
        realm.components.pop(2)
        before = copy.deepcopy(realm.components)
        setup.configure(realm, RESOURCE, apply=True, configure_dcr=True)
        self.assertEqual(realm.components, before)

    def test_default_setup_never_reads_or_writes_registration_policies(self):
        realm = Realm()
        realm.components = []

        def api(path, method="GET", data=None):
            self.assertFalse(
                path.startswith("components"), "Registration policies are outside default setup"
            )
            return realm(path, method, data)

        setup.configure(api, RESOURCE, apply=True)
        self.assertEqual(setup.configure(api, RESOURCE, apply=True), [])
        self.assertEqual(realm.components, [])

    def test_dcr_opt_in_previews_and_updates_only_the_existing_scope_allowlist(self):
        realm = Realm()
        before = copy.deepcopy(realm.__dict__)
        changes = setup.configure(realm, RESOURCE, configure_dcr=True)
        self.assertTrue(any("allow-list" in change for change in changes))
        self.assertEqual(realm.__dict__, before)
        setup.configure(realm, RESOURCE, apply=True, configure_dcr=True)
        self.assertEqual(realm.components[:2], before["components"][:2])
        self.assertEqual(realm.components[3:], before["components"][3:])
        self.assertEqual(realm.components[2]["config"]["allow-default-scopes"], ["false"])
        self.assertEqual(
            realm.components[2]["config"]["allowed-client-scopes"],
            ["openid", "other:access", "sandbox:mcp"],
        )
        writes = list(realm.writes)
        self.assertEqual(setup.configure(realm, RESOURCE, apply=True, configure_dcr=True), [])
        self.assertEqual(realm.writes, writes)

    def test_missing_openid_in_dcr_policy_does_not_block_default_setup(self):
        realm = Realm()
        realm.components[2]["config"]["allowed-client-scopes"].remove("openid")
        before = copy.deepcopy(realm.components)
        setup.configure(realm, RESOURCE, apply=True)
        self.assertEqual(realm.components, before)

    def test_cli_accepts_discovery_without_dcr_for_pre_registration_or_cimd(self):
        for cimd in (False, True):
            with self.subTest(cimd=cimd):
                api = self.issuer(cimd=cimd)
                self.run_cli(api, "--apply")
                self.assertTrue(api.logged_in)
                self.assertEqual(len(api.scopes), 2)
                self.assertFalse(any(path.startswith("components") for path, method in api.writes))

    def test_cli_dcr_opt_in_requires_registration_metadata_before_writes(self):
        api = self.issuer()
        with self.assertRaisesRegex(ValueError, "registration_endpoint"):
            self.run_cli(api, "--configure-dcr", "--apply")
        self.assertFalse(api.logged_in)
        self.assertEqual(api.writes, [])

    def test_cli_still_requires_s256_with_every_registration_method(self):
        api = self.issuer()
        api.metadata["code_challenge_methods_supported"] = ["plain"]
        with self.assertRaisesRegex(ValueError, "S256 PKCE"):
            self.run_cli(api, "--apply")
        self.assertFalse(api.logged_in)
        self.assertEqual(api.writes, [])

    def issuer(self, *, cimd=False):
        api = Realm()
        api.issuer = ISSUER
        api.metadata = {
            "issuer": ISSUER,
            "jwks_uri": ISSUER + "/protocol/openid-connect/certs",
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": cimd,
        }
        api.logged_in = False

        def login():
            api.logged_in = True

        api.login = login
        api.request = lambda url: copy.deepcopy(api.metadata)
        return api

    def run_cli(self, api, *arguments):
        argv = ["configure-mcp.py", "--issuer", ISSUER, "--resource-url", RESOURCE, *arguments]
        with (
            patch.object(setup, "Keycloak", return_value=api),
            patch("sys.argv", argv),
            redirect_stdout(io.StringIO()),
        ):
            setup.main()

    def test_invalid_urls_and_reserved_scopes_do_not_write(self):
        for url, scope in (
            ("http://remote.example.com/api/mcp", "sandbox:mcp"),
            ("https://user:password@example.com/api/mcp", "sandbox:mcp"),
            (RESOURCE + "?token=secret", "sandbox:mcp"),
            (RESOURCE, "openid"),
        ):
            with self.subTest(url=url, scope=scope):
                realm = Realm()
                with self.assertRaises(ValueError):
                    setup.configure(realm, url, scope, apply=True)
                self.assertEqual(realm.writes, [])

    def test_http_client_refuses_credential_forwarding_redirects(self):
        self.assertIsNone(
            setup.NoRedirect().redirect_request(
                None, None, 302, "Found", {}, "https://other.example.com"
            )
        )

    def test_private_admin_url_keeps_the_public_issuer(self):
        api = setup.Keycloak(ISSUER, admin_url="https://admin.example.com/auth/")
        self.assertEqual(api.issuer, ISSUER)
        with patch.object(api, "request", return_value=[]) as request:
            api("client-scopes")
        request.assert_called_once_with(
            "https://admin.example.com/auth/admin/realms/example/client-scopes",
            "GET",
            None,
            authenticated=True,
        )

    def test_admin_login_uses_private_endpoint_with_loopback_http(self):
        api = setup.Keycloak(ISSUER, admin_url="http://127.0.0.1:18080")
        with (
            patch.dict(
                setup.os.environ,
                {
                    "KEYCLOAK_ADMIN_USERNAME": "operator",
                    "KEYCLOAK_ADMIN_PASSWORD": "example-only",
                    "KEYCLOAK_ADMIN_REALM": "master",
                },
            ),
            patch.object(api, "request", return_value={"access_token": "example-token"}) as request,
        ):
            api.login()
        self.assertEqual(
            request.call_args.args[0],
            "http://127.0.0.1:18080/realms/master/protocol/openid-connect/token",
        )
        self.assertEqual(api.issuer, ISSUER)

    def test_private_admin_url_rejects_remote_http_and_embedded_credentials(self):
        for url in (
            "http://admin.example.com",
            "https://operator:password@admin.example.com",
            "https://admin.example.com?token=example",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                setup.Keycloak(ISSUER, admin_url=url)

    def test_cli_passes_admin_url_without_changing_discovery(self):
        api = self.issuer()
        with patch.object(setup, "Keycloak", return_value=api) as constructor:
            argv = [
                "configure-mcp.py",
                "--issuer",
                ISSUER,
                "--admin-url",
                "http://127.0.0.1:18080",
                "--resource-url",
                RESOURCE,
            ]
            with patch("sys.argv", argv), redirect_stdout(io.StringIO()):
                setup.main()
        self.assertEqual(constructor.call_args.kwargs["admin_url"], "http://127.0.0.1:18080")
        self.assertEqual(api.issuer, ISSUER)


if __name__ == "__main__":
    unittest.main()
