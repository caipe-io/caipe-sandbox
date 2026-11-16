"""Configure one Sandbox MCP resource in an existing Keycloak realm; preview by default."""

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

OWNER = "sandbox.mcp.resource"
POLICIES = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
SCOPE = "sandbox:mcp"


def https_url(value):
    parsed = urlsplit(value)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in value)
        or parsed.port == 0
        or (
            parsed.scheme != "https"
            and not (
                parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            )
        )
    ):
        raise ValueError(
            "URLs must use HTTPS without credentials, query or fragment (HTTP only on loopback)"
        )
    return value.rstrip("/")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class Keycloak:
    def __init__(self, issuer, token=None):
        self.issuer = https_url(issuer)
        self.base, separator, realm = self.issuer.rpartition("/realms/")
        if not separator or not re.fullmatch(r"[A-Za-z0-9_-]+", realm):
            raise ValueError("Issuer must end in /realms/<realm-name>")
        self.root = self.base + "/admin/realms/" + realm + "/"
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, url, method="GET", data=None, *, form=False, authenticated=False):
        headers = {}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if data is not None:
            headers["Content-Type"] = (
                "application/x-www-form-urlencoded" if form else "application/json"
            )
            data = urlencode(data).encode() if form else json.dumps(data).encode()
        request = Request(url, data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=20) as response:
            body = response.read()
            return json.loads(body) if body else None

    def login(self):
        if not self.token:
            username = os.environ.get("KEYCLOAK_ADMIN_USERNAME")
            password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
            if not username or not password:
                raise ValueError(
                    "Set KEYCLOAK_ADMIN_TOKEN, or KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD"
                )
            realm = quote(os.environ.get("KEYCLOAK_ADMIN_REALM", "master"), safe="")
            grant = self.request(
                self.base + f"/realms/{realm}/protocol/openid-connect/token",
                "POST",
                {
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": username,
                    "password": password,
                },
                form=True,
            )
            self.token = grant["access_token"]

    def __call__(self, path, method="GET", data=None):
        return self.request(self.root + path, method, data, authenticated=True)


def mappers(resource):
    token = {
        "access.token.claim": "true",
        "id.token.claim": "false",
        "userinfo.token.claim": "false",
        "introspection.token.claim": "true",
    }
    return [
        {
            "name": "sandbox-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {**token, "included.custom.audience": resource},
        },
        {
            "name": "sandbox-subject",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-sub-mapper",
            "config": {"access.token.claim": "true", "introspection.token.claim": "true"},
        },
        *[
            {
                "name": "sandbox-" + claim,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-property-mapper",
                "config": {
                    **token,
                    "user.attribute": property_name,
                    "claim.name": claim,
                    "jsonType.label": kind,
                },
            }
            for claim, property_name, kind in (
                ("email", "email", "String"),
                ("email_verified", "emailVerified", "boolean"),
            )
        ],
    ]


def mapper_matches(current, desired):
    return all(
        current.get(k) == desired[k] for k in ("name", "protocol", "protocolMapper")
    ) and all(current.get("config", {}).get(k) == v for k, v in desired["config"].items())


def configure(api, resource, scope=SCOPE, *, apply=False, configure_dcr=False):
    resource = https_url(resource)
    if not urlsplit(resource).path.endswith("/api/mcp"):
        raise ValueError("Resource URL must end in the Sandbox base path plus /api/mcp")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+:[A-Za-z0-9:._/-]+", scope):
        raise ValueError("Use an application-specific scope, for example sandbox:mcp")
    current = next((s for s in api("client-scopes") if s["name"] == scope), None)
    if current and (current.get("attributes") or {}).get(OWNER) != resource:
        raise ValueError(
            f"Scope {scope} is not owned by this Sandbox resource; choose a different scope or review it manually"
        )
    allowed = []
    if configure_dcr:
        components = api("components?type=" + POLICIES)
        providers = {c["providerId"] for c in components if c.get("subType") == "anonymous"}
        if {"consent-required", "scope"} - providers:
            raise ValueError(
                "Configure Keycloak's anonymous Consent Required and Full Scope Disabled registration policies first; this helper does not enable DCR"
            )
        allowed = [
            c
            for c in components
            if c.get("providerId") == "allowed-client-templates" and c.get("subType") == "anonymous"
        ]
        if len(allowed) > 1:
            raise ValueError(
                "Multiple anonymous Allowed Client Scopes policies exist; review them before configuration"
            )
        if allowed and "openid" not in (allowed[0].get("config") or {}).get(
            "allowed-client-scopes", []
        ):
            raise ValueError(
                "The existing anonymous scope allow-list does not permit openid. Configure the realm's OIDC/DCR prerequisites first; no Sandbox entries changed"
            )
    optional = api("default-optional-client-scopes")
    existing_mappers = (
        api(f"client-scopes/{current['id']}/protocol-mappers/models") if current else []
    )
    desired_mappers = mappers(resource)
    for desired in desired_mappers:
        if sum(m["name"] == desired["name"] for m in existing_mappers) > 1:
            raise ValueError(
                f"Duplicate managed mapper {desired['name']}; review it before configuration"
            )
    desired = {
        "name": scope,
        "protocol": "openid-connect",
        "description": "Sandbox MCP access",
        "attributes": {
            **((current or {}).get("attributes") or {}),
            OWNER: resource,
            "include.in.token.scope": "true",
            "display.on.consent.screen": "true",
            "consent.screen.text": "Access my MCP-enabled sandboxes",
        },
    }
    changes = []

    def change(label, path, method, data=None):
        changes.append(label)
        if apply:
            api(path, method, data)

    if current is None:
        change(
            f"Create {scope} with Sandbox audience and identity mappers",
            "client-scopes",
            "POST",
            {**desired, "protocolMappers": desired_mappers},
        )
        if apply:
            current = next(s for s in api("client-scopes") if s["name"] == scope)
            if (current.get("attributes") or {}).get(OWNER) != resource:
                raise ValueError("Scope ownership changed during setup; inspect it before retrying")
    else:
        if any(current.get(k) != v for k, v in desired.items()):
            change(
                f"Update {scope} consent settings", f"client-scopes/{current['id']}", "PUT", desired
            )
        for mapper in desired_mappers:
            found = next((m for m in existing_mappers if m["name"] == mapper["name"]), None)
            path = f"client-scopes/{current['id']}/protocol-mappers/models"
            if found is None:
                change(f"Add {mapper['name']}", path, "POST", mapper)
            elif not mapper_matches(found, mapper):
                change(
                    f"Update {mapper['name']}",
                    path + "/" + found["id"],
                    "PUT",
                    {**mapper, "id": found["id"]},
                )
    if current is None or not any(s["id"] == current["id"] for s in optional):
        path = "default-optional-client-scopes/" + (current["id"] if current else "")
        change(f"Make {scope} optional for new OAuth clients", path, "PUT")
    if allowed:
        policy = allowed[0]
        config = policy.get("config") or {}
        if scope not in config.get("allowed-client-scopes", []):
            updated = {
                **policy,
                "config": {
                    **config,
                    "allowed-client-scopes": [*config.get("allowed-client-scopes", []), scope],
                },
            }
            change(
                f"Append only {scope} to the existing anonymous scope allow-list",
                "components/" + policy["id"],
                "PUT",
                updated,
            )
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True, help="Public Keycloak realm issuer URL")
    parser.add_argument("--resource-url", required=True, help="Exact public Sandbox MCP URL")
    parser.add_argument("--scope", default=SCOPE)
    parser.add_argument(
        "--configure-dcr",
        action="store_true",
        help="Also check existing DCR prerequisites and add the scope to its existing allow-list; does not enable DCR",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the listed changes; default is read-only preview",
    )
    args = parser.parse_args()
    api = Keycloak(args.issuer, os.environ.get("KEYCLOAK_ADMIN_TOKEN"))
    metadata = api.request(api.issuer + "/.well-known/openid-configuration")
    if metadata.get("issuer") != api.issuer:
        raise ValueError("Discovery issuer does not match --issuer")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise ValueError("Issuer must advertise S256 PKCE for authenticated MCP")
    if args.configure_dcr and not metadata.get("registration_endpoint"):
        raise ValueError("--configure-dcr requires the issuer to advertise a registration_endpoint")
    jwks = https_url(metadata["jwks_uri"])
    api.login()
    changes = configure(
        api, args.resource_url, args.scope, apply=args.apply, configure_dcr=args.configure_dcr
    )
    if args.apply and configure(
        api, args.resource_url, args.scope, configure_dcr=args.configure_dcr
    ):
        raise ValueError("Setup is incomplete; rerun the preview to inspect remaining changes")
    print("Applied:" if args.apply else "Preview (no configuration writes):")
    for change in changes:
        print("- " + change)
    if not changes:
        print("No changes required.")
    print("\nSandbox Helm values:")
    print("mcp:\n  enabled: true")
    for key, value in {
        "resource_url": https_url(args.resource_url),
        "issuer": api.issuer,
        "jwks_url": jwks,
        "read_scope": args.scope,
        "execute_scope": args.scope,
    }.items():
        print(f"  {key}: {json.dumps(value)}")
    if not args.apply:
        print("\nRerun with --apply to make the listed changes.")
    print(
        "Use pre-registration, CIMD or optional DCR as supported by your client and issuer. Existing clients keep their assignments; attach this scope to them explicitly if needed."
    )


if __name__ == "__main__":
    try:
        main()
    except HTTPError as exc:
        print(
            f"Keycloak setup failed: HTTP {exc.code}. Check permissions/readiness, then rerun the preview. Responses and credentials are not logged.",
            file=sys.stderr,
        )
        sys.exit(1)
    except (ValueError, KeyError, URLError, TimeoutError, StopIteration) as exc:
        print(f"Keycloak setup failed: {exc}", file=sys.stderr)
        sys.exit(1)
