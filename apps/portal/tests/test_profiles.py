import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from inventory_fakes import as_sandbox
from kubernetes.client import ApiException
from test_portal import BASE, HEADERS, OTHER, OWNER, SETTINGS, Kubernetes, Omnigent
from test_provisioning import CleanupKubernetes

from portal.app import create_app
from portal.config import Settings, runtime_classes, sandbox_security_context
from portal.integrations.agent_sandbox import execution
from portal.namespaces import UserNamespaces, namespace_config, namespace_name
from portal.profiles import Profiles, applied, helper
from portal.sandboxes import Store
from portal.storage import Conflict


def store_for(settings=SETTINGS, kube=None):
    kube = kube or Kubernetes()
    return Store(
        settings,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(settings, kube, kube, kube),
        metadata=kube.metadata,
    ), kube


def test_namespace_baseline_network_policy_is_off_by_default():
    settings = replace(SETTINGS, namespace_policy=Settings().namespace_policy)
    store, kube = store_for(settings)
    sandbox = store.create(OWNER).reference
    namespace = sandbox["metadata"]["namespace"]
    assert ("NetworkPolicy", namespace, "sandbox-isolation") not in kube.baseline
    assert ("RoleBinding", namespace, "sandbox-portal-access") in kube.baseline


def test_disabling_baseline_does_not_delete_an_existing_policy():
    store, kube = store_for()
    first = store.create(OWNER).reference
    key = ("NetworkPolicy", first["metadata"]["namespace"], "sandbox-isolation")
    original = deepcopy(kube.baseline[key])
    settings = replace(SETTINGS, namespace_policy=Settings().namespace_policy)
    second, _ = store_for(settings, kube)
    second.create(OWNER)
    assert kube.baseline[key] == original


def test_default_catalog_has_an_agent_independent_preset():
    profiles = Profiles(SETTINGS)
    terminal = profiles.get("terminal")
    assert "omnigent" not in terminal.model_dump()
    assert terminal.openShell is None
    assert terminal.agentSandbox.spec["podTemplate"]["spec"]["containers"][0][
        "command"
    ] == ["sleep", "infinity"]
    assert {p.id for p in profiles.items.values()} == {"development", "terminal"}


def test_runtime_classes_default_to_the_configured_runtime():
    assert runtime_classes(SETTINGS) == [SETTINGS.runtime_class]
    settings = replace(SETTINGS, runtime_class="sandbox.example")
    profiles = Profiles(settings)
    profile = profiles.get("terminal")
    assert (
        profiles.render(profile, profiles.size(profile))["podTemplate"]["spec"][
            "runtimeClassName"
        ]
        == "sandbox.example"
    )


@pytest.mark.parametrize(
    "classes",
    [
        [],
        {},
        "kata-dev",
        [None],
        [""],
        ["UPPER"],
        ["bad/name"],
        ["x" * 254],
        ["kata-dev", "kata-dev"],
        ["kata-fc"],
    ],
)
def test_runtime_class_configuration_rejects_invalid_or_missing_defaults(classes):
    with pytest.raises(ValueError):
        Profiles(replace(SETTINGS, allowed_runtime_classes=json.dumps(classes)))


def test_profiles_select_only_deployment_approved_runtime_classes():
    definition = Profiles(SETTINGS).get("terminal").model_dump(exclude_none=True)
    definition["agentSandbox"]["spec"]["podTemplate"]["spec"]["runtimeClassName"] = (
        "kata-fc"
    )
    settings = replace(
        SETTINGS,
        profiles=json.dumps([definition]),
        default_profile="terminal",
        allowed_runtime_classes='["kata-dev","kata-fc"]',
    )
    store, kube = store_for(settings)
    cr = store.create(OWNER).reference
    assert cr["spec"]["podTemplate"]["spec"]["runtimeClassName"] == "kata-fc"
    assert (
        applied(as_sandbox(store, cr))["definition"]["agentSandbox"]["spec"][
            "podTemplate"
        ]["spec"]["runtimeClassName"]
        == "kata-fc"
    )
    restarted, _ = store_for(replace(settings, runtime_class="kata-fc"), kube)
    restarted.mode(cr["metadata"]["name"], OWNER, "Suspended").reference
    assert (
        restarted.mode(cr["metadata"]["name"], OWNER, "Running").reference["spec"][
            "podTemplate"
        ]["spec"]["runtimeClassName"]
        == "kata-fc"
    )
    for approved in ("null", '["kata-dev"]'):
        with pytest.raises(ValueError, match="approved runtime class"):
            Profiles(replace(settings, allowed_runtime_classes=approved))


def test_runtime_class_allowlist_is_loaded_from_environment(monkeypatch):
    monkeypatch.setenv("PORTAL_PROFILES", SETTINGS.profiles)
    monkeypatch.setenv("PORTAL_DEFAULT_PROFILE", SETTINGS.default_profile)
    monkeypatch.setenv("PORTAL_AUTH_MODE", "omnigent")
    monkeypatch.setenv("PORTAL_AUTH_OMNIGENT_URL", SETTINGS.auth_omnigent_url)
    monkeypatch.setenv("PORTAL_RUNTIME_CLASS", "kata-dev")
    monkeypatch.setenv("PORTAL_ALLOWED_RUNTIME_CLASSES", '["kata-dev","kata-fc"]')
    assert runtime_classes(Settings.from_env()) == ["kata-dev", "kata-fc"]
    monkeypatch.setenv("PORTAL_ALLOWED_RUNTIME_CLASSES", "[]")
    with pytest.raises(ValueError, match="runtime classes"):
        Settings.from_env()


def test_default_runtime_changes_affect_only_new_allocations():
    settings = replace(SETTINGS, allowed_runtime_classes='["kata-dev","kata-fc"]')
    store, kube = store_for(settings)
    first = store.create(OWNER, profile_id="terminal").reference
    changed, _ = store_for(replace(settings, runtime_class="kata-fc"), kube)
    second = changed.create(OWNER, profile_id="terminal").reference
    changed.mode(first["metadata"]["name"], OWNER, "Suspended").reference
    resumed = changed.mode(first["metadata"]["name"], OWNER, "Running").reference
    assert resumed["spec"]["podTemplate"]["spec"]["runtimeClassName"] == "kata-dev"
    assert second["spec"]["podTemplate"]["spec"]["runtimeClassName"] == "kata-fc"


def test_cluster_default_runtime_requires_explicit_operator_approval():
    with pytest.raises(ValueError, match="approve the cluster default"):
        Profiles(replace(SETTINGS, runtime_class=""))
    settings = replace(SETTINGS, runtime_class="", allowed_runtime_classes='[""]')
    profiles = Profiles(settings)
    profile = profiles.get("terminal")
    spec = profiles.render(profile, profiles.size(profile))
    assert spec["podTemplate"]["spec"]["runtimeClassName"] is None


def test_saved_default_runtime_survives_a_new_named_platform_default():
    settings = replace(
        SETTINGS, runtime_class="", allowed_runtime_classes='["","kata-dev"]'
    )
    store, kube = store_for(settings)
    first = store.create(OWNER, profile_id="terminal").reference
    changed, _ = store_for(replace(settings, runtime_class="kata-dev"), kube)
    second = changed.create(OWNER, profile_id="terminal").reference
    changed.mode(first["metadata"]["name"], OWNER, "Suspended")
    resumed = changed.mode(first["metadata"]["name"], OWNER, "Running").reference
    assert resumed["spec"]["podTemplate"]["spec"]["runtimeClassName"] is None
    assert second["spec"]["podTemplate"]["spec"]["runtimeClassName"] == "kata-dev"


def test_default_runtime_preserves_native_node_placement():
    definitions = json.loads(SETTINGS.profiles)
    profile = next(p for p in definitions if p["id"] == "terminal")
    placement = {
        "nodeSelector": {"node-pool": "development"},
        "tolerations": [{"key": "development", "operator": "Exists"}],
    }
    profile["agentSandbox"]["spec"]["podTemplate"]["spec"].update(placement)
    store, _ = store_for(
        replace(
            SETTINGS,
            runtime_class="",
            allowed_runtime_classes='[""]',
            profiles=json.dumps(definitions),
        )
    )
    spec = store.create(OWNER, profile_id="terminal").reference["spec"]["podTemplate"][
        "spec"
    ]
    assert all(spec[key] == value for key, value in placement.items())


def test_engineers_cannot_override_runtime_through_create_requests():
    settings = replace(SETTINGS, allowed_runtime_classes='["kata-dev","kata-fc"]')
    store, kube = store_for(settings)
    with TestClient(create_app(settings, store, Omnigent())) as browser:
        response = browser.post(
            BASE + "/sandboxes",
            headers=HEADERS,
            json={"profile": "terminal", "runtimeClassName": "kata-fc"},
        )
    assert response.status_code == 422
    assert not kube.items


def test_sandbox_identity_uses_platform_configuration():
    identity = {"runAsUser": 1000, "runAsGroup": 2000, "fsGroup": 3000}
    settings = replace(SETTINGS, sandbox_security_context=json.dumps(identity))
    store, _ = store_for(settings)
    cr = store.create(OWNER).reference
    pod = cr["spec"]["podTemplate"]["spec"]
    assert pod["securityContext"] == {
        **identity,
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert pod["automountServiceAccountToken"] is False
    assert pod["containers"][0]["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "privileged": False,
        "capabilities": {"drop": ["ALL"]},
    }


@pytest.mark.parametrize(
    "identity",
    [
        None,
        [],
        "1000",
        {},
        {"runAsUser": 1000, "runAsGroup": 1000},
        *[
            {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, field: value}
            for field in ("runAsUser", "runAsGroup", "fsGroup")
            for value in (0, -1, True, 1.5, "1000", 2147483648)
        ],
        {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, "runAsNonRoot": False},
    ],
)
def test_invalid_sandbox_identity_prevents_startup(identity):
    with pytest.raises(ValueError, match="Sandbox security context"):
        Profiles(replace(SETTINGS, sandbox_security_context=json.dumps(identity)))


def test_sandbox_identity_is_loaded_from_environment(monkeypatch):
    monkeypatch.setenv("PORTAL_PROFILES", SETTINGS.profiles)
    monkeypatch.setenv("PORTAL_DEFAULT_PROFILE", SETTINGS.default_profile)
    monkeypatch.setenv("PORTAL_AUTH_MODE", "omnigent")
    monkeypatch.setenv("PORTAL_AUTH_OMNIGENT_URL", SETTINGS.auth_omnigent_url)
    monkeypatch.setenv("PORTAL_RUNTIME_CLASS", SETTINGS.runtime_class)
    identity = {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 2000}
    monkeypatch.setenv("PORTAL_SANDBOX_SECURITY_CONTEXT", json.dumps(identity))
    settings = Settings.from_env()
    assert sandbox_security_context(settings)["runAsUser"] == 1000
    monkeypatch.setenv("PORTAL_SANDBOX_SECURITY_CONTEXT", '{"runAsUser":0}')
    with pytest.raises(ValueError, match="Sandbox security context"):
        Settings.from_env()


@pytest.mark.parametrize("container", ["host", "init"])
@pytest.mark.parametrize("field", ["runAsUser", "runAsGroup"])
def test_profiles_cannot_override_platform_identity_at_container_level(
    container, field
):
    profiles = json.loads(SETTINGS.profiles)
    pod = profiles[0]["agentSandbox"]["spec"]["podTemplate"]["spec"]
    if container == "init":
        pod["initContainers"] = [{"name": "prepare", "image": "example/tools"}]
        entry = pod["initContainers"][0]
    else:
        entry = pod["containers"][0]
    entry["securityContext"] = {
        field: json.loads(SETTINGS.sandbox_security_context)[field] + 1
    }
    with pytest.raises(ValueError, match="platform-controlled container field"):
        Profiles(replace(SETTINGS, profiles=json.dumps(profiles)))


def test_sandbox_identity_changes_affect_only_new_allocations():
    store, kube = store_for()
    first = store.create(OWNER).reference
    old = first["spec"]["podTemplate"]["spec"]["securityContext"]
    changed, _ = store_for(
        replace(
            SETTINGS,
            sandbox_security_context=json.dumps(
                {
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "fsGroup": 2000,
                }
            ),
        ),
        kube,
    )
    second = changed.create(OWNER).reference
    assert second["spec"]["podTemplate"]["spec"]["securityContext"]["runAsUser"] == 1000
    changed.mode(first["metadata"]["name"], OWNER, "Suspended").reference
    resumed = changed.mode(first["metadata"]["name"], OWNER, "Running").reference
    assert resumed["spec"]["podTemplate"]["spec"]["securityContext"] == old


def test_applied_revision_survives_catalog_default_changes_and_retries():
    store, kube = store_for()
    request_id = uuid4()
    cr = store.create(OWNER, request_id=request_id, profile_id="terminal").reference
    original = applied(as_sandbox(store, cr))
    definitions = json.loads(SETTINGS.profiles)
    definitions[1]["agentSandbox"]["spec"]["podTemplate"]["spec"]["containers"][0][
        "image"
    ] = "example/new-image"
    changed = replace(
        SETTINGS, profiles=json.dumps(definitions), default_profile="development"
    )
    restarted, _ = store_for(changed, kube)
    retry = restarted.create(OWNER, request_id=request_id).reference
    assert applied(as_sandbox(store, retry)) == original
    assert restarted.profiles.get("terminal").revision != original["revision"]
    restarted.mode(cr["metadata"]["name"], OWNER, "Suspended").reference
    resumed = restarted.mode(cr["metadata"]["name"], OWNER, "Running").reference
    assert resumed["spec"]["podTemplate"] == cr["spec"]["podTemplate"]
    with pytest.raises(HTTPException, match="different sandbox settings"):
        restarted.create(
            OWNER, request_id=request_id, profile_id="development"
        ).reference


def test_per_sandbox_namespaces_keep_ownership_and_work_after_strategy_change():
    settings = replace(
        SETTINGS,
        namespace=json.dumps(
            {
                "strategy": "perSandbox",
                "labels": {"team.example.com/name": "platform"},
                "annotations": {"team.example.com/contact": "helpdesk"},
            }
        ),
    )
    store, kube = store_for(settings)
    request_id = uuid4()
    first = store.create(OWNER, request_id=request_id).reference
    second = store.create(OWNER).reference
    other = store.create(OTHER, request_id=request_id).reference
    assert len({cr["metadata"]["namespace"] for cr in (first, second, other)}) == 3
    ns = kube.namespace_objects[first["metadata"]["namespace"]]
    assert ns["metadata"]["labels"]["team.example.com/name"] == "platform"
    assert ns["metadata"]["annotations"]["team.example.com/contact"] == "helpdesk"
    assert len(store.list(OWNER)) == 2
    migrated, _ = store_for(SETTINGS, kube)
    assert (
        migrated.create(OWNER, request_id=request_id).reference["metadata"]
        == first["metadata"]
    )
    third = migrated.create(OWNER).reference
    assert third["metadata"]["namespace"] == namespace_name(SETTINGS, OWNER)
    assert len(migrated.list(OWNER)) == 3
    assert len(migrated.list(OTHER)) == 1


@pytest.mark.parametrize(
    "config",
    [
        {"strategy": "shared"},
        {"labels": {"pod-security.kubernetes.io/enforce": "privileged"}},
        {"annotations": {"sandbox.caipe.io/owner": "attacker"}},
        {"labels": {"invalid/key/part": "value"}},
        {"labels": {"team": "spaces are invalid"}},
        {"annotations": {"team": 42}},
    ],
)
def test_namespace_metadata_rejects_invalid_and_protected_keys(config):
    with pytest.raises((ValueError, TypeError)):
        namespace_config(replace(SETTINGS, namespace=json.dumps(config)))


def test_native_validation_precedes_persisted_creation():
    store, kube = store_for()
    create = kube.create_namespaced_custom_object = Mock(
        wraps=kube.create_namespaced_custom_object
    )
    store.create(OWNER, profile_id="terminal").reference
    assert create.call_args_list[0].kwargs == {
        "dry_run": "All",
        "field_validation": "Strict",
    }
    assert create.call_args_list[1].kwargs == {"field_validation": "Strict"}


def test_creation_waits_for_exact_namespace_rbac_denial_on_dry_run(monkeypatch):
    from test_integrations import native_rbac_denial

    store, kube = store_for()
    original = kube.create_namespaced_custom_object
    rejected = False

    def delayed_grant(group, version, namespace, *args, **kwargs):
        nonlocal rejected
        if not rejected and kwargs.get("dry_run") == "All":
            rejected = True
            raise native_rbac_denial(
                namespace=namespace,
                username=f"system:serviceaccount:{store.settings.portal_namespace}:{store.settings.portal_service_account}",
            )
        return original(group, version, namespace, *args, **kwargs)

    monkeypatch.setattr(kube, "create_namespaced_custom_object", delayed_grant)
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)
    sandbox = store.create(OWNER, profile_id="terminal")
    assert sandbox.record.binding is not None
    assert sandbox.record.operation is None
    assert len(kube.items) == len(store.metadata.list_sandboxes()) == 1
    sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("status,response", [(403, 503), (500, 503), (422, 422)])
def test_creation_does_not_retry_other_errors(monkeypatch, status, response):
    store, kube = store_for()
    create = Mock(side_effect=ApiException(status))
    monkeypatch.setattr(kube, "create_namespaced_custom_object", create)
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)
    with pytest.raises(HTTPException) as error:
        store.create(OWNER, profile_id="terminal")
    assert error.value.status_code == response
    assert create.call_count == 1
    sleep.assert_not_called()
    assert not kube.items


def test_per_sandbox_quota_is_shared_across_owner_namespaces():
    settings = replace(
        SETTINGS,
        namespace='{"strategy":"perSandbox"}',
        namespace_policy=json.dumps(
            {
                **json.loads(SETTINGS.namespace_policy),
                "quota": {"requests.storage": "30Gi"},
            }
        ),
    )
    store, kube = store_for(settings)
    store.create(OWNER).reference
    with pytest.raises(Conflict, match="Owner resource quota exceeded"):
        store.create(OWNER).reference
    store.create(OTHER).reference
    assert len(kube.items) == 2


def test_shared_namespace_does_not_combine_per_user_count_limits():
    store, kube = store_for(
        replace(SETTINGS, namespace='{"strategy":"perUser"}', max_sandboxes_per_user=5)
    )
    first = store.create(OWNER)
    store.sharing(first.name, OWNER, {OTHER: "shell"})
    for _ in range(4):
        store.create(OWNER, namespace=first.scope)
    for _ in range(5):
        store.create(OTHER, namespace=first.scope)
    for owner in [OWNER, OTHER]:
        with pytest.raises(Conflict, match="limit of 5 micro VMs"):
            store.create(owner, namespace=first.scope)
    assert len(kube.items) == 10
    assert {scope for scope, _ in kube.items} == {first.scope}
    assert not any(kind == "ResourceQuota" for kind, _, _ in kube.baseline)


@pytest.mark.parametrize("maximum", [0, 5, -1])
def test_owner_count_limit_is_loaded_from_deployment(monkeypatch, maximum):
    for name, value in SETTINGS.__dict__.items():
        monkeypatch.setenv("PORTAL_" + name.upper(), str(value))
    monkeypatch.setenv("PORTAL_MAX_SANDBOXES_PER_USER", str(maximum))
    if maximum < 0:
        with pytest.raises(ValueError, match="MAX_SANDBOXES_PER_USER"):
            Settings.from_env()
    else:
        assert Settings.from_env().max_sandboxes_per_user == maximum


def test_namespace_cleanup_waits_for_retained_claims():
    settings = replace(
        SETTINGS,
        namespace='{"strategy":"perSandbox"}',
        namespace_policy=json.dumps(
            {**json.loads(SETTINGS.namespace_policy), "deleteWhenEmpty": True}
        ),
    )
    store, kube = store_for(settings, CleanupKubernetes())
    cr = store.create(OWNER).reference
    namespace = cr["metadata"]["namespace"]
    kube.list_namespaced_persistent_volume_claim = Mock(
        return_value=SimpleNamespace(items=[object()])
    )
    store.delete(cr["metadata"]["name"], OWNER)
    store.cleanup_namespaces()
    assert namespace in kube.namespace_objects
    kube.list_namespaced_persistent_volume_claim.return_value.items = []
    store.cleanup_namespaces()
    assert namespace not in kube.namespace_objects


def test_helper_scripts_are_retained_and_server_resolved(monkeypatch):
    store, _ = store_for()
    cr = store.create(OWNER, profile_id="terminal").reference
    name = cr["metadata"]["name"]
    original = helper(as_sandbox(store, cr), "workspace").script

    class Exec:
        opened = True

        def is_open(self):
            return self.opened

        def update(self, timeout):
            pass

        def read_all(self):
            return ""

        def read_channel(self, channel):
            return ""

        def close(self):
            self.opened = False

    attach = Mock(return_value=Exec())
    monkeypatch.setattr(execution, "stream", attach)
    with TestClient(create_app(SETTINGS, store, Omnigent())) as browser:
        with browser.websocket_connect(
            BASE + f"/sandboxes/{name}/terminal?helper=workspace", headers=HEADERS
        ) as ws:
            assert ws.receive_json(mode="binary") == {"type": "ready"}
        assert attach.call_args.kwargs["command"] == ["/bin/sh", "-c", original]
        attach.reset_mock()
        with browser.websocket_connect(
            BASE + f"/sandboxes/{name}/terminal?helper=not-in-profile", headers=HEADERS
        ) as ws:
            assert ws.receive_json(mode="binary")["code"] == "http-404"
        attach.assert_not_called()


def test_catalog_and_retained_configuration_are_read_only_and_authorized():
    settings = replace(SETTINGS, admin_emails=json.dumps([OWNER]))
    store, kube = store_for(settings)
    kube.list_cluster_custom_object = lambda *args, **kwargs: {
        "items": list(kube.items.values())
    }
    cr = store.create(OWNER, profile_id="terminal").reference
    with TestClient(create_app(settings, store, Omnigent())) as browser:
        catalog = browser.get(BASE + "/profiles", headers=HEADERS)
        assert catalog.status_code == 200
        assert all(
            "script" not in helper
            for p in catalog.json()["profiles"]
            for helper in p["helpers"]
        )
        admin_catalog = browser.get(BASE + "/admin/profiles", headers=HEADERS).json()
        assert admin_catalog["default"] == settings.default_profile
        assert admin_catalog["profiles"][1]["definition"]["helpers"][0]["script"]
        path = BASE + f"/sandboxes/{cr['metadata']['name']}/configuration"
        configuration = browser.get(path, headers=HEADERS).json()
        assert (
            configuration["creation"]["revision"]
            == applied(as_sandbox(store, cr))["revision"]
        )
        assert "legacy" not in configuration
        assert browser.get(path, headers={"Cookie": "session=bob"}).status_code == 404
        assert (
            browser.put(
                BASE + "/profiles/terminal", headers=HEADERS, json={}
            ).status_code
            == 404
        )


@pytest.mark.parametrize("section", ["openShell", "envoyEgress"])
def test_unintegrated_backends_never_fall_back_to_direct_execution(section):
    definition = Profiles(SETTINGS).get("terminal").model_dump(exclude_none=True)
    definition[section] = {"template": "protected"}
    with pytest.raises(ValueError):
        Profiles(
            replace(
                SETTINGS, profiles=json.dumps([definition]), default_profile="terminal"
            )
        )


def test_retained_definition_hash_does_not_depend_on_new_model_defaults():
    from portal.profiles import definition_revision
    from portal.storage.schema import sandboxes

    store, _ = store_for()
    cr = store.create(OWNER, profile_id="terminal").reference
    snapshot = applied(as_sandbox(store, cr))
    snapshot["definition"].pop("description")
    snapshot["revision"] = definition_revision(snapshot["definition"])
    with store.metadata.engine.begin() as connection:
        connection.execute(
            sandboxes.update()
            .where(sandboxes.c.name == cr["metadata"]["name"])
            .values(profile_snapshot=snapshot)
        )
    assert applied(as_sandbox(store, cr))["revision"] == snapshot["revision"]


def ui_profile_settings():
    from pathlib import Path

    import yaml

    values = yaml.safe_load(
        (Path(__file__).parents[1] / "examples/profiles.values.yaml").read_text()
    )
    return replace(
        SETTINGS,
        profiles=json.dumps(values["profiles"]),
        default_profile=values["defaultProfile"],
    )


def test_ui_resource_defaults_render_native_fields_and_publish_individual_bounds():
    settings = ui_profile_settings()
    store, _ = store_for(settings)
    cr = store.create(OWNER).reference
    host = cr["spec"]["podTemplate"]["spec"]["containers"][0]
    assert host["resources"]["requests"] == {
        "cpu": "500m",
        "memory": "1024Mi",
        "ephemeral-storage": "2Gi",
    }
    assert (
        cr["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"][
            "storage"
        ]
        == "20Gi"
    )
    assert (
        "resources"
        not in applied(as_sandbox(store, cr))["definition"]["agentSandbox"]["spec"][
            "podTemplate"
        ]["spec"]["containers"][0]
    )
    with TestClient(create_app(settings, store, Omnigent())) as browser:
        catalog = browser.get(BASE + "/sandboxes", headers=HEADERS).json()
    assert catalog["profiles"][0]["resources"]["cpu_request_millicores"] == 500
    assert catalog["profiles"][0]["resource_bounds"]["cpu_limit_millicores"] == {
        "min": 100,
        "max": 2000,
    }
    assert catalog["sandboxes"][0]["resource_bounds"]["workspace_gib"] == {
        "min": 1,
        "max": 50,
    }


@pytest.mark.parametrize(
    "resource,value",
    [
        ("cpu", "0"),
        ("cpu", "-1"),
        ("cpu", "NaN"),
        ("cpu", "Infinity"),
        ("cpu", "1e999999999"),
        ("cpu", "1e1000"),
        ("cpu", "0.0001"),
        ("cpu", True),
        ("cpu", {}),
        ("cpu", ""),
        ("memory", "1.5Mi"),
        ("memory", "1m"),
        ("memory", "NaN"),
        ("storage", "1Mi"),
        ("storage", "1.5Gi"),
        ("storage", False),
    ],
)
def test_ui_quantities_reject_invalid_or_unrepresentable_values(resource, value):
    from portal.resource_controls import ResourceControls

    definition = json.loads(ui_profile_settings().profiles)[0]["ui"]["resources"]
    target = (
        definition["default"]
        if resource == "storage"
        else definition["default"]["requests"]
    )
    target[resource] = value
    with pytest.raises(ValueError):
        ResourceControls.model_validate(definition)


def test_ui_quantities_accept_numeric_cpu_and_exact_binary_units():
    definitions = json.loads(ui_profile_settings().profiles)
    controls = definitions[0]["ui"]["resources"]
    controls["default"]["requests"]["cpu"] = 0.5
    controls["default"]["limits"]["cpu"] = 2
    controls["default"]["requests"]["memory"] = "1024Mi"
    settings = replace(ui_profile_settings(), profiles=json.dumps(definitions))
    assert (
        Profiles(settings).size(Profiles(settings).get()).cpu_request_millicores == 500
    )


@pytest.mark.parametrize("kind", ["cpu", "memory", "storage"])
def test_ui_resource_controls_reject_duplicate_native_defaults(kind):
    definitions = json.loads(ui_profile_settings().profiles)
    spec = definitions[0]["agentSandbox"]["spec"]
    if kind == "storage":
        spec["volumeClaimTemplates"] = [
            {
                "metadata": {"name": "home"},
                "spec": {"resources": {"requests": {"storage": "20Gi"}}},
            }
        ]
    else:
        spec["podTemplate"]["spec"]["containers"][0]["resources"] = {
            "requests": {kind: "500m" if kind == "cpu" else "1Gi"}
        }
    with pytest.raises(ValueError, match="only in ui.resources.default"):
        Profiles(replace(ui_profile_settings(), profiles=json.dumps(definitions)))


@pytest.mark.parametrize("kind", ["default", "minimum", "maximum"])
def test_ui_resource_controls_reject_outside_or_reversed_ranges(kind):
    definitions = json.loads(ui_profile_settings().profiles)
    definitions[0]["ui"]["resources"][kind]["storage"] = {
        "default": "51Gi",
        "minimum": "21Gi",
        "maximum": "10Gi",
    }[kind]
    with pytest.raises(ValueError):
        Profiles(replace(ui_profile_settings(), profiles=json.dumps(definitions)))


def test_profile_ranges_cannot_widen_platform_controls():
    definitions = json.loads(ui_profile_settings().profiles)
    definitions[0]["ui"]["resources"]["maximum"]["limits"]["cpu"] = "5"
    with pytest.raises(ValueError, match="cpu_limit_millicores must be between"):
        Profiles(replace(ui_profile_settings(), profiles=json.dumps(definitions)))


def test_api_checks_profile_bounds_even_when_global_policy_allows_the_request():
    settings = ui_profile_settings()
    store, kube = store_for(settings)
    size = store.profiles.size(store.profiles.get()).model_dump()
    with TestClient(create_app(settings, store, Omnigent())) as browser:
        response = browser.post(
            BASE + "/sandboxes",
            headers=HEADERS,
            json={"resources": {**size, "cpu_limit_millicores": 3000}},
        )
        assert (
            response.status_code == 422
            and "profile resource bounds" in response.json()["detail"]
        )
        assert not kube.items
        response = browser.post(
            BASE + "/sandboxes",
            headers=HEADERS,
            json={"resources": {**size, "workspace_gib": 1}},
        )
        assert (
            response.status_code == 201
            and response.json()["allocation"]["workspace_gib"] == 1
        )
    assert len(kube.items) == 1


def test_resize_uses_saved_profile_bounds_after_catalog_changes():
    from test_portal import suspended

    from portal.resources import Allocation

    settings = ui_profile_settings()
    store, kube = store_for(settings)
    cr = store.create(OWNER).reference
    suspended(kube, cr)
    definitions = json.loads(settings.profiles)
    for profile in definitions:
        profile["ui"]["resources"]["maximum"]["limits"]["cpu"] = "4"
    restarted, _ = store_for(replace(settings, profiles=json.dumps(definitions)), kube)
    size = store.profiles.size(store.profiles.get()).model_dump()
    with pytest.raises(HTTPException, match="profile resource bounds"):
        restarted.configure(
            cr["metadata"]["name"],
            OWNER,
            Allocation(**{**size, "cpu_limit_millicores": 3000}),
        ).reference
    changed = restarted.configure(
        cr["metadata"]["name"],
        OWNER,
        Allocation(**{**size, "cpu_limit_millicores": 1500}),
    ).reference
    assert (
        changed["spec"]["podTemplate"]["spec"]["containers"][0]["resources"]["limits"][
            "cpu"
        ]
        == "1500m"
    )
    assert applied(as_sandbox(store, changed)) == applied(as_sandbox(store, cr))


def test_empty_storage_class_uses_cluster_default_and_explicit_choice_is_retained():
    for storage_class in ("", "organisation-storage"):
        store, _ = store_for(replace(SETTINGS, storage_class=storage_class))
        cr = store.create(OWNER).reference
        claim = cr["spec"]["volumeClaimTemplates"][0]["spec"]
        if storage_class:
            assert claim["storageClassName"] == storage_class
        else:
            assert "storageClassName" not in claim
