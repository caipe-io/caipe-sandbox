"""Shared routing contracts exercised with a provider other than OpenShell."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from inventory_fakes import as_sandbox
from kubernetes.client import ApiException
from portal import execution, integrations
from portal.controls import SandboxUpdate
from portal.integrations.agent_sandbox import execution as native_execution
from portal.integrations.agent_sandbox.inventory import PREFIX, manifest
from portal.integrations.agent_sandbox.service import Integration as NativeIntegration
from portal.namespaces import namespace_name
from portal.storage import Conflict
from portal.storage.schema import sandboxes
from test_portal import OWNER
from test_profiles import store_for


@pytest.fixture
def another_runtime(monkeypatch):
    class Backend(NativeIntegration):
        key = "anotherRuntime"

        def __init__(self, store, *, catalog=None):
            super().__init__(store, catalog=catalog)
            self.calls = []

        def status(self, cr, row):
            return {
                **row,
                "state": "Suspended",
                "integrations": [
                    {
                        "id": "another-runtime",
                        "title": "Another runtime",
                        "layer": "Runtime",
                        "state": "active",
                        "icon": "box",
                    }
                ],
            }

        def mode(self, cr, mode, **kwargs):
            self.calls.append(("mode", mode))
            return cr

        def configure(self, cr, size):
            self.calls.append(("configure", size))
            return cr

        def control(self, cr, control, mode):
            self.calls.append(("control", control, mode))
            return cr

        def delete(self, cr, **kwargs):
            self.calls.append(("delete",))
            return {"status": "deleting"}

        def usage(self, cr):
            return {"pods": 2}

        def execution(self, cr, *, admin=False):
            from execution_fakes import target

            return target(lambda command, **kwargs: ("native-stream", command))

        def recover(self, **kwargs):
            return []

        def retained_usage(self, owner, uids):
            return {}

        def cleanup(self):
            pass

        def close(self):
            self.calls.append(("close",))

    bootstrap = Mock()
    provider = SimpleNamespace(
        key="anotherRuntime",
        Integration=Backend,
        managed=lambda cr: (
            cr.get("metadata", {})
            .get("annotations", {})
            .get("sandbox.caipe.io/backend")
            == "anotherRuntime"
        ),
        reserved_prefixes=("another-runtime.example/",),
        namespace_name=lambda settings, owner, sandbox=None: (
            namespace_name(settings, owner, sandbox) + "-other"
        ),
        namespace_labels=lambda settings: {"another-runtime.example/managed": "true"},
        supports_namespace=lambda settings: True,
        sandbox_name=lambda request: "other-" + str(request).replace("-", "")[:10],
        bootstrap=bootstrap,
    )
    monkeypatch.setattr(integrations, "PROVIDERS", (*integrations.PROVIDERS, provider))
    return provider


def bind_test_runtime(store, kube, cr):
    # Set up a saved allocation from the test provider; native tags cannot switch it.
    meta = cr["metadata"]
    kube.items[(meta["namespace"], meta["name"])]["metadata"]["annotations"][
        PREFIX + "backend"
    ] = "anotherRuntime"
    with store.metadata.engine.begin() as connection:
        connection.execute(
            sandboxes.update()
            .where(sandboxes.c.name == meta["name"])
            .values(provider="anotherRuntime", profile_snapshot=None)
        )


def test_new_backend_routes_shared_status_lifecycle_and_execution(another_runtime):
    store, kube = store_for()
    cr = store.create(OWNER).reference
    key = (cr["metadata"]["namespace"], cr["metadata"]["name"])
    bind_test_runtime(store, kube, cr)
    cr = kube.items[key]
    row = store.status_view(as_sandbox(store, cr))
    assert row["integrations"][0]["title"] == "Another runtime"
    backend = store.integrations.items["anotherRuntime"]
    store.mode(key[1], OWNER, "Suspended").reference
    assert backend.calls == [("mode", "Suspended")]
    store.integrations.catalog.core.read_namespaced_pod = Mock(
        side_effect=AssertionError("This provider has no Pod")
    )
    target = store.integrations.execution(as_sandbox(store, cr))
    assert execution.connect(target, ["sh"]) == ("native-stream", ["sh"])
    store.integrations.close()
    assert backend.calls[-1] == ("close",)


def test_selected_backend_owns_native_mutations(another_runtime):
    store, kube = store_for()
    cr = store.create(OWNER).reference
    meta = cr["metadata"]
    bind_test_runtime(store, kube, cr)
    for operation in ("create", "patch", "delete"):
        setattr(
            kube,
            operation + "_namespaced_custom_object",
            Mock(
                side_effect=AssertionError(
                    "Native writes must use the selected integration"
                )
            ),
        )
    backend = store.integrations.items["anotherRuntime"]
    size = store.profiles.size(store.profiles.get())
    store.mode(meta["name"], OWNER, "Suspended").reference
    store.configure(meta["name"], OWNER, size).reference
    store.admin_control(
        meta["name"],
        meta["namespace"],
        meta["uid"],
        SandboxUpdate(
            resource_version=as_sandbox(store, cr).resource_version, disabled=True
        ),
        OWNER,
    ).reference
    assert store.admin_delete(meta["name"], meta["namespace"], meta["uid"]) == {
        "status": "deleting"
    }
    assert [call[0] for call in backend.calls] == [
        "mode",
        "configure",
        "mode",
        "delete",
    ]
    assert backend.calls[2] == ("mode", "Suspended")
    assert store.get(meta["name"], OWNER).record.control["disabled"] is True
    for operation in ("create", "patch", "delete"):
        getattr(kube, operation + "_namespaced_custom_object").assert_not_called()


@pytest.mark.parametrize("tamper", [None, "owner", "request-id", "application"])
def test_native_create_collision_does_not_reenter_portal_inventory(tamper):
    store, kube = store_for()
    cr = store.create(OWNER).reference
    meta = cr["metadata"]
    request_id = meta["annotations"][PREFIX + "request-id"]
    body = manifest(
        store.settings, OWNER, request_id=request_id, catalog=store.profiles
    )
    existing = kube.items[(meta["namespace"], meta["name"])]
    if tamper == "application":
        existing["metadata"]["labels"]["app.kubernetes.io/name"] = (
            "unrelated-controller"
        )
    elif tamper:
        existing["metadata"]["annotations"][PREFIX + tamper] = "unrelated-value"
    kube.create_namespaced_custom_object = Mock(side_effect=[body, ApiException(409)])
    store.get = Mock(
        side_effect=AssertionError("An integration must read its own native identity")
    )
    backend = store.integrations.items["agentSandbox"]
    if tamper:
        with pytest.raises(HTTPException) as error:
            backend.create(body, request_id)
        assert error.value.status_code == 409
    else:
        assert backend.create(body, request_id) == cr
    store.get.assert_not_called()


def native_rbac_denial(
    *, namespace="sandbox-example", username="system:serviceaccount:portal:portal-agent"
):
    error = ApiException(status=403, reason="Forbidden")
    error.body = json.dumps(
        {
            "reason": "Forbidden",
            "message": (
                "sandboxes.agents.x-k8s.io is forbidden: User "
                f'"{username}" cannot create resource "sandboxes" '
                f'in API group "agents.x-k8s.io" in the namespace "{namespace}"'
            ),
        }
    )
    return error


def native_create_fixture():
    custom = SimpleNamespace(create_namespaced_custom_object=Mock())
    settings = SimpleNamespace(
        portal_namespace="portal",
        portal_service_account="portal-agent",
        namespace_access_role="portal-access",
    )
    backend = NativeIntegration(
        SimpleNamespace(settings=settings), catalog=SimpleNamespace(custom=custom)
    )
    return (
        backend,
        custom,
        {"metadata": {"namespace": "sandbox-example", "name": "test-agent"}},
    )


def test_native_create_retries_only_bootstrap_rbac_denial_on_dry_run(monkeypatch):
    backend, custom, body = native_create_fixture()
    result = {"metadata": {"name": "test-agent", "uid": "uid-example"}}
    custom.create_namespaced_custom_object.side_effect = [
        native_rbac_denial(),
        native_rbac_denial(),
        body,
        result,
    ]
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)
    check = Mock()

    assert backend._create(body, "request-example", check) == result
    calls = custom.create_namespaced_custom_object.call_args_list
    assert len(calls) == 4
    assert [c.kwargs.get("dry_run") for c in calls] == ["All", "All", "All", None]
    assert all(c.kwargs["field_validation"] == "Strict" for c in calls)
    assert check.call_count == 4  # each attempt and the final mutation
    assert [c.args[0] for c in sleep.call_args_list] == [0.1, 0.2]


def test_portal_create_recovers_from_new_namespace_rbac_delay(monkeypatch):
    store, kube = store_for()
    original = kube.create_namespaced_custom_object
    dry_runs = []

    def create(group, version, namespace, plural, body, **kwargs):
        if kwargs.get("dry_run") == "All":
            dry_runs.append(namespace)
            if len(dry_runs) < 3:
                settings = store.settings
                raise native_rbac_denial(
                    namespace=namespace,
                    username=f"system:serviceaccount:{settings.portal_namespace}:{settings.portal_service_account}",
                )
        return original(group, version, namespace, plural, body, **kwargs)

    kube.create_namespaced_custom_object = Mock(side_effect=create)
    monkeypatch.setattr("time.sleep", Mock())
    sandbox = store.create(OWNER)

    assert sandbox.reference["metadata"]["uid"]
    assert len(dry_runs) == 3
    assert len(kube.items) == 1  # Exactly one native allocation was created.


def test_persistent_bootstrap_rbac_denial_is_bounded_and_never_creates(monkeypatch):
    backend, custom, body = native_create_fixture()
    custom.create_namespaced_custom_object.side_effect = native_rbac_denial()
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)
    check = Mock()

    with pytest.raises(HTTPException) as error:
        backend._create(body, "request-example", check)
    assert error.value.status_code == 503
    assert "permission" in error.value.detail.lower()
    assert "system:serviceaccount" not in error.value.detail
    calls = custom.create_namespaced_custom_object.call_args_list
    assert len(calls) == 6 and all(c.kwargs.get("dry_run") == "All" for c in calls)
    assert check.call_count == 6 and sleep.call_count == 5


@pytest.mark.parametrize(
    "error",
    [
        ApiException(status=422, reason="Invalid"),
        ApiException(status=403, reason="Forbidden"),
        native_rbac_denial(namespace="another-sandbox"),
        native_rbac_denial(username="system:serviceaccount:other:other"),
    ],
)
def test_unrelated_native_denials_are_not_retried(monkeypatch, error):
    backend, custom, body = native_create_fixture()
    custom.create_namespaced_custom_object.side_effect = error
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)

    with pytest.raises(ApiException):
        backend._create(body, "request-example", Mock())
    assert custom.create_namespaced_custom_object.call_count == 1
    assert custom.create_namespaced_custom_object.call_args.kwargs["dry_run"] == "All"
    sleep.assert_not_called()


def test_native_create_checks_lease_again_before_mutation(monkeypatch):
    backend, custom, body = native_create_fixture()
    custom.create_namespaced_custom_object.side_effect = [native_rbac_denial(), body]
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", Mock())
    check = Mock(side_effect=[None, None, Conflict("lease lost")])

    with pytest.raises(Conflict, match="lease lost"):
        backend._create(body, "request-example", check)
    assert custom.create_namespaced_custom_object.call_count == 2
    assert all(
        c.kwargs.get("dry_run") == "All"
        for c in custom.create_namespaced_custom_object.call_args_list
    )


def test_mutating_native_create_denial_is_never_retried(monkeypatch):
    backend, custom, body = native_create_fixture()
    custom.create_namespaced_custom_object.side_effect = [body, native_rbac_denial()]
    sleep = Mock()
    monkeypatch.setattr("portal.integrations.agent_sandbox.service.time.sleep", sleep)

    with pytest.raises(ApiException):
        backend._create(body, "request-example", Mock())
    assert [
        c.kwargs.get("dry_run")
        for c in custom.create_namespaced_custom_object.call_args_list
    ] == ["All", None]
    sleep.assert_not_called()


def test_new_backend_owns_namespace_details(another_runtime):
    store, _ = store_for()
    name = store.integrations.catalog.namespaces.ensure(OWNER, backend="anotherRuntime")
    assert name.endswith("-other")
    another_runtime.bootstrap.assert_called_once()
    ns = store.integrations.catalog.core.namespace_objects[name]
    assert ns["metadata"]["labels"]["sandbox.caipe.io/backend"] == "anotherRuntime"
    assert ns["metadata"]["labels"]["another-runtime.example/managed"] == "true"


@pytest.mark.parametrize(
    "metadata",
    [
        {"annotations": {"sandbox.caipe.io/backend": "unavailableRuntime"}},
        {
            "annotations": {"sandbox.caipe.io/backend": "agentSandbox"},
            "labels": {"sandbox.caipe.io/backend": "anotherRuntime"},
        },
        {
            "annotations": {"sandbox.caipe.io/backend": "agentSandbox"},
            "labels": {"openshell.ai/managed-by": "openshell"},
        },
    ],
)
def test_unknown_or_conflicting_backend_cannot_fall_back_to_direct_execution(metadata):
    store, _ = store_for()
    with pytest.raises(HTTPException) as error:
        store.integrations.catalog.backend_for({"metadata": metadata})
    assert error.value.status_code == 409


def test_raw_pod_never_falls_back_to_kubernetes(monkeypatch):
    api = Mock()
    monkeypatch.setattr(native_execution.client, "ApiClient", api)
    with pytest.raises(HTTPException, match="execution transport is unavailable"):
        execution.connect(
            SimpleNamespace(metadata=SimpleNamespace(name="pod", namespace="ns")),
            ["sh"],
        )
    api.assert_not_called()


def test_backend_defaults_still_obey_platform_resource_controls(monkeypatch):
    from portal import profiles

    store, _ = store_for()
    profile = store.profiles.get().model_copy(update={"ui": None})
    oversized = store.profiles.size(profile).model_copy(
        update={"cpu_request_millicores": 999999, "cpu_limit_millicores": 999999}
    )
    adapter = SimpleNamespace(
        profile=SimpleNamespace(
            size=lambda profile, settings: oversized,
            validate_size=lambda size, settings: None,
        )
    )
    monkeypatch.setattr(profiles, "profile_backend", lambda profile: adapter)
    with pytest.raises(HTTPException) as error:
        store.profiles.size(profile)
    assert error.value.status_code == 422


def test_future_runtime_control_panel_uses_common_routing_and_durable_operations(
    another_runtime,
    monkeypatch,
):
    store, kube = store_for()
    cr = store.create(OWNER).reference
    bind_test_runtime(store, kube, cr)
    sandbox = store.get(cr["metadata"]["name"], OWNER)
    backend = store.integrations.items["anotherRuntime"]
    descriptor = {
        "id": "another-runtime",
        "title": "Another runtime",
        "icon": "box",
    }
    controller = SimpleNamespace(
        descriptor=descriptor,
        supports_sandbox=lambda record: record.provider == "anotherRuntime",
    )
    controller.read = Mock(return_value={"settings": {"network": "private"}})
    controller.plan = Mock(
        return_value=(sandbox.record.manifest, {"native_revision": "v2"})
    )
    controller.apply = Mock()
    monkeypatch.setattr(
        integrations, "UI_INTEGRATIONS", (*integrations.UI_INTEGRATIONS, controller)
    )
    assert store.status_view(sandbox)["control_panels"] == [descriptor]
    current = store.integration_panel(sandbox, "another-runtime")
    assert current["settings"] == {"network": "private"}
    body = SimpleNamespace(
        uid=current["uid"],
        revision=current["revision"],
        native_revision="v2",
        configuration={"network": "private"},
    )
    updated = store.update_integration(sandbox, "another-runtime", body, OWNER)
    assert updated.record.operation is None
    assert controller.apply.call_args.args[0] is backend
    assert controller.apply.call_args.args[3] == {"native_revision": "v2"}
    with pytest.raises(HTTPException) as error:
        store.integration_panel(updated, "openshell")
    assert error.value.status_code == 404


def test_multiple_ui_integrations_share_one_backend_without_owning_its_lifecycle(
    monkeypatch,
):
    from copy import deepcopy

    controllers = []
    for key in ("first", "second"):

        def prepare(manifest, configuration, key=key):
            result = deepcopy(manifest)
            result["metadata"].setdefault("annotations", {})[f"example.org/{key}"] = (
                configuration["value"]
            )
            return result

        controllers.append(
            SimpleNamespace(
                descriptor={"id": key, "title": key, "icon": "box"},
                supports_profile=lambda profile: profile.agentSandbox is not None,
                supports_sandbox=lambda record: record.provider == "agentSandbox",
                creation_defaults=lambda profile: {"value": "profile-default"},
                prepare_creation=prepare,
                read=Mock(return_value={"available": True}),
            )
        )
    monkeypatch.setattr(integrations, "UI_INTEGRATIONS", tuple(controllers))
    store, _ = store_for()
    assert [item["id"] for item in integrations.creation_ui(store.profiles.get())] == [
        "first",
        "second",
    ]
    sandbox = store.create(
        OWNER,
        integration_configuration={
            "first": {"value": "one"},
            "second": {"value": "two"},
        },
    )
    assert sandbox.record.provider == "agentSandbox"
    assert (
        sandbox.record.manifest["metadata"]["annotations"]["example.org/first"] == "one"
    )
    assert (
        sandbox.record.manifest["metadata"]["annotations"]["example.org/second"]
        == "two"
    )
    assert [item["id"] for item in store.status_view(sandbox)["control_panels"]] == [
        "first",
        "second",
    ]
    for controller in controllers:
        assert store.integration_panel(sandbox, controller.descriptor["id"])[
            "available"
        ]
        assert (
            controller.read.call_args.args[0]
            is store.integrations.items["agentSandbox"]
        )
        with pytest.raises(HTTPException) as error:
            store.update_integration(
                sandbox,
                controller.descriptor["id"],
                SimpleNamespace(
                    uid=sandbox.uid,
                    revision=sandbox.record.revision,
                ),
                OWNER,
            )
        assert error.value.status_code == 405


def test_future_integration_reconciles_scope_controls_through_the_common_hook(
    another_runtime, monkeypatch
):
    store, kube = store_for()
    cr = store.create(OWNER).reference
    bind_test_runtime(store, kube, cr)
    controller = SimpleNamespace(
        descriptor={"id": "future-policy", "title": "Future policies"},
        supports_sandbox=lambda record: record.provider == "anotherRuntime",
        reconcile_scope=Mock(),
    )
    monkeypatch.setattr(
        integrations, "UI_INTEGRATIONS", (*integrations.UI_INTEGRATIONS, controller)
    )
    assert store.reconcile_controls() == []
    controller.reconcile_scope.assert_called_once()
    assert (
        controller.reconcile_scope.call_args.args[0]
        is store.integrations.items["anotherRuntime"]
    )
