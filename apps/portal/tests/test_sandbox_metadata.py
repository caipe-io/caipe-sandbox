"""Durable intent survives interrupted provider calls without adopting native state."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from portal.app import create_app
from portal.storage import Conflict, StorageError
from test_portal import BASE, HEADERS, OTHER, OWNER, SETTINGS, Omnigent, suspended
from test_profiles import store_for


def test_restriction_saved_during_observation_blocks_resume_dispatch(monkeypatch):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    store.mode(sandbox.name, OWNER, "Suspended")
    backend = store.integrations.items["agentSandbox"]
    observe, mode = backend.observe, Mock(wraps=backend.mode)

    def restrict_during_operation(binding):
        result = observe(binding)
        if store.metadata.get_sandbox(sandbox.record.id).operation:
            store.metadata.save_controls(
                {"sandboxes_disabled": True}, expected_revision=1
            )
        return result

    monkeypatch.setattr(backend, "observe", restrict_during_operation)
    monkeypatch.setattr(backend, "mode", mode)
    with pytest.raises(HTTPException) as error:
        store.mode(sandbox.name, OWNER, "Running")
    assert error.value.status_code == 403
    mode.assert_not_called()
    saved = store.metadata.get_sandbox(sandbox.record.id)
    assert saved.operation.state == "needs_attention"
    assert (
        kube.items[(sandbox.scope, sandbox.name)]["spec"]["operatingMode"]
        == "Suspended"
    )


def test_reconciliation_on_two_replicas_dispatches_one_suspension(monkeypatch):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    replica = restarted(store, kube)
    store.metadata.save_controls({"sandboxes_disabled": True}, expected_revision=1)
    entered, release = threading.Event(), threading.Event()
    backend = store.integrations.items["agentSandbox"]
    mode = backend.mode

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return mode(*args, **kwargs)

    dispatch = Mock(side_effect=blocked)
    monkeypatch.setattr(backend, "mode", dispatch)
    second_dispatch = Mock(
        side_effect=AssertionError("Must not duplicate a pending mutation")
    )
    monkeypatch.setattr(
        replica.integrations.items["agentSandbox"], "mode", second_dispatch
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(store.reconcile_controls)
        assert entered.wait(5)
        try:
            pending = replica.reconcile_controls()
            assert [row["name"] for row in pending] == [sandbox.name]
            second_dispatch.assert_not_called()
        finally:
            release.set()
        assert first.result(timeout=5) == []
    dispatch.assert_called_once()
    assert replica.reconcile_controls() == []


def restarted(store, kube):
    return store_for(store.settings, kube)[0]


def test_lost_create_response_keeps_reservation_and_retries_original_intent(
    monkeypatch,
):
    settings = replace(
        SETTINGS,
        namespace_policy=json.dumps(
            {**json.loads(SETTINGS.namespace_policy), "quota": {"pods": "1"}}
        ),
    )
    store, kube = store_for(settings)
    backend = store.integrations.items["agentSandbox"]
    create = backend.create
    request_id = uuid4()

    def lost_response(body, key):
        record = store.metadata.find_creation(OWNER, key)
        assert record and record.operation.kind == "create"
        assert (
            record.binding is None
        )  # The database transaction ended before this call.
        create(body, key)
        raise OSError("private transport details")

    monkeypatch.setattr(backend, "create", lost_response)
    with pytest.raises(OSError):
        store.create(OWNER, request_id=request_id)
    record = store.metadata.find_creation(OWNER, request_id)
    assert record.operation.state == "needs_attention" and record.binding is None
    assert store.list(OWNER)[0].state == "Error"
    assert "private transport details" not in store.list(OWNER)[0].message
    assert len(kube.items) == 1
    assert store.list(OWNER)[0].record.id == record.id
    with pytest.raises(Conflict, match="quota"):
        store.create(OWNER)

    replica = restarted(store, kube)
    replica.integrations.items["agentSandbox"].create = Mock(
        side_effect=AssertionError("Must recover the existing allocation")
    )
    recovered = replica.create(OWNER, request_id=request_id)
    assert recovered.record.id == record.id and recovered.record.operation is None
    assert recovered.record.manifest == record.manifest
    assert len(kube.items) == 1
    for key in ("profile", "shares", "admin-control"):
        assert (
            "sandbox.caipe.io/" + key
            not in recovered.reference["metadata"]["annotations"]
        )


def test_failed_creation_explains_the_error_after_restart_and_clears_on_retry(
    monkeypatch,
):
    store, kube = store_for()
    backend = store.integrations.items["agentSandbox"]
    message = (
        "The selected runtime has not been approved. Ask an administrator to sync it."
    )
    monkeypatch.setattr(
        backend, "create", Mock(side_effect=HTTPException(409, message))
    )
    request_id = uuid4()
    with pytest.raises(HTTPException):
        store.create(OWNER, request_id=request_id)
    record = store.metadata.find_creation(OWNER, request_id)
    replica = restarted(store, kube)
    failed = replica.get(record.name, OWNER)
    assert failed.state == "Error" and failed.message == message
    assert failed.view()["operation"]["error"] == message
    assert record.operation.parameters["_error"] == message
    recovered = replica.retry(record.name, OWNER)
    assert recovered.record.operation is None
    assert recovered.view()["operation"] is None


def test_native_success_followed_by_database_failure_is_recoverable(monkeypatch):
    store, kube = store_for()
    request_id = uuid4()
    confirm = store.metadata.confirm_binding
    monkeypatch.setattr(
        store.metadata,
        "confirm_binding",
        Mock(side_effect=StorageError("database unavailable")),
    )
    with pytest.raises(StorageError):
        store.create(OWNER, request_id=request_id)
    assert len(kube.items) == 1
    record = store.metadata.find_creation(OWNER, request_id)
    assert record.operation and not record.binding
    monkeypatch.setattr(store.metadata, "confirm_binding", confirm)
    recovered = restarted(store, kube).create(OWNER, request_id=request_id)
    assert recovered.record.id == record.id and recovered.record.binding
    assert len(kube.items) == 1


def test_interrupted_suspend_retries_saved_operation_through_api(monkeypatch):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    backend = store.integrations.items["agentSandbox"]
    mode = backend.mode

    def lost_response(reference, target, **kwargs):
        mode(reference, target, **kwargs)
        raise OSError("connection lost")

    monkeypatch.setattr(backend, "mode", lost_response)
    with pytest.raises(OSError):
        store.mode(sandbox.name, OWNER, "Suspended")
    saved = store.get(sandbox.name, OWNER).record
    assert saved.requested_mode == "suspended" and saved.operation.kind == "mode"
    replica = restarted(store, kube)
    with TestClient(create_app(SETTINGS, replica, Omnigent())) as browser:
        row = browser.get(BASE + "/sandboxes", headers=HEADERS).json()["sandboxes"][0]
        assert row["operation"]["state"] == "needs_attention" and not row["can_shell"]
        assert (
            browser.post(
                BASE + f"/sandboxes/{sandbox.name}/retry",
                headers={**HEADERS, "Cookie": "session=bob"},
            ).status_code
            == 404
        )
        result = browser.post(
            BASE + f"/sandboxes/{sandbox.name}/retry", headers=HEADERS
        )
        assert result.status_code == 200 and result.json()["operation"] is None
    assert len(kube.items) == 1


def test_interrupted_resize_preserves_intent_and_original_profile(monkeypatch):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    store.mode(sandbox.name, OWNER, "Suspended")
    suspended(kube, sandbox.reference)
    size = store.profiles.size(store.profiles.get()).model_copy(
        update={"cpu_limit_millicores": 3000}
    )
    backend = store.integrations.items["agentSandbox"]
    configure = backend.configure

    def lost_response(reference, requested):
        configure(reference, requested)
        raise OSError("connection lost")

    monkeypatch.setattr(backend, "configure", lost_response)
    with pytest.raises(OSError):
        store.configure(sandbox.name, OWNER, size)
    record = store.get(sandbox.name, OWNER).record
    assert record.operation.kind == "configure"
    assert record.profile_snapshot == sandbox.record.profile_snapshot
    assert backend.allocation(record.manifest) == size
    replica = restarted(store, kube)
    result = replica.retry(sandbox.name, OWNER)
    assert result.record.operation is None and result.allocation == size.model_dump()
    assert len(kube.items) == 1


def test_deleted_allocation_leaves_a_tombstone_for_old_creation_retries():
    store, kube = store_for()
    request_id = uuid4()
    sandbox = store.create(OWNER, request_id=request_id)
    store.delete(sandbox.name, OWNER)
    assert store.list(OWNER) == [] and store.admin_list() == []
    record = store.metadata.find_creation(OWNER, request_id)
    assert record.deleted_at and record.operation is None
    with pytest.raises(HTTPException, match="deleted sandbox"):
        restarted(store, kube).create(OWNER, request_id=request_id)
    assert not kube.items


def test_lost_delete_response_can_be_confirmed_without_recreating(monkeypatch):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    backend = store.integrations.items["agentSandbox"]
    delete = backend.delete

    def lost_response(reference, **kwargs):
        delete(reference, **kwargs)
        raise OSError("connection lost")

    monkeypatch.setattr(backend, "delete", lost_response)
    with pytest.raises(OSError):
        store.delete(sandbox.name, OWNER)
    record = store.metadata.get_sandbox(sandbox.record.id)
    assert record.operation.kind == "delete" and record.resource_usage
    replica = restarted(store, kube)
    assert replica.list(OWNER) == []
    assert replica.metadata.get_sandbox(record.id).deleted_at
    assert not kube.items


def test_missing_or_changed_native_identity_stays_visible_without_repair(monkeypatch):
    store, kube = store_for()
    first, second = store.create(OWNER), store.create(OWNER)
    del kube.items[(first.scope, first.name)]
    kube.items[(second.scope, second.name)]["metadata"]["uid"] = "replacement"
    native_create = Mock(
        side_effect=AssertionError("Read must not recreate missing compute")
    )
    monkeypatch.setattr(
        store.integrations.items["agentSandbox"], "create", native_create
    )
    for sandbox in store.list(OWNER):
        assert sandbox.state == "Unknown" and sandbox.reference is None
        assert store.configuration(sandbox)["desired"] == sandbox.record.manifest
        with pytest.raises(HTTPException):
            store.execution(sandbox.name, OWNER)
    assert len(store.list(OWNER)) == 2
    native_create.assert_not_called()


def test_provider_outage_does_not_hide_inventory_or_change_authorization(monkeypatch):
    store, _ = store_for()
    sandbox = store.create(OWNER)
    store.sharing(sandbox.name, OWNER, {OTHER: "view"})
    observe = Mock(side_effect=HTTPException(503, "provider down"))
    monkeypatch.setattr(store.integrations.items["agentSandbox"], "observe", observe)
    assert store.list(OWNER)[0].state == "Unknown"
    assert (
        store.shared_list(OTHER, OWNER)[0].profile_snapshot == sandbox.profile_snapshot
    )
    assert (
        store.get(sandbox.name, OWNER).record.resource_usage
        == sandbox.record.resource_usage
    )
    observe.reset_mock()
    with pytest.raises(HTTPException):
        store.shared_get(sandbox.name, "unauthorized@example.com", OWNER)
    observe.assert_not_called()


def test_database_outage_fails_closed_before_provider_observation(monkeypatch):
    store, _ = store_for()
    sandbox = store.create(OWNER)
    observe = Mock()
    monkeypatch.setattr(store.integrations.items["agentSandbox"], "observe", observe)
    monkeypatch.setattr(
        store.metadata, "find_sandbox", Mock(side_effect=StorageError("unavailable"))
    )
    with pytest.raises(StorageError):
        store.execution(sandbox.name, OWNER)
    observe.assert_not_called()


def test_native_drift_is_reported_without_saving_or_repairing_it():
    store, kube = store_for()
    sandbox = store.create(OWNER)
    kube.items[(sandbox.scope, sandbox.name)]["spec"]["podTemplate"]["spec"][
        "containers"
    ][0]["image"] = "changed-outside-portal"
    observed = store.get(sandbox.name, OWNER)
    assert observed.configuration_drift
    assert "differs" in store.status_view(observed)["message"]
    assert (
        store.metadata.get_sandbox(sandbox.record.id).manifest
        == sandbox.record.manifest
    )
    assert len(kube.items) == 1


def test_status_observation_is_bounded_and_only_reads_authorized_records(monkeypatch):
    store, _ = store_for()
    mine = [store.create(OWNER) for _ in range(12)]
    foreign = store.create(OTHER)
    backend = store.integrations.items["agentSandbox"]
    observe = backend.observe
    lock = threading.Lock()
    active = maximum = 0
    seen = set()

    def slow_observation(binding):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
            seen.add(binding.key)
        try:
            time.sleep(0.02)
            return observe(binding)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(backend, "observe", slow_observation)
    assert len(store.shared_list(OWNER, OWNER)) == len(mine)
    assert 1 < maximum <= 8 and foreign.uid not in seen
    store.close()


def test_old_create_retry_does_not_execute_a_later_pending_mutation(monkeypatch):
    store, _ = store_for()
    key = uuid4()
    sandbox = store.create(OWNER, request_id=key)
    monkeypatch.setattr(
        store.integrations.items["agentSandbox"],
        "mode",
        Mock(side_effect=HTTPException(503, "unavailable")),
    )
    with pytest.raises(HTTPException):
        store.mode(sandbox.name, OWNER, "Suspended")
    perform = Mock(
        side_effect=AssertionError("A create retry must not run a later operation")
    )
    monkeypatch.setattr(store, "_perform", perform)
    replay = store.create(OWNER, request_id=key)
    assert replay.record.operation.kind == "mode"
    perform.assert_not_called()


def test_resized_allocation_is_read_from_saved_manifest_during_provider_outage(
    monkeypatch,
):
    store, kube = store_for()
    sandbox = store.create(OWNER)
    store.mode(sandbox.name, OWNER, "Suspended")
    suspended(kube, sandbox.reference)
    size = store.profiles.size(store.profiles.get()).model_copy(
        update={"cpu_limit_millicores": 3000}
    )
    store.configure(sandbox.name, OWNER, size)
    backend = store.integrations.items["agentSandbox"]
    monkeypatch.setattr(
        backend, "observe", Mock(side_effect=HTTPException(503, "unavailable"))
    )
    row = store.status_view(store.get(sandbox.name, OWNER))
    assert row["state"] == "Unknown" and row["allocation"] == size.model_dump()


def test_cleanup_pending_remains_visible_and_maintenance_retries():
    from portal.integrations.caipe.storage import OWNED_TABLES, cleanup_sandbox

    store, kube = store_for()
    sandbox = store.create(OWNER)
    identity = {
        "sandbox_uid": sandbox.uid,
        "owner_subject": "subject",
        "conversation_id": "conversation",
        "binding_id": "binding",
        "policy_revision": "sha256:" + "a" * 64,
    }
    token = store.metadata.admit_acp(identity, "run")
    store.metadata.register_metadata_integration(
        "caipe", tables=OWNED_TABLES, cleanup_sandbox=cleanup_sandbox
    )
    with pytest.raises(Conflict, match="active or unconfirmed"):
        store.delete(sandbox.name, OWNER)
    assert store.metadata.acp_binding(sandbox.uid)["active_run_id"] == "run"
    assert store.metadata.finish_acp(sandbox.uid, "run", token)
    store.delete(sandbox.name, OWNER)
    assert store.metadata.get_sandbox(sandbox.record.id).deleted_at is not None
    assert store.metadata.acp_binding(sandbox.uid) is None
    assert not kube.items
