"""Admission, identity and loss boundaries for preprovisioned ACP processes."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from test_storage import database  # noqa: F401 -- shared isolated database fixture

from portal.acp import Connections, OpenProcess, configuration_revision, install
from portal.auth import Principal
from portal.config import Settings
from portal.execution import ExecutionTarget
from portal.profiles import Profile
from portal.storage import Conflict, open_store
from portal.terminal import TerminalIO

IDENTITY = {
    "sandbox_uid": "sandbox-uid",
    "owner_subject": "test-user",
    "conversation_id": "conversation",
    "binding_id": "binding",
    "policy_revision": "sha256:" + "a" * 64,
}


@pytest.fixture
def metadata(database):  # noqa: F811 -- injected shared pytest fixture
    store = open_store(database)
    store.migrate()
    yield store
    store.close()


def test_retained_binding_blocks_another_caller_conversation_or_policy(metadata):
    token = metadata.admit_acp(IDENTITY, "run-1")
    assert metadata.finish_acp(IDENTITY["sandbox_uid"], "run-1", token)
    for key in ("owner_subject", "conversation_id", "binding_id", "policy_revision"):
        with pytest.raises(Conflict, match="another conversation or policy"):
            metadata.admit_acp({**IDENTITY, key: "different"}, "run-2")
    metadata.admit_acp(IDENTITY, "run-2")


def test_uncertain_run_never_expires_and_duplicate_cannot_spawn(metadata):
    token = metadata.admit_acp(IDENTITY, "accepted-run")
    for run in ("accepted-run", "different-run"):
        with pytest.raises(Conflict, match="active or unconfirmed"):
            metadata.admit_acp(IDENTITY, run)
    assert not metadata.finish_acp("sandbox-uid", "accepted-run", "stale-token")
    assert not metadata.finish_acp("sandbox-uid", "different-run", token)
    assert metadata.acp_binding("sandbox-uid")["active_run_id"] == "accepted-run"
    assert metadata.finish_acp("sandbox-uid", "accepted-run", token)
    assert metadata.admit_acp(IDENTITY, "next-run") != token


def test_two_replicas_admit_one_process(metadata):
    def admit(i):
        try:
            return metadata.admit_acp(IDENTITY, "run-" + str(i))
        except Conflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(value is not None for value in pool.map(admit, range(2))) == 1


def test_configuration_revision_includes_namespace_policy():
    snapshot = {"revision": "sha256:" + "b" * 64}
    settings = Settings()
    assert configuration_revision(snapshot, settings) != configuration_revision(
        snapshot, replace(settings, namespace_policy='{"publicHttpsEgress":false}')
    )


def test_machine_auth_does_not_accept_browser_or_another_subject():
    settings = replace(
        Settings(),
        acp_service_token="x" * 40,
        acp_connections=json.dumps(
            {
                "primary": {
                    "owner": "user@example.test",
                    "owner_subject": "test-user",
                    "sandbox_name": "example",
                    "sandbox_uid": "sandbox-uid",
                    "policy_revision": IDENTITY["policy_revision"],
                }
            }
        ),
    )
    admitted = Connections(settings)
    headers = {
        "authorization": "Bearer " + "x" * 40,
        "x-harness-engine-subject": "test-user",
    }
    assert (
        admitted.authorize(SimpleNamespace(headers=headers), "primary").owner_subject
        == "test-user"
    )
    for changes in (
        {"authorization": "Bearer wrong"},
        {"origin": "https://example.test"},
        {"x-harness-engine-subject": "other"},
    ):
        with pytest.raises(HTTPException):
            admitted.authorize(
                SimpleNamespace(headers={**headers, **changes}), "primary"
            )


def test_open_cannot_supply_commands_or_urls():
    frame = {**IDENTITY, "type": "open", "protocol": 1, "run_id": "run"}
    assert OpenProcess.model_validate(frame).binding_id == "binding"
    with pytest.raises(ValueError):
        OpenProcess.model_validate({**frame, "command": ["sh"]})


class ProcessStream:
    def __init__(self):
        self.frames = []
        self.config = None
        self.open = True

    def is_open(self):
        return self.open

    def update(self, timeout):
        return None

    def read_stdout(self):
        value, self.frames = "".join(self.frames), []
        return value

    def read_stderr(self):
        return ""

    def write_stdin(self, raw):
        frame = json.loads(raw)
        if frame["type"] == "start":
            self.config = frame
            self.frames.append(
                json.dumps(
                    {
                        **{key: frame[key] for key in IDENTITY},
                        "type": "ready",
                        "protocol": 1,
                        "run_id": frame["run_id"],
                        "process_id": frame["process_token"],
                        "workspace": "/workspace",
                        "cwd": "/workspace/binding",
                        "config_dir": "/workspace/binding/.claude",
                        "mcp_url": "http://127.0.0.1:12345/mcp/capability",
                    }
                )
                + "\n"
            )
        elif frame["type"] == "cancel":
            self.frames.append(
                json.dumps(
                    {
                        "type": "exit",
                        "drained": True,
                        "returncode": 0,
                        "run_id": self.config["run_id"],
                        "process_id": self.config["process_token"],
                    }
                )
                + "\n"
            )

    def close(self):
        self.open = False


@pytest.fixture
def relay(metadata):
    settings = replace(Settings(), acp_service_token="x" * 40)
    snapshot = {
        "revision": "sha256:" + "b" * 64,
        "namespaceStrategy": "perSandbox",
        "definition": {
            "acp": {"command": ["approved-acp"], "workspace_root": "/workspace"}
        },
    }
    revision = configuration_revision(snapshot, settings)
    settings = replace(
        settings,
        acp_connections=json.dumps(
            {
                "primary": {
                    "owner": "user@example.test",
                    "owner_subject": "test-user",
                    "sandbox_name": "example",
                    "sandbox_uid": "sandbox-uid",
                    "policy_revision": revision,
                }
            }
        ),
    )
    from test_storage import create

    from portal.storage import NativeBinding

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    sandbox = SimpleNamespace(
        provider="agentSandbox",
        uid="sandbox-uid",
        require_metadata=lambda: None,
        profile_snapshot=snapshot,
        record=SimpleNamespace(
            id=record.id,
            revision=record.revision,
            provider=record.provider,
            provider_instance=record.provider_instance,
            scope=record.scope,
            scope_owner="user@example.test",
        ),
        grants={},
        configuration_drift=False,
        state="Running",
    )
    streams = []

    def connector(command, **kwargs):
        assert command == [
            "/opt/venv/bin/python",
            "-I",
            "/usr/local/lib/sandbox/acp_runner.py",
        ]
        assert kwargs["tty"] is False
        stream = ProcessStream()
        streams.append(stream)
        return stream

    target = ExecutionTarget(
        key=("test", "pod-uid"),
        scope="scope",
        sandbox_uid="sandbox-uid",
        connector=connector,
    )
    store = SimpleNamespace(
        metadata=metadata,
        controls=SimpleNamespace(
            read=Mock(return_value=(SimpleNamespace(namespaces={}), 1))
        ),
        get=Mock(return_value=sandbox),
        check_access=Mock(),
        execution=Mock(return_value=target),
    )
    io = TerminalIO(2)
    app = FastAPI()
    app.state.store = store
    app.state.terminal_io = io
    app.state.upstream = None
    install(
        app,
        settings,
        SimpleNamespace(
            principal=AsyncMock(return_value=Principal("user@example.test", "user"))
        ),
        Mock(),
    )
    headers = {
        "Authorization": "Bearer " + "x" * 40,
        "X-Harness-Engine-Subject": "test-user",
    }
    frame = {
        **IDENTITY,
        "policy_revision": revision,
        "type": "open",
        "protocol": 1,
        "run_id": "run",
    }
    with TestClient(app) as browser:
        yield (
            browser,
            settings.base_path + "/api/acp/connections/primary/stdio",
            headers,
            frame,
            streams,
        )
    io.close()


def test_private_websocket_only_releases_after_exact_drain_and_keeps_binding(
    relay, metadata
):
    browser, path, headers, frame, streams = relay
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json(frame)
        ready = ws.receive_json()
        assert ready["type"] == "ready"
        assert metadata.acp_binding("sandbox-uid")["active_run_id"] == "run"
        ws.send_json({"type": "cancel"})
        assert ws.receive_json()["drained"] is True
    assert metadata.acp_binding("sandbox-uid")["active_run_id"] is None
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json({**frame, "conversation_id": "another", "run_id": "run-2"})
        denial = ws.receive_json()
        assert denial["admitted"] is False
        assert denial["code"] == "sandbox_bound"
        assert all(
            denial[key]
            == {**frame, "conversation_id": "another", "run_id": "run-2"}[key]
            for key in (*IDENTITY, "run_id")
        )
    assert len(streams) == 1


def test_owner_connection_metadata_is_not_cacheable(relay):
    browser, path, _headers, _frame, _streams = relay
    response = browser.get(
        path.partition("/api/acp/")[0] + "/api/sandboxes/example/acp"
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["registration"]["sandbox_uid"] == "sandbox-uid"


def test_unqualified_backend_is_rejected_before_process_admission(relay, metadata):
    browser, path, headers, frame, streams = relay
    browser.app.state.store.get.return_value.provider = "openShell"
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json(frame)
        rejection = ws.receive_json()
        assert rejection["admitted"] is False
        assert "qualified Agent Sandbox" in rejection["message"]
    assert streams == []
    assert metadata.acp_binding("sandbox-uid") is None


def test_creation_catalog_rejects_acp_on_unqualified_backend():
    with pytest.raises(ValueError, match="qualified Agent Sandbox"):
        Profile.model_validate(
            {
                "id": "coding",
                "title": "Coding sandbox",
                "openShell": {"spec": {}},
                "acp": {"command": ["example-acp"], "workspace_root": "/home/sandbox"},
            }
        )


def test_websocket_loss_is_not_remote_drain(relay, metadata):
    browser, path, headers, frame, streams = relay
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json(frame)
        assert ws.receive_json()["type"] == "ready"
    assert metadata.acp_binding("sandbox-uid")["active_run_id"] == "run"
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json(frame)
        rejection = ws.receive_json()
        assert rejection["admitted"] is False
        assert rejection["code"] == "sandbox_busy"
    assert len(streams) == 1


def test_another_run_on_the_same_busy_binding_does_not_launch(relay, metadata):
    browser, path, headers, frame, streams = relay
    metadata.admit_acp({key: frame[key] for key in IDENTITY}, "existing-run")
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json({**frame, "run_id": "new-attempt"})
        rejection = ws.receive_json()
        assert rejection["admitted"] is False
        assert rejection["code"] == "sandbox_busy"
    assert streams == []
    assert metadata.acp_binding("sandbox-uid")["active_run_id"] == "existing-run"


def test_integration_cleanup_is_scoped_and_retryable(metadata):
    from uuid import uuid4

    import sqlalchemy as sa
    from test_storage import create

    from portal.integrations.caipe.storage import OWNED_TABLES, cleanup_sandbox
    from portal.storage import NativeBinding, PendingOperation

    assert [table.name for table in OWNED_TABLES] == ["acp_bindings"]
    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    token = metadata.admit_acp(IDENTITY, "active-run")
    other = {**IDENTITY, "sandbox_uid": "another-sandbox"}
    metadata.admit_acp(other, "another-run")
    with metadata.engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE another_integration (value TEXT)"))
        connection.execute(
            sa.text("INSERT INTO another_integration VALUES ('preserved')")
        )
    with pytest.raises(Conflict, match="active or unconfirmed"):
        metadata.begin_operation(
            record.id,
            PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
            expected_revision=record.revision,
            manifest=record.manifest,
            requested_mode="suspended",
            resource_usage={},
        )
    assert metadata.finish_acp("sandbox-uid", "active-run", token)
    metadata.register_metadata_integration(
        "caipe", tables=OWNED_TABLES, cleanup_sandbox=cleanup_sandbox
    )
    deleting = metadata.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="suspended",
        resource_usage={},
    )
    deleted = metadata.finish_operation(
        record.id, expected_revision=deleting.revision, resource_usage={}, deleted=True
    )
    assert deleted.deleted_at is not None
    assert metadata.acp_binding("sandbox-uid") is None
    assert metadata.acp_binding("another-sandbox") is not None
    with metadata.engine.connect() as connection:
        assert (
            connection.execute(
                sa.text("SELECT value FROM another_integration")
            ).scalar_one()
            == "preserved"
        )
    assert (
        metadata.finish_operation(
            record.id,
            expected_revision=deleting.revision,
            resource_usage={},
            deleted=True,
        ).deleted_at
        is not None
    )


def test_disabled_integration_preserves_bindings_after_deletion(metadata):
    from uuid import uuid4

    from test_storage import create

    from portal.storage import NativeBinding, PendingOperation

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    token = metadata.admit_acp(IDENTITY, "active-run")
    assert metadata.finish_acp("sandbox-uid", "active-run", token)
    deleting = metadata.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="suspended",
        resource_usage={},
    )
    metadata.finish_operation(
        record.id, expected_revision=deleting.revision, resource_usage={}, deleted=True
    )
    assert metadata.acp_binding("sandbox-uid")["active_run_id"] is None
    with pytest.raises(Conflict, match="deleted"):
        metadata.admit_acp(IDENTITY, "new-run")


def test_cleanup_failure_rolls_back_and_retry_succeeds(metadata):
    from uuid import uuid4

    from test_storage import create

    from portal.integrations.caipe.storage import OWNED_TABLES, cleanup_sandbox
    from portal.storage import NativeBinding, PendingOperation

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    token = metadata.admit_acp(IDENTITY, "run")
    assert metadata.finish_acp("sandbox-uid", "run", token)
    deleting = metadata.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="suspended",
        resource_usage={},
    )

    def fail_after_cleanup(connection, current):
        cleanup_sandbox(connection, current)
        raise OSError("injected cleanup failure")

    metadata.register_metadata_integration(
        "caipe", tables=OWNED_TABLES, cleanup_sandbox=fail_after_cleanup
    )
    with pytest.raises(OSError, match="injected"):
        metadata.finish_operation(
            record.id,
            expected_revision=deleting.revision,
            resource_usage={},
            deleted=True,
        )
    assert metadata.acp_binding("sandbox-uid") is not None
    assert metadata.get_sandbox(record.id).operation.kind == "delete"
    metadata.register_metadata_integration(
        "caipe", tables=OWNED_TABLES, cleanup_sandbox=cleanup_sandbox
    )
    metadata.finish_operation(
        record.id, expected_revision=deleting.revision, resource_usage={}, deleted=True
    )
    assert metadata.acp_binding("sandbox-uid") is None


def test_delete_reservation_blocks_late_admission(metadata):
    from uuid import uuid4

    from test_storage import create

    from portal.integrations.caipe.storage import OWNED_TABLES, cleanup_sandbox
    from portal.storage import NativeBinding, PendingOperation

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    deleting = metadata.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="suspended",
        resource_usage={},
    )
    with pytest.raises(Conflict, match="unfinished operation"):
        metadata.admit_acp(IDENTITY, "late-run")
    assert metadata.acp_binding("sandbox-uid") is None
    metadata.register_metadata_integration(
        "caipe", tables=OWNED_TABLES, cleanup_sandbox=cleanup_sandbox
    )
    metadata.finish_operation(
        record.id, expected_revision=deleting.revision, resource_usage={}, deleted=True
    )
    with pytest.raises(Conflict, match="deleted"):
        metadata.admit_acp(IDENTITY, "late-run")


def test_admission_rejects_stale_sandbox_revision(metadata):
    from test_storage import create

    from portal.storage import NativeBinding

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    metadata.set_scope_grants(
        record.id, {"other@example.com": "shell"}, expected_revision=record.revision
    )
    with pytest.raises(Conflict):
        metadata.admit_acp(
            IDENTITY, "run", sandbox_id=record.id, expected_revision=record.revision
        )
    assert metadata.acp_binding("sandbox-uid") is None


def test_active_admission_rejects_sharing_change(metadata):
    from test_storage import create

    from portal.storage import NativeBinding

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    metadata.admit_acp(
        IDENTITY, "run", sandbox_id=record.id, expected_revision=record.revision
    )
    with pytest.raises(Conflict, match="active or unconfirmed"):
        metadata.set_scope_grants(
            record.id, {"other@example.com": "shell"}, expected_revision=record.revision
        )


def test_namespace_reservation_blocks_acp_siblings_and_retry_is_idempotent(metadata):
    from uuid import uuid4

    from test_storage import intent

    request = uuid4()
    coding = intent(profile_snapshot={"definition": {"acp": {"command": ["agent"]}}})
    first = metadata.reserve_create(coding, request)
    assert metadata.reserve_create(coding, request).id == first.id
    sibling = intent(
        scope=coding.scope,
        provider=coding.provider,
        provider_instance=coding.provider_instance,
    )
    with pytest.raises(Conflict, match="exclusive namespace"):
        metadata.reserve_create(sibling, uuid4())


def test_legacy_shared_namespace_cannot_admit(metadata):
    from uuid import uuid4

    from test_storage import create, intent

    from portal.storage import NativeBinding

    record = create(metadata)
    record = metadata.confirm_binding(
        record.id,
        NativeBinding(key="sandbox-uid", reference={}),
        expected_revision=record.revision,
    )
    metadata.reserve_create(
        intent(
            name="sibling-12345",
            scope=record.scope,
            provider=record.provider,
            provider_instance=record.provider_instance,
        ),
        uuid4(),
    )
    with pytest.raises(Conflict, match="exclusive namespace"):
        metadata.admit_acp(
            IDENTITY,
            "run",
            sandbox_id=record.id,
            expected_revision=record.revision,
            scope_identity=(record.provider, record.provider_instance, record.scope),
        )


def test_inflight_policy_change_blocks_admission_from_another_store(
    relay,
    metadata,
    database,  # noqa: F811
):
    from portal.coordination import claim
    from portal.storage import scope_key

    browser, path, headers, frame, streams = relay
    record = browser.app.state.store.get.return_value.record
    key = scope_key(record.provider, record.provider_instance, record.scope)
    other = open_store(database)
    try:
        with (
            claim(other, f"namespace-network/{key}"),
            browser.websocket_connect(path, headers=headers) as ws,
        ):
            ws.send_json(frame)
            assert ws.receive_json()["admitted"] is False
        assert streams == []
        assert metadata.acp_binding("sandbox-uid") is None
    finally:
        other.close()


def test_concurrent_scope_reservations_cannot_share_acp_namespace(metadata, database):  # noqa: F811
    from threading import Barrier
    from uuid import uuid4

    from test_storage import intent

    other = open_store(database)
    coding = intent(profile_snapshot={"definition": {"acp": {"command": ["agent"]}}})
    sibling = intent(
        name="sibling-12345",
        scope=coding.scope,
        provider=coding.provider,
        provider_instance=coding.provider_instance,
    )
    barrier = Barrier(2)

    def reserve(store, value):
        barrier.wait()
        try:
            store.reserve_create(value, uuid4())
            return True
        except Conflict:
            return False

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [
                pool.submit(reserve, metadata, coding),
                pool.submit(reserve, other, sibling),
            ]
            assert sum(f.result() for f in results) == 1
    finally:
        other.close()


def test_saved_network_policy_blocks_admission(relay, metadata):
    from portal.controls import NamespaceControl
    from portal.storage import scope_key

    browser, path, headers, frame, streams = relay
    store = browser.app.state.store
    record = store.get.return_value.record
    key = scope_key(record.provider, record.provider_instance, record.scope)
    store.controls.read.return_value = (
        SimpleNamespace(
            namespaces={key: NamespaceControl(network_policy={"pending": True})}
        ),
        1,
    )
    with browser.websocket_connect(path, headers=headers) as ws:
        ws.send_json(frame)
        assert ws.receive_json()["admitted"] is False
    assert streams == []
    assert metadata.acp_binding("sandbox-uid") is None


def test_expired_policy_lease_cannot_admit(metadata):
    from datetime import UTC, datetime, timedelta

    from portal.storage.schema import leases

    lease = metadata.acquire_lease("namespace-network/test", seconds=120)
    with metadata.engine.begin() as connection:
        connection.execute(
            leases.update()
            .where(leases.c.name == lease.name)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    with pytest.raises(Conflict, match="ownership expired"):
        metadata.admit_acp(IDENTITY, "run", policy_lease=lease)
    assert metadata.acp_binding("sandbox-uid") is None


def test_policy_lease_expiring_while_waiting_for_row_lock_is_rejected(metadata):
    from concurrent.futures import TimeoutError
    from datetime import UTC, datetime, timedelta
    from threading import Event

    import sqlalchemy as sa

    from portal.storage.schema import leases

    if metadata.engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL row-lock regression")
    lease = metadata.acquire_lease("namespace-network/blocked", seconds=120)
    started = Event()

    def admit():
        started.set()
        return metadata.admit_acp(IDENTITY, "run", policy_lease=lease)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with metadata.engine.begin() as connection:
            connection.execute(
                sa.select(leases).where(leases.c.name == lease.name).with_for_update()
            ).first()
            future = pool.submit(admit)
            assert started.wait(5)
            with pytest.raises(TimeoutError):
                future.result(timeout=0.2)
            connection.execute(
                leases.update()
                .where(leases.c.name == lease.name)
                .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
        with pytest.raises(Conflict, match="ownership expired"):
            future.result(timeout=5)
    assert metadata.acp_binding("sandbox-uid") is None
