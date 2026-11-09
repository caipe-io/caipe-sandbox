"""Run the same persistence guarantees against file SQLite and real PostgreSQL."""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from portal.storage import (
    Conflict,
    NativeBinding,
    PendingOperation,
    SandboxIntent,
    SandboxRecord,
    SchemaMismatch,
    SchemaUpgradeRequired,
    StorageError,
    open_store,
)
from portal.storage.database import DatabaseSettings
from portal.storage.schema import controls, leases, metadata
from portal.storage.sql import MIGRATION_LOCK_ID, SQLMetadataStore


@pytest.fixture(params=["sqlite", "postgresql"])
def database(request, tmp_path):
    if request.param == "sqlite":
        yield DatabaseSettings(url=f"sqlite:///{tmp_path / 'metadata.db'}")
        return
    configured = os.environ.get("PORTAL_TEST_DATABASE_URL")
    if not configured:
        pytest.skip("Set PORTAL_TEST_DATABASE_URL to run the real PostgreSQL contract")
    base = DatabaseSettings(url=configured).parsed_url()
    if (
        base.host not in {"127.0.0.1", "localhost", "postgres"}
        or base.database != "portal_metadata_test"
    ):
        pytest.fail("PostgreSQL tests require a local portal_metadata_test database")
    name = "portal_metadata_test_" + uuid4().hex
    admin = sa.create_engine(base, isolation_level="AUTOCOMMIT", hide_parameters=True)
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
        yield DatabaseSettings(
            url=base.set(database=name).render_as_string(hide_password=False)
        )
    finally:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}"')
        admin.dispose()


@pytest.fixture
def store(database):
    result = SQLMetadataStore(database)
    try:
        result.migrate()
        yield result
    finally:
        result.close()


def intent(**changes):
    identity = uuid4()
    return SandboxIntent.model_validate(
        {
            "id": str(identity),
            "scope": "sandbox/" + str(identity),
            "name": "calm-otter-123ab",
            "owner": "alice@example.com",
            "provider": "agentSandbox",
            "provider_instance": "test",
            "manifest": {"agentSandbox": {"spec": {"image": "tools:v1"}}},
            "profile_snapshot": {
                "id": "engineering",
                "helpers": [{"script": "echo hello"}],
            },
            **changes,
        }
    )


def create(store, **changes):
    return store.reserve_create(intent(**changes), uuid4())


def test_explicit_schema_setup_and_idempotent_upgrade(database):
    store = SQLMetadataStore(database)
    try:
        with pytest.raises(SchemaMismatch):
            store.check_schema()
        store.migrate()
        record = create(store)
        store.migrate()
        store.check_schema()
        assert store.get_sandbox(record.id) == record
        with store.engine.connect() as connection:
            assert not compare_metadata(
                MigrationContext.configure(connection), metadata
            )
    finally:
        store.close()


def test_round_trip_and_restart_preserve_intent_and_profile(store, database):
    record = create(store)
    assert record.created_at.tzinfo == UTC and record.updated_at.tzinfo == UTC
    assert record.binding is None and record.revision == 1
    other = SQLMetadataStore(database)
    try:
        assert other.get_sandbox(record.id) == record
        other.get_sandbox(record.id).manifest.clear()
        assert other.get_sandbox(record.id).manifest == record.manifest
    finally:
        other.close()
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from os import environ
from uuid import UUID
from portal.storage import open_store
from portal.storage.database import DatabaseSettings
store = open_store(DatabaseSettings(url=environ['PORTAL_DATABASE_URL']))
print(store.get_sandbox(UUID(environ['SANDBOX_TEST_ID'])).model_dump_json())
store.close()
""",
        ],
        env={
            **os.environ,
            "PORTAL_DATABASE_URL": database.url,
            "SANDBOX_TEST_ID": str(record.id),
        },
        capture_output=True,
        text=True,
        check=True,
    )
    assert type(record).model_validate_json(process.stdout) == record


def test_retry_returns_one_record_and_changed_input_rolls_back(store):
    request, original = uuid4(), intent()
    first = store.reserve_create(original, request)
    assert store.reserve_create(original, request) == first
    with pytest.raises(Conflict):
        store.reserve_create(intent(name="new-otter-123ab"), request)
    assert store.list_authorized_sandboxes(original.owner) == [first]


def test_request_keys_and_names_are_scoped_to_owner(store):
    request = uuid4()
    alice = store.reserve_create(intent(), request)
    bob = store.reserve_create(intent(owner="bob@example.com"), request)
    assert alice.id != bob.id
    with pytest.raises(Conflict):
        create(store)
    assert store.list_authorized_sandboxes(alice.owner) == [alice]
    assert store.list_authorized_sandboxes(bob.owner) == [bob]


def test_grants_are_atomic_revocable_and_do_not_grant_ownership(store):
    record = create(store)
    assert not store.list_authorized_sandboxes("bob@example.com")
    shared = store.set_scope_grants(
        record.id, members={"bob@example.com": "shell"}, expected_revision=1
    )
    assert shared.revision == 2 and shared.owner == record.owner
    assert store.list_authorized_sandboxes("bob@example.com") == [shared]
    with pytest.raises(ValueError):
        store.set_scope_grants(
            record.id, {"bob@example.com": "admin"}, expected_revision=2
        )
    assert store.get_sandbox(record.id) == shared
    store.set_scope_grants(record.id, {}, expected_revision=2)
    assert not store.list_authorized_sandboxes("bob@example.com")


def test_stale_manifest_and_grants_cannot_overwrite_each_other(store):
    record = create(store)
    changed = store.revise_manifest(
        record.id,
        {"native": [1, True, None]},
        expected_revision=1,
        requested_mode="suspended",
    )
    assert changed.revision == 2 and changed.requested_mode == "suspended"
    assert changed.profile_snapshot == record.profile_snapshot
    with pytest.raises(Conflict):
        store.set_scope_grants(
            record.id, {"bob@example.com": "view"}, expected_revision=1
        )
    with pytest.raises(Conflict):
        store.revise_manifest(
            record.id, {}, expected_revision=1, requested_mode="running"
        )
    assert store.get_sandbox(record.id) == changed


def test_integration_operation_preserves_native_fence_and_repairs_only_failed_attempt(
    store,
):
    record = create(store)
    record = store.finish_operation(
        record.id, expected_revision=record.revision, resource_usage={}
    )
    operation = PendingOperation(
        kind="integration",
        request_id=uuid4(),
        actor=record.owner,
        parameters={"native_revision": "42", "base_policy": {"version": 1}},
    )
    record = store.begin_operation(
        record.id,
        operation,
        expected_revision=record.revision,
        manifest={"spec": {"policy": {"version": 1}}},
        requested_mode="running",
        resource_usage={},
    )
    assert store.get_sandbox(record.id).operation.parameters == operation.parameters
    replacement = operation.model_copy(update={"request_id": uuid4()})
    arguments = dict(
        manifest=record.manifest, requested_mode="running", resource_usage={}
    )
    with pytest.raises(Conflict):
        store.begin_operation(
            record.id,
            replacement,
            expected_revision=record.revision,
            replace_operation_id=operation.request_id,
            **arguments,
        )
    record = store.operation_needs_attention(
        record.id,
        expected_revision=record.revision,
        error="Runtime configuration needs attention",
    )
    saved = store.get_sandbox(record.id)
    assert saved.operation.error == "Runtime configuration needs attention"
    assert saved.operation.parameters["native_revision"] == "42"
    with pytest.raises(Conflict):
        store.begin_operation(
            record.id,
            replacement,
            expected_revision=record.revision,
            replace_operation_id=uuid4(),
            **arguments,
        )
    repaired = store.begin_operation(
        record.id,
        replacement,
        expected_revision=record.revision,
        replace_operation_id=operation.request_id,
        **arguments,
    )
    assert repaired.operation == replacement
    assert repaired.profile_snapshot == record.profile_snapshot


def test_native_identity_is_immutable_unique_and_retry_safe(store):
    first = create(store)
    second = create(store, name="kind-otter-123ab")
    native = NativeBinding(
        key="native-id", reference={"workspace": "native-workspace", "id": "native-id"}
    )
    bound = store.confirm_binding(first.id, native, expected_revision=1)
    assert bound.binding == native and bound.revision == 2
    assert store.confirm_binding(first.id, native, expected_revision=1) == bound
    with pytest.raises(Conflict):
        store.confirm_binding(second.id, native, expected_revision=1)
    with pytest.raises(Conflict):
        store.confirm_binding(
            first.id,
            NativeBinding(key="replacement", reference={}),
            expected_revision=2,
        )
    assert store.get_sandbox(second.id).binding is None
    third = create(store, name="warm-otter-123ab", provider_instance="another-provider")
    assert (
        store.confirm_binding(third.id, native, expected_revision=1).binding == native
    )


def test_provider_specific_json_and_missing_profile_are_preserved(store):
    record = create(
        store,
        provider="futureProvider",
        manifest={"native": {"workers": ["shared"]}},
        profile_snapshot=None,
    )
    assert store.get_sandbox(record.id) == record
    assert record.profile_snapshot is None


def test_authorized_pagination_has_no_duplicate_or_unshared_rows(store):
    records = [create(store, name=f"test-{i}") for i in range(3)]
    create(store, owner="bob@example.com")
    first = store.list_authorized_sandboxes(records[0].owner, limit=1)
    rest = store.list_authorized_sandboxes(records[0].owner, after=first[-1].id)
    assert {r.id for r in [*first, *rest]} == {r.id for r in records}
    assert not store.list_authorized_sandboxes("stranger@example.com")
    with pytest.raises(ValueError):
        store.list_authorized_sandboxes(records[0].owner, limit=10000)


def test_simultaneous_duplicate_creates_reserve_one_identity(store):
    request, original = uuid4(), intent()
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(
            pool.map(lambda _: store.reserve_create(original, request), range(8))
        )
    assert len({r.id for r in records}) == 1
    assert len(store.list_authorized_sandboxes(original.owner)) == 1


def test_simultaneous_revision_changes_have_one_winner(store):
    record = create(store)

    def change(value):
        try:
            return store.revise_manifest(
                record.id,
                {"value": value},
                expected_revision=1,
                requested_mode="running",
            )
        except Conflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, [1, 2]))
    assert sum(result is not None for result in results) == 1
    assert store.get_sandbox(record.id).revision == 2


def expire_lease(store, lease):
    with store.engine.begin() as connection:
        connection.execute(
            leases.update()
            .where(leases.c.name == lease.name)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=60))
        )


def test_claims_are_exclusive_across_clients_and_independent_by_name(store, database):
    other = SQLMetadataStore(database)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda client: client.acquire_lease("same-operation", seconds=30),
                    [store, other],
                )
            )
        (winner,) = [result for result in results if result is not None]
        assert other.acquire_lease("unrelated-operation", seconds=30)
        assert other.renew_lease(winner, seconds=30)
        store.release_lease(winner)
        assert other.acquire_lease("same-operation", seconds=30)
    finally:
        other.close()


def test_expired_owner_cannot_renew_or_release_its_successor(store):
    first = store.acquire_lease("operation", seconds=30)
    expire_lease(store, first)
    assert not store.renew_lease(first, seconds=30)
    second = store.acquire_lease("operation", seconds=30)
    assert second.token != first.token
    store.release_lease(first)
    assert store.acquire_lease("operation", seconds=30) is None
    assert store.renew_lease(second, seconds=30)


@pytest.mark.parametrize("completion", ["bind", "finish", "attention"])
def test_stale_owner_cannot_complete_or_change_pending_operation(store, completion):
    record = create(store)
    first = store.acquire_lease(f"sandbox/{record.id}", seconds=30)
    expire_lease(store, first)
    second = store.acquire_lease(first.name, seconds=30)

    def complete(lease, operation_id=record.operation.request_id):
        arguments = dict(
            expected_revision=record.revision,
            lease=lease,
            operation_id=operation_id,
        )
        if completion == "bind":
            return store.confirm_binding(
                record.id, NativeBinding(key="native", reference={}), **arguments
            )
        if completion == "finish":
            return store.finish_operation(record.id, resource_usage={}, **arguments)
        return store.operation_needs_attention(record.id, **arguments)

    with pytest.raises(Conflict, match="expired"):
        complete(first)
    with pytest.raises(Conflict, match="operation changed"):
        complete(second, uuid4())
    assert store.get_sandbox(record.id) == record
    assert complete(second).revision == 2


def test_claimed_completion_preserves_concurrent_grants_and_controls(store):
    record = create(store)
    lease = store.acquire_lease(f"sandbox/{record.id}", seconds=30)
    shared = store.set_scope_grants(
        record.id, {"bob@example.com": "shell"}, expected_revision=1
    )
    controlled = store.save_sandbox_control(
        record.id, {"disabled": True}, expected_revision=shared.revision
    )
    bound = store.confirm_binding(
        record.id,
        NativeBinding(key="native", reference={}),
        expected_revision=record.revision,
        lease=lease,
        operation_id=record.operation.request_id,
    )
    assert bound.revision == controlled.revision + 1
    assert bound.grants == shared.grants and bound.control == controlled.control
    assert bound.binding and bound.operation is None


def test_operation_claim_cannot_be_used_for_another_sandbox(store):
    record = create(store)
    lease = store.acquire_lease(f"sandbox/{uuid4()}", seconds=30)
    with pytest.raises(Conflict, match="does not match"):
        store.operation_needs_attention(
            record.id,
            expected_revision=1,
            lease=lease,
            operation_id=record.operation.request_id,
        )


def test_claim_migration_preserves_pending_intent_grants_and_controls(database):
    from alembic import command

    store = SQLMetadataStore(database)
    try:
        with store._transaction(write=True) as connection:
            command.upgrade(store._migration_config(connection), "0003_sandbox_state")
            original = intent(scope="workspace")
            sandboxes = sa.Table("sandboxes", sa.MetaData(), autoload_with=connection)

            old_grants = sa.table(
                "sandbox_grants",
                sa.column("sandbox_id"),
                sa.column("principal"),
                sa.column("role"),
            )
            connection.execute(
                sandboxes.insert().values(
                    **original.model_dump(mode="json", exclude={"scope_owner"}),
                    revision=3,
                    control={"disabled": True},
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
            )
            connection.execute(
                old_grants.insert().values(
                    sandbox_id=str(original.id),
                    principal="bob@example.com",
                    role="shell",
                )
            )
        store.migrate()
        store.check_schema()
        saved = store.get_sandbox(original.id)
        assert saved.manifest == original.manifest and saved.control == {
            "disabled": True
        }
        assert saved.grants == {"bob@example.com": "shell"} and saved.revision == 3
        assert store.acquire_lease(f"sandbox/{original.id}", seconds=30)
    finally:
        store.close()


def test_scope_is_in_use_until_deletion_is_confirmed(store):
    from portal.storage import PendingOperation

    record = create(store, scope="workspace")
    assert store.scope_has_sandboxes(
        record.provider, record.provider_instance, record.scope
    )
    assert not store.scope_has_sandboxes(
        record.provider, "another-instance", record.scope
    )
    assert not store.scope_has_sandboxes(
        "another-provider", record.provider_instance, record.scope
    )
    bound = store.confirm_binding(
        record.id, NativeBinding(key="native", reference={}), expected_revision=1
    )
    deleting = store.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=bound.revision,
        manifest=record.manifest,
        requested_mode="suspended",
        resource_usage={},
    )
    assert store.scope_has_sandboxes(
        record.provider, record.provider_instance, record.scope
    )
    store.finish_operation(
        record.id, expected_revision=deleting.revision, resource_usage={}, deleted=True
    )
    assert not store.scope_has_sandboxes(
        record.provider, record.provider_instance, record.scope
    )


def test_future_schema_is_rejected_without_changing_records(store):
    record = create(store)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE alembic_version SET version_num='future_schema'"
        )
    with pytest.raises(SchemaMismatch):
        store.check_schema()
    with pytest.raises(SchemaMismatch):
        store.migrate()
    assert store.get_sandbox(record.id) == record


def test_controls_are_seeded_and_survive_restart_and_schema_upgrade(store, database):
    initial = store.get_controls()
    assert initial.policy == {} and initial.revision == 1
    policy = {
        "sandboxes_disabled": True,
        "users": {"alice@example.com": {"creation_disabled": True}},
        "announcement": {"title": "Maintenance", "body": "Please save your work"},
    }
    saved = store.save_controls(policy, expected_revision=1)
    assert saved.revision == 2 and saved.policy == policy
    restarted = SQLMetadataStore(database)
    try:
        restarted.migrate()
        assert restarted.get_controls() == saved
        restarted.get_controls().policy.clear()
        assert restarted.get_controls() == saved
    finally:
        restarted.close()


def test_controls_updates_are_atomic_across_independent_connections(store, database):
    other = SQLMetadataStore(database)

    def change(client, reason):
        try:
            return client.save_controls({"reason": reason}, expected_revision=1)
        except Conflict:
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(change, store, "First admin")
            second = pool.submit(change, other, "Second admin")
            winners = [r for r in [first.result(), second.result()] if r is not None]
        assert len(winners) == 1
        assert store.get_controls() == winners[0] and winners[0].revision == 2
    finally:
        other.close()


def test_deleted_controls_are_never_implicitly_recreated(store):
    with store.engine.begin() as connection:
        connection.execute(controls.delete())
    with pytest.raises(StorageError, match="controls are missing"):
        store.get_controls()
    with pytest.raises(Conflict):
        store.save_controls({}, expected_revision=1)
    store.migrate()
    with pytest.raises(StorageError):
        store.get_controls()


def previous_schema_record(store):
    record = SandboxRecord(
        **intent().model_dump(),
        revision=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    with store.engine.begin() as connection:
        previous = sa.Table("sandboxes", sa.MetaData(), autoload_with=connection)
        values = record.model_dump(mode="json")
        values.update(created_at=record.created_at, updated_at=record.updated_at)
        connection.execute(
            previous.insert().values(
                **{key: value for key, value in values.items() if key in previous.c}
            )
        )
    return record


def test_controls_migration_preserves_existing_sandbox_records(database):
    from alembic import command

    store = SQLMetadataStore(database)
    try:
        with store.engine.begin() as connection:
            command.upgrade(store._migration_config(connection), "0001_metadata")
        record = previous_schema_record(store)
        with pytest.raises(SchemaMismatch):
            store.check_schema()
        store.migrate()
        store.check_schema()
        assert store.get_sandbox(record.id) == record
        assert store.get_controls().revision == 1
    finally:
        store.close()


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url-with-private-password",
        "mysql://private-password@host/db",
        "sqlite:///:memory:",
        "sqlite:///relative.db",
        "sqlite:////tmp/db?password=private-password",
        "postgresql://host",
        "sqlite+aiosqlite:////tmp/db",
    ],
)
def test_unsupported_urls_are_rejected_without_echoing_credentials(url):
    with pytest.raises(ValueError) as error:
        DatabaseSettings(url=url).parsed_url()
    assert "private-password" not in str(error.value)
    assert "private-password" not in repr(DatabaseSettings(url=url))


def test_schema_cli_uses_environment_without_printing_database_url(tmp_path):
    url = f"sqlite:///{tmp_path / 'private-location.db'}"
    env = {**os.environ, "PORTAL_DATABASE_URL": url}
    for action, expected in [("check", 1), ("migrate", 0), ("check", 0)]:
        result = subprocess.run(
            [sys.executable, "-m", "portal.storage", action],
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == expected, result.stderr
        assert url not in result.stdout + result.stderr


def schema_command(database, action):
    return subprocess.run(
        [sys.executable, "-m", "portal.storage", action],
        env={**os.environ, "PORTAL_DATABASE_URL": database.url},
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_check_of_empty_schema_is_read_only_and_requests_recreate(database):
    store = SQLMetadataStore(database)
    try:
        result = schema_command(database, "check")
        assert result.returncode == 1
        assert "Database schema upgrade required" in result.stderr
        assert "strategy.type=Recreate" in result.stderr
        with store.engine.connect() as connection:
            assert not sa.inspect(connection).get_table_names()
    finally:
        store.close()


def test_check_of_older_schema_preserves_version_and_records(database):
    from alembic import command

    store = SQLMetadataStore(database)
    try:
        with store.engine.begin() as connection:
            command.upgrade(store._migration_config(connection), "0001_metadata")
        record = previous_schema_record(store)
        result = schema_command(database, "check")
        assert result.returncode == 1 and "strategy.type=Recreate" in result.stderr
        with store.engine.connect() as connection:
            assert MigrationContext.configure(connection).get_current_heads() == (
                "0001_metadata",
            )
        with store.engine.connect() as connection:
            previous = sa.Table("sandboxes", sa.MetaData(), autoload_with=connection)
            assert (
                connection.execute(sa.select(previous.c.manifest)).scalar_one()
                == record.manifest
            )
        with pytest.raises(SchemaUpgradeRequired):
            store.check_schema()
        assert schema_command(database, "migrate").returncode == 0
        assert schema_command(database, "check").returncode == 0
        assert store.get_sandbox(record.id) == record
    finally:
        store.close()


def test_unknown_schema_never_suggests_an_upgrade_or_changes_records(store, database):
    record = create(store)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE alembic_version SET version_num='future_schema'"
        )
    for action in ("check", "migrate"):
        result = schema_command(database, action)
        assert result.returncode == 1
        assert "newer or unknown" in result.stderr
        assert "strategy.type=Recreate" not in result.stderr
        assert "Recreate cannot downgrade" in result.stderr
    assert store.get_sandbox(record.id) == record
    with store.engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (
            "future_schema",
        )
        if connection.dialect.name == "postgresql":
            assert connection.scalar(
                sa.text("SELECT pg_try_advisory_xact_lock(:key)"),
                {"key": MIGRATION_LOCK_ID},
            )


def test_multiple_processes_migrate_an_empty_database_once(database):
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(
            pool.map(lambda _: schema_command(database, "migrate"), range(3))
        )
    assert [r.returncode for r in results] == [0, 0, 0], [r.stderr for r in results]
    store = SQLMetadataStore(database)
    try:
        store.check_schema()
        assert store.get_controls().revision == 1
    finally:
        store.close()


def test_migration_wait_is_bounded_and_releases_after_another_writer_finishes(database):
    store = SQLMetadataStore(database)
    try:
        with store.engine.connect().execution_options(
            metadata_write=True
        ) as connection:
            with connection.begin():
                if connection.dialect.name == "postgresql":
                    connection.execute(
                        sa.text("SELECT pg_advisory_xact_lock(:key)"),
                        {"key": MIGRATION_LOCK_ID},
                    )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        """
import os, sys
from portal.storage import StorageError, open_store
from portal.storage.database import DatabaseSettings
store = open_store(DatabaseSettings(url=os.environ["PORTAL_DATABASE_URL"], timeout_seconds=1))
try:
    store.migrate()
except StorageError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
finally:
    store.close()
""",
                    ],
                    env={**os.environ, "PORTAL_DATABASE_URL": database.url},
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                assert result.returncode == 1
                assert "strategy.type=Recreate" not in result.stderr
                if connection.dialect.name == "postgresql":
                    assert (
                        "Timed out waiting for another database migration"
                        in result.stderr
                    )
                assert not sa.inspect(connection).get_table_names()
        assert schema_command(database, "migrate").returncode == 0
        store.check_schema()
    finally:
        store.close()


def test_current_schema_check_does_not_need_the_migration_lock(store, database):
    with store.engine.connect().execution_options(metadata_write=True) as connection:
        with connection.begin():
            if connection.dialect.name == "postgresql":
                connection.execute(
                    sa.text("SELECT pg_advisory_xact_lock(:key)"),
                    {"key": MIGRATION_LOCK_ID},
                )
            assert schema_command(database, "check").returncode == 0


@pytest.mark.parametrize("action", ["check", "migrate"])
def test_cli_connection_errors_are_distinct_from_schema_changes(action):
    result = schema_command(
        DatabaseSettings(
            url="postgresql://portal:private-password@127.0.0.1:1/missing"
        ),
        action,
    )
    assert result.returncode == 1
    assert "Metadata database is unavailable" in result.stderr
    assert "strategy.type=Recreate" not in result.stderr
    assert "private-password" not in result.stdout + result.stderr


def test_connection_errors_do_not_expose_credentials():
    store = open_store(
        DatabaseSettings(
            url="postgresql://portal:private-password@127.0.0.1:1/missing",
            timeout_seconds=1,
        )
    )
    try:
        with pytest.raises(StorageError) as error:
            store.check_schema()
        assert "private-password" not in str(error.value)
    finally:
        store.close()


@pytest.mark.parametrize("value", [float("inf"), float("nan")])
def test_non_finite_json_is_rejected_consistently(value):
    with pytest.raises(ValueError):
        intent(manifest={"value": value})
    with pytest.raises(ValueError):
        NativeBinding(key="native", reference={"value": value})


def test_quota_reservation_is_atomic_across_store_instances(store, database):
    other = SQLMetadataStore(database)
    try:

        def reserve(index):
            target = store if index == 0 else other
            try:
                return target.reserve_create(
                    intent(name=f"calm-fox-{index}", resource_usage={"pods": "1"}),
                    uuid4(),
                    quota={"pods": "1"},
                )
            except Conflict:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(reserve, range(2)))
        assert sum(result is not None for result in results) == 1
        assert len(store.list_authorized_sandboxes("alice@example.com")) == 1
    finally:
        other.close()


def test_five_sandbox_limit_counts_all_owner_allocations(store, database):
    key = "count/sandboxes.agents.x-k8s.io"
    quota, usage = {key: "5"}, {key: "1"}
    other = SQLMetadataStore(database)
    try:

        def reserve(index):
            try:
                return (store if index % 2 else other).reserve_create(
                    intent(
                        name=f"calm-fox-{index}",
                        provider="openShell" if index % 2 else "agentSandbox",
                        requested_mode="running" if index % 2 else "suspended",
                        resource_usage=usage,
                    ),
                    uuid4(),
                    quota=quota,
                )
            except Conflict as exc:
                assert "limit of 5 micro VMs" in str(exc)
                return None

        with ThreadPoolExecutor(max_workers=6) as executor:
            records = [r for r in executor.map(reserve, range(6)) if r is not None]
        assert len(records) == 5
        assert len({r.scope for r in records}) == 5
        assert {r.provider for r in records} == {"agentSandbox", "openShell"}
        assert {r.requested_mode for r in records} == {"running", "suspended"}
        assert all(r.operation.kind == "create" for r in records)
        record = store.operation_needs_attention(
            records[0].id, expected_revision=records[0].revision
        )
        assert reserve(6) is None
        store.reserve_create(
            intent(owner="bob@example.com", resource_usage=usage), uuid4(), quota=quota
        )
        record = store.finish_operation(
            record.id, expected_revision=record.revision, resource_usage=usage
        )
        record = store.begin_operation(
            record.id,
            PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
            expected_revision=record.revision,
            manifest=record.manifest,
            requested_mode=record.requested_mode,
            resource_usage=usage,
        )
        assert reserve(6) is None
        store.finish_operation(
            record.id,
            expected_revision=record.revision,
            resource_usage={},
            deleted=True,
        )
        assert reserve(6) is not None
    finally:
        other.close()


def test_pending_operation_and_tombstone_survive_restart(store, database):
    from portal.storage import PendingOperation

    record = create(store, scope="team/project", resource_usage={"pods": "1"})
    record = store.confirm_binding(
        record.id,
        NativeBinding(key="native-42", reference={"id": "42"}),
        expected_revision=record.revision,
    )
    record = store.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="running",
        resource_usage=record.resource_usage,
    )
    record = store.operation_needs_attention(
        record.id, expected_revision=record.revision
    )
    other = SQLMetadataStore(database)
    try:
        assert other.get_sandbox(record.id) == record
        deleted = other.finish_operation(
            record.id,
            expected_revision=record.revision,
            resource_usage={},
            deleted=True,
        )
        assert deleted.deleted_at and not deleted.operation
        assert store.list_authorized_sandboxes(record.owner) == []
        assert store.list_sandboxes() == []
        assert store.get_sandbox(record.id).deleted_at
    finally:
        other.close()


def test_concurrent_deletion_observations_are_idempotent(store):
    from portal.storage import PendingOperation

    record = create(store)
    record = store.confirm_binding(
        record.id,
        NativeBinding(key="deleted-native", reference={"id": "42"}),
        expected_revision=record.revision,
    )
    record = store.begin_operation(
        record.id,
        PendingOperation(kind="delete", request_id=uuid4(), actor=record.owner),
        expected_revision=record.revision,
        manifest=record.manifest,
        requested_mode="running",
        resource_usage={"pods": "1"},
    )

    def confirm(_):
        return store.finish_operation(
            record.id,
            expected_revision=record.revision,
            resource_usage={},
            deleted=True,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(confirm, range(4)))
    assert all(result == results[0] for result in results)
    assert results[0].deleted_at
    with pytest.raises(Conflict):
        store.finish_operation(
            record.id,
            expected_revision=results[0].revision,
            resource_usage={"pods": "1"},
        )


def test_scope_grants_cover_future_siblings_but_never_other_owners_or_providers(store):
    first = create(store, scope="shared")
    sibling = create(store, name="calm-wolf", scope="shared")
    for index, changes in enumerate(
        (
            {"provider": "other"},
            {"provider_instance": "other"},
            {"owner": "other@example.com"},
            {"scope": "elsewhere"},
        )
    ):
        create(store, name=f"outside-{index}", **{"scope": "shared", **changes})
    store.set_scope_grants(first.id, {"bob@example.com": "shell"}, expected_revision=1)
    future = create(store, name="calm-lynx", scope="shared")
    assert {r.id for r in store.list_authorized_sandboxes("bob@example.com")} == {
        first.id,
        sibling.id,
        future.id,
    }
    with pytest.raises(Conflict):
        store.set_scope_grants(sibling.id, {}, expected_revision=1)
    store.set_scope_grants(sibling.id, {"bob@example.com": "view"}, expected_revision=2)
    assert all(
        r.grants == {"bob@example.com": "view"}
        for r in store.list_authorized_sandboxes("bob@example.com")
    )
    store.set_scope_grants(future.id, {}, expected_revision=2)
    assert not store.list_authorized_sandboxes("bob@example.com")


def test_simultaneous_scope_edits_through_different_siblings_have_one_winner(store):
    first = create(store, scope="shared")
    second = create(store, name="calm-wolf", scope="shared")

    def change(record):
        try:
            store.set_scope_grants(
                record.id, {"bob@example.com": "view"}, expected_revision=1
            )
            return True
        except Conflict:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(change, (first, second))) == [False, True]
    assert store.get_sandbox(first.id).grants == store.get_sandbox(second.id).grants


def test_scope_migration_preserves_only_access_common_to_all_live_siblings(database):
    from alembic import command

    store = SQLMetadataStore(database)
    try:
        with store._transaction(write=True) as connection:
            command.upgrade(
                store._migration_config(connection), "0004_operation_leases"
            )
            sandboxes = sa.Table("sandboxes", sa.MetaData(), autoload_with=connection)
            old = sa.table(
                "sandbox_grants",
                sa.column("sandbox_id"),
                sa.column("principal"),
                sa.column("role"),
            )
            originals = []
            for index, (scope, members) in enumerate(
                [
                    (
                        "shared",
                        {"bob@example.com": "shell", "carol@example.com": "shell"},
                    ),
                    ("shared", {"bob@example.com": "view"}),
                    ("separate", {"bob@example.com": "shell"}),
                    ("", {"carol@example.com": "shell"}),
                    ("", {}),
                ]
            ):
                original = intent(name=f"old-{index}", scope=scope or "temporary")
                originals.append(original)
                connection.execute(
                    sandboxes.insert().values(
                        **{
                            **original.model_dump(mode="json", exclude={"scope_owner"}),
                            "scope": scope,
                        },
                        revision=1,
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                    )
                )
                for principal, role in members.items():
                    connection.execute(
                        old.insert().values(
                            sandbox_id=str(original.id), principal=principal, role=role
                        )
                    )
        store.migrate()
        actual = [store.get_sandbox(original.id) for original in originals]
        assert actual[0].grants == actual[1].grants == {"bob@example.com": "view"}
        assert actual[2].grants == {"bob@example.com": "shell"}
        assert (
            actual[3].grants == {"carol@example.com": "shell"}
            and actual[4].grants == {}
        )
        assert actual[3].scope != actual[4].scope
        store.migrate()
        assert store.get_sandbox(originals[0].id) == actual[0]
    finally:
        store.close()


@pytest.mark.parametrize("rejected", [False, True])
def test_failed_creation_cancellation_requires_fence_and_confirmed_rejection(
    store, rejected
):
    record = create(store, resource_usage={"pods": "1"})
    record = store.operation_needs_attention(
        record.id, expected_revision=record.revision, creation_rejected=rejected
    )
    arguments = dict(expected_revision=record.revision, resource_usage={}, deleted=True)
    with pytest.raises(Conflict):
        store.finish_operation(record.id, **arguments)
    lease = store.acquire_lease(f"sandbox/{record.id}", seconds=30)
    fence = dict(lease=lease, operation_id=record.operation.request_id)
    if rejected:
        cancelled = store.finish_operation(record.id, **arguments, **fence)
        assert (
            cancelled.deleted_at
            and not cancelled.operation
            and not cancelled.resource_usage
        )
    else:
        with pytest.raises(Conflict):
            store.finish_operation(record.id, **arguments, **fence)
        assert store.get_sandbox(record.id).resource_usage == {"pods": "1"}
    store.release_lease(lease)


@pytest.mark.parametrize(
    "revision", ["0007_acp_bindings", "0007_namespace_network_policy"]
)
def test_merge_preserves_existing_metadata_histories(database, revision):
    from alembic import command

    from portal.storage.schema import acp_bindings

    store = SQLMetadataStore(database)
    try:
        with store._transaction(write=True) as connection:
            command.upgrade(store._migration_config(connection), revision)
            if revision == "0007_acp_bindings":
                connection.execute(
                    acp_bindings.insert().values(
                        sandbox_uid="existing",
                        owner_subject="owner",
                        conversation_id="conversation",
                        binding_id="binding",
                        policy_revision="revision",
                        active_run_id="run",
                        process_token="token",
                    )
                )
        store.migrate()
        store.check_schema()
        if revision == "0007_acp_bindings":
            assert store.acp_binding("existing")["active_run_id"] == "run"
        else:
            assert store.acp_binding("existing") is None
    finally:
        store.close()
