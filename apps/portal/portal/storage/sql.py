"""One metadata implementation for SQLite and PostgreSQL."""

import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from pydantic import ValidationError

from ..integrations.caipe.storage import CAIPEStorage
from . import (
    Conflict,
    Lease,
    ManifestUpdate,
    NativeBinding,
    PendingOperation,
    PortalControls,
    SandboxIntent,
    SandboxRecord,
    SchemaMismatch,
    SchemaUpgradeRequired,
    StorageError,
)
from .database import DatabaseSettings
from .schema import controls, grants, leases, requests, sandboxes

# Transaction-scoped and shared by all migrators of this database.
MIGRATION_LOCK_ID = 0x706F7274616C6462
SCOPE_FIELDS = ("owner", "provider", "provider_instance", "scope")


def grant_scope(columns):
    return sa.and_(
        *(
            grants.c[field] == columns["scope_owner" if field == "owner" else field]
            for field in SCOPE_FIELDS
        )
    )


class SQLMetadataStore(CAIPEStorage):
    def __init__(self, settings: DatabaseSettings):
        self.engine = settings.engine()
        self.migration_lock_timeout_ms = settings.timeout_seconds * 1000
        self.metadata_integrations = {}

    def register_metadata_integration(self, integration_id, *, tables, cleanup_sandbox):
        self.metadata_integrations[integration_id] = {
            "tables": tuple(tables),
            "cleanup_sandbox": cleanup_sandbox,
        }

    def close(self):
        self.engine.dispose()

    def _database_time(self, connection):
        clock = (
            sa.func.clock_timestamp()
            if connection.dialect.name == "postgresql"
            else sa.func.current_timestamp()
        )
        value = connection.execute(sa.select(clock)).scalar_one()
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

    def acquire_lease(self, name, *, seconds):
        if not 1 <= seconds <= 3600:
            raise ValueError("Lease duration must be between 1 and 3600 seconds")
        try:
            with self._transaction(write=True) as connection:
                now = self._database_time(connection)
                lease = Lease(
                    name=name,
                    token=uuid4(),
                    expires_at=now + timedelta(seconds=seconds),
                )
                existing = (
                    connection.execute(sa.select(leases).where(leases.c.name == name))
                    .mappings()
                    .first()
                )
                if existing is None:
                    connection.execute(
                        leases.insert().values(
                            **lease.model_dump(exclude={"token"}),
                            token=str(lease.token),
                        )
                    )
                else:
                    updated = connection.execute(
                        leases.update()
                        .where(leases.c.name == name, leases.c.expires_at <= now)
                        .values(token=str(lease.token), expires_at=lease.expires_at)
                    )
                    if updated.rowcount != 1:
                        return None
                return lease
        except Conflict:
            return None

    def renew_lease(self, lease, *, seconds):
        if not 1 <= seconds <= 3600:
            raise ValueError("Lease duration must be between 1 and 3600 seconds")
        with self._transaction(write=True) as connection:
            now = self._database_time(connection)
            result = connection.execute(
                leases.update()
                .where(
                    leases.c.name == lease.name,
                    leases.c.token == str(lease.token),
                    leases.c.expires_at > now,
                )
                .values(expires_at=now + timedelta(seconds=seconds))
            )
            return result.rowcount == 1

    def release_lease(self, lease):
        with self._transaction(write=True) as connection:
            connection.execute(
                leases.delete().where(
                    leases.c.name == lease.name, leases.c.token == str(lease.token)
                )
            )

    def scope_has_sandboxes(self, provider, provider_instance, scope):
        with self._transaction() as connection:
            return connection.execute(
                sa.select(
                    sa.exists().where(
                        sandboxes.c.provider == provider,
                        sandboxes.c.provider_instance == provider_instance,
                        sandboxes.c.scope == scope,
                        sandboxes.c.deleted_at.is_(None),
                    )
                )
            ).scalar_one()

    def _operation_revision(
        self, connection, sandbox_id, expected_revision, lease, operation_id
    ):
        if lease is None:
            return expected_revision
        if lease.name != f"sandbox/{sandbox_id}" or operation_id is None:
            raise Conflict("Operation claim does not match this sandbox")
        now = self._database_time(connection)
        query = (
            sa.select(leases.c.token)
            .where(
                leases.c.name == lease.name,
                leases.c.token == str(lease.token),
                leases.c.expires_at > now,
            )
            .with_for_update()
        )
        if connection.execute(query).scalar_one_or_none() is None:
            raise Conflict(
                "Operation ownership expired; refresh and confirm its outcome"
            )
        connection.execute(
            sa.select(sandboxes.c.id)
            .where(sandboxes.c.id == str(sandbox_id))
            .with_for_update()
        )
        current = self._record(connection, sandbox_id)
        if (
            current is None
            or current.operation is None
            or current.operation.request_id != operation_id
        ):
            raise Conflict("Sandbox operation changed; refresh and retry")
        return current.revision

    def _migration_config(self, connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path(__file__).parent / "migrations")
        )
        config.attributes["connection"] = connection
        return config

    @contextmanager
    def _transaction(self, *, write=False):
        try:
            with self.engine.connect() as connection:
                connection = connection.execution_options(metadata_write=write)
                with connection.begin():
                    yield connection
        except sa.exc.IntegrityError:
            raise Conflict("Metadata identity or revision conflict") from None
        except sa.exc.SQLAlchemyError:
            raise StorageError("Metadata database is unavailable") from None

    def migrate(self):
        """Explicit operator action; normal store construction never changes the schema."""
        try:
            with self._transaction(write=True) as connection:
                if connection.dialect.name == "postgresql":
                    self._lock_migrations(connection)
                try:
                    self._check_schema(connection)
                except SchemaUpgradeRequired:
                    command.upgrade(self._migration_config(connection), "head")
        except CommandError:
            raise SchemaMismatch(
                "Metadata schema cannot be upgraded by this release"
            ) from None

    def _lock_migrations(self, connection):
        connection.execute(
            sa.text("SELECT set_config('lock_timeout', :timeout, true)"),
            {"timeout": f"{self.migration_lock_timeout_ms}ms"},
        )
        try:
            connection.execute(
                sa.text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": MIGRATION_LOCK_ID},
            )
        except sa.exc.OperationalError as exc:
            if getattr(exc.orig, "sqlstate", None) == "55P03":
                raise StorageError(
                    "Timed out waiting for another database migration; retry after it finishes"
                ) from None
            raise

    def _check_schema(self, connection):
        current = set(MigrationContext.configure(connection).get_current_heads())
        scripts = ScriptDirectory.from_config(self._migration_config(connection))
        expected = set(scripts.get_heads())
        if len(expected) != 1:
            raise SchemaMismatch(
                "Portal image must contain exactly one metadata migration head"
            )
        if current == expected:
            return
        known = {revision.revision for revision in scripts.walk_revisions()}
        if current <= known:
            raise SchemaUpgradeRequired(
                "Database schema upgrade required. Upgrade with strategy.type=Recreate "
                "so existing portal replicas stop before migrations run."
            )
        raise SchemaMismatch(
            "Database schema is newer or unknown to this portal image. "
            "Use a compatible image or restore a supported backup; Recreate cannot downgrade it."
        )

    def check_schema(self):
        with self._transaction() as connection:
            self._check_schema(connection)

    def _controls(self, connection):
        row = connection.execute(sa.select(controls)).mappings().first()
        if row is None:
            raise StorageError("Required portal controls are missing; restore metadata")
        try:
            return PortalControls(policy=row["policy"], revision=row["revision"])
        except ValidationError:
            raise StorageError("Portal administrative metadata is invalid") from None

    def get_controls(self):
        with self._transaction() as connection:
            return self._controls(connection)

    def save_controls(self, policy, *, expected_revision):
        candidate = PortalControls(policy=policy, revision=expected_revision + 1)
        with self._transaction(write=True) as connection:
            result = connection.execute(
                controls.update()
                .where(
                    controls.c.id == "global", controls.c.revision == expected_revision
                )
                .values(policy=candidate.policy, revision=candidate.revision)
            )
            if result.rowcount != 1:
                raise Conflict("Admin controls changed; refresh and retry")
            return self._controls(connection)

    def _record(self, connection, sandbox_id):
        records = self._records(
            connection, sa.select(sandboxes).where(sandboxes.c.id == str(sandbox_id))
        )
        return records[0] if records else None

    def _records(self, connection, query):
        # Read each revision and its grants in the same database snapshot.
        page = query.subquery()
        joined = (
            sa.select(
                page,
                grants.c.principal.label("grantee"),
                grants.c.role.label("grant_role"),
            )
            .outerjoin(grants, grant_scope(page.c))
            .order_by(page.c.id)
        )
        rows = {}
        for row in connection.execute(joined).mappings():
            values = dict(row)
            principal, role = values.pop("grantee"), values.pop("grant_role")
            values = rows.setdefault(values["id"], {**values, "grants": {}})
            if principal is not None:
                values["grants"][principal] = role
        records = []
        for values in rows.values():
            key, reference = values.pop("native_key"), values.pop("native_reference")
            values["binding"] = (
                NativeBinding(key=key, reference=reference) if key else None
            )
            for field in ("created_at", "updated_at", "deleted_at"):
                timestamp = values[field]
                if timestamp is None:
                    continue
                values[field] = (
                    timestamp.astimezone(UTC)
                    if timestamp.tzinfo
                    else timestamp.replace(tzinfo=UTC)
                )
            try:
                records.append(SandboxRecord.model_validate(values))
            except ValidationError:
                raise StorageError("Saved sandbox metadata is invalid") from None
        return records

    def get_sandbox(self, sandbox_id):
        with self._transaction() as connection:
            return self._record(connection, sandbox_id)

    def find_creation(self, owner, request_id):
        with self._transaction() as connection:
            key = connection.execute(
                sa.select(requests.c.sandbox_id).where(
                    requests.c.owner == owner, requests.c.request_id == str(request_id)
                )
            ).scalar_one_or_none()
            return self._record(connection, key) if key else None

    def find_sandbox(self, name, *, owner=None, scope=None, scope_owner=None):
        query = sa.select(sandboxes).where(
            sandboxes.c.name == name, sandboxes.c.deleted_at.is_(None)
        )
        if owner is not None:
            query = query.where(sandboxes.c.owner == owner)
        if scope is not None:
            query = query.where(sandboxes.c.scope == scope)
        if scope_owner is not None:
            query = query.where(sandboxes.c.scope_owner == scope_owner)
        with self._transaction() as connection:
            records = self._records(connection, query.limit(2))
            if len(records) > 1:
                raise Conflict("Sandbox name is ambiguous; specify its owner and scope")
            return records[0] if records else None

    def _page(self, *, after, limit, include_deleted=False):
        if not 1 <= limit <= 200:
            raise ValueError("Page size must be between 1 and 200")
        query = sa.select(sandboxes)
        if not include_deleted:
            query = query.where(sandboxes.c.deleted_at.is_(None))
        if after is not None:
            query = query.where(sandboxes.c.id > str(after))
        return query.order_by(sandboxes.c.id).limit(limit)

    def list_sandboxes(
        self, *, after=None, limit=100, owner=None, include_deleted=False
    ):
        with self._transaction() as connection:
            query = self._page(
                after=after, limit=limit, include_deleted=include_deleted
            )
            if owner is not None:
                query = query.where(sandboxes.c.owner == owner)
            return self._records(connection, query)

    def list_scopes(self):
        columns = [
            sandboxes.c[field]
            for field in ("provider", "provider_instance", "scope", "scope_owner")
        ]
        with self._transaction() as connection:
            query = (
                sa.select(*columns, sa.func.count().label("count"))
                .where(sandboxes.c.deleted_at.is_(None))
                .group_by(*columns)
                .order_by(*columns)
            )
            return [dict(row) for row in connection.execute(query).mappings()]

    def clear_scope_grants(self, provider, provider_instance, scope):
        with self._transaction(write=True) as connection:
            connection.execute(
                grants.delete().where(
                    grants.c.provider == provider,
                    grants.c.provider_instance == provider_instance,
                    grants.c.scope == scope,
                )
            )

    def get_scope_grants(self, owner, provider, provider_instance, scope):
        with self._transaction() as connection:
            query = sa.select(grants.c.principal, grants.c.role).where(
                grants.c.owner == owner,
                grants.c.provider == provider,
                grants.c.provider_instance == provider_instance,
                grants.c.scope == scope,
            )
            return dict(connection.execute(query).all())

    def list_authorized_sandboxes(self, principal, *, after=None, limit=100):
        visible = sa.or_(
            sandboxes.c.owner == principal,
            sandboxes.c.scope_owner == principal,
            sa.exists().where(
                grant_scope(sandboxes.c), grants.c.principal == principal
            ),
        )
        query = self._page(after=after, limit=limit).where(visible)
        with self._transaction() as connection:
            return self._records(connection, query)

    def _check_quota(
        self, connection, owner, candidate, quota, retained, excluding=None
    ):
        if not quota:
            return
        if connection.dialect.name == "postgresql":
            connection.execute(
                sa.text("SELECT set_config('lock_timeout', :timeout, true)"),
                {"timeout": f"{self.migration_lock_timeout_ms}ms"},
            )
            key = int.from_bytes(
                hashlib.sha256(("quota/" + owner).encode()).digest()[:8],
                "big",
                signed=True,
            )
            connection.execute(
                sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": key}
            )
        query = sa.select(sandboxes.c.resource_usage).where(
            sandboxes.c.owner == owner, sandboxes.c.deleted_at.is_(None)
        )
        if excluding:
            query = query.where(sandboxes.c.id != str(excluding))
        totals = {key: Decimal(value) for key, value in (retained or {}).items()}
        for usage in [candidate, *connection.execute(query).scalars()]:
            for key, value in usage.items():
                totals[key] = totals.get(key, Decimal(0)) + Decimal(value)
        for key, limit in quota.items():
            if totals.get(key, Decimal(0)) > Decimal(limit):
                if key == "count/sandboxes.agents.x-k8s.io":
                    raise Conflict(
                        f"You have reached your limit of {limit} micro VMs. "
                        "Suspended micro VMs and unfinished creations also count. "
                        "Delete a micro VM to free a slot."
                    )
                raise Conflict(f"Owner resource quota exceeded: {key}")

    def _lock_scope(self, connection, provider, instance, scope):
        if connection.dialect.name == "postgresql":
            key = int.from_bytes(
                hashlib.sha256(
                    json.dumps([provider, instance, scope]).encode()
                ).digest()[:8],
                "big",
                signed=True,
            )
            connection.execute(
                sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": key}
            )

    def _scope_records(self, connection, provider, instance, scope):
        return (
            connection.execute(
                sa.select(sandboxes.c.id, sandboxes.c.profile_snapshot).where(
                    sandboxes.c.provider == provider,
                    sandboxes.c.provider_instance == instance,
                    sandboxes.c.scope == scope,
                    sandboxes.c.deleted_at.is_(None),
                )
            )
            .mappings()
            .all()
        )

    @staticmethod
    def _is_acp_snapshot(snapshot):
        return bool((snapshot or {}).get("definition", {}).get("acp"))

    def reserve_create(
        self, intent: SandboxIntent, request_id, *, quota=None, retained_usage=None
    ):
        request_id = UUID(str(request_id))
        payload = json.dumps(
            intent.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        fingerprint = hashlib.sha256(payload.encode()).hexdigest()
        request = sa.and_(
            requests.c.owner == intent.owner, requests.c.request_id == str(request_id)
        )
        try:
            with self._transaction(write=True) as connection:
                self._lock_scope(
                    connection, intent.provider, intent.provider_instance, intent.scope
                )
                siblings = self._scope_records(
                    connection, intent.provider, intent.provider_instance, intent.scope
                )
                if siblings and (
                    self._is_acp_snapshot(intent.profile_snapshot)
                    or any(
                        self._is_acp_snapshot(row["profile_snapshot"])
                        for row in siblings
                    )
                ):
                    raise Conflict(
                        "ACP coding sandboxes require an exclusive namespace"
                    )
                self._check_quota(
                    connection,
                    intent.owner,
                    intent.resource_usage,
                    quota,
                    retained_usage,
                )
                now = datetime.now(UTC)
                connection.execute(
                    sandboxes.insert().values(
                        **intent.model_dump(mode="json"),
                        operation=PendingOperation(
                            kind="create", request_id=request_id, actor=intent.owner
                        ).model_dump(mode="json"),
                        revision=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
                connection.execute(
                    requests.insert().values(
                        owner=intent.owner,
                        request_id=str(request_id),
                        fingerprint=fingerprint,
                        sandbox_id=str(intent.id),
                    )
                )
                return self._record(connection, intent.id)
        except Conflict:
            with self._transaction() as connection:
                saved = (
                    connection.execute(sa.select(requests).where(request))
                    .mappings()
                    .first()
                )
                if saved is None:
                    raise
                if saved["fingerprint"] != fingerprint:
                    raise Conflict(
                        "Creation request or sandbox name is already in use"
                    ) from None
                return self._record(connection, saved["sandbox_id"])

    def _revise(self, connection, sandbox_id, expected_revision, **values):
        result = connection.execute(
            sandboxes.update()
            .where(
                sandboxes.c.id == str(sandbox_id),
                sandboxes.c.revision == expected_revision,
            )
            .values(
                **values, revision=expected_revision + 1, updated_at=datetime.now(UTC)
            )
        )
        if result.rowcount != 1:
            raise Conflict("Sandbox changed; refresh and retry")

    def confirm_binding(
        self,
        sandbox_id,
        binding: NativeBinding,
        *,
        expected_revision,
        lease=None,
        operation_id=None,
    ):
        with self._transaction(write=True) as connection:
            expected_revision = self._operation_revision(
                connection, sandbox_id, expected_revision, lease, operation_id
            )
            current = self._record(connection, sandbox_id)
            if current is not None and current.binding == binding:
                return current
            if current is not None and current.binding is not None:
                raise Conflict("Sandbox is already bound to another native identity")
            self._revise(
                connection,
                sandbox_id,
                expected_revision,
                native_key=binding.key,
                native_reference=binding.reference,
                operation=None,
            )
            return self._record(connection, sandbox_id)

    def revise_manifest(
        self, sandbox_id, manifest, *, expected_revision, requested_mode
    ):
        candidate = ManifestUpdate(manifest=manifest, requested_mode=requested_mode)
        with self._transaction(write=True) as connection:
            self._revise(
                connection,
                sandbox_id,
                expected_revision,
                manifest=candidate.manifest,
                requested_mode=candidate.requested_mode,
            )
            return self._record(connection, sandbox_id)

    def _lock_acp_mutation(self, connection, sandbox_id):
        from .schema import acp_bindings

        row = connection.execute(
            sa.select(sandboxes.c.native_key)
            .where(sandboxes.c.id == str(sandbox_id))
            .with_for_update()
        ).first()
        if (
            row
            and row.native_key
            and connection.execute(
                sa.select(acp_bindings.c.sandbox_uid).where(
                    acp_bindings.c.sandbox_uid == row.native_key,
                    acp_bindings.c.active_run_id.is_not(None),
                )
            ).first()
        ):
            raise Conflict(
                "CAIPE process is active or unconfirmed; reconcile it before changing this sandbox"
            )

    def set_scope_grants(self, sandbox_id, members, *, expected_revision):
        if any(
            not isinstance(p, str)
            or not 1 <= len(p) <= 254
            or role not in {"view", "shell"}
            for p, role in members.items()
        ):
            raise ValueError("Sharing grants require principals and view/shell roles")
        with self._transaction(write=True) as connection:
            current = self._record(connection, sandbox_id)
            if current:
                self._lock_scope(
                    connection,
                    current.provider,
                    current.provider_instance,
                    current.scope,
                )
                for sibling in self._scope_records(
                    connection,
                    current.provider,
                    current.provider_instance,
                    current.scope,
                ):
                    self._lock_acp_mutation(connection, sibling["id"])
            current = self._record(connection, sandbox_id)
            if current is None or current.deleted_at:
                raise Conflict("Sandbox no longer exists")
            identity = {
                field: getattr(current, "scope_owner" if field == "owner" else field)
                for field in SCOPE_FIELDS
            }
            if connection.dialect.name == "postgresql":
                connection.execute(
                    sa.text("SELECT set_config('lock_timeout', :timeout, true)"),
                    {"timeout": f"{self.migration_lock_timeout_ms}ms"},
                )
                key = int.from_bytes(
                    hashlib.sha256(
                        json.dumps(identity, sort_keys=True).encode()
                    ).digest()[:8],
                    "big",
                    signed=True,
                )
                connection.execute(
                    sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": key}
                )
            if current.scope_owner in members:
                raise ValueError("The owner already has access")
            self._revise(connection, sandbox_id, expected_revision)
            siblings = sa.and_(
                *(
                    sandboxes.c["scope_owner" if field == "owner" else field] == value
                    for field, value in identity.items()
                )
            )
            connection.execute(
                sandboxes.update()
                .where(
                    siblings,
                    sandboxes.c.id != str(sandbox_id),
                    sandboxes.c.deleted_at.is_(None),
                )
                .values(revision=sandboxes.c.revision + 1, updated_at=datetime.now(UTC))
            )
            connection.execute(
                grants.delete().where(
                    *(grants.c[field] == value for field, value in identity.items())
                )
            )
            if members:
                connection.execute(
                    grants.insert(),
                    [
                        {
                            **identity,
                            "principal": principal,
                            "role": role,
                        }
                        for principal, role in members.items()
                    ],
                )
            return self._record(connection, sandbox_id)

    def save_sandbox_control(self, sandbox_id, control, *, expected_revision):
        with self._transaction(write=True) as connection:
            self._revise(connection, sandbox_id, expected_revision, control=control)
            return self._record(connection, sandbox_id)

    def begin_operation(
        self,
        sandbox_id,
        operation,
        *,
        expected_revision,
        manifest,
        requested_mode,
        resource_usage,
        quota=None,
        retained_usage=None,
        replace_operation_id=None,
    ):
        candidate = ManifestUpdate(manifest=manifest, requested_mode=requested_mode)
        with self._transaction(write=True) as connection:
            self._lock_acp_mutation(connection, sandbox_id)
            current = self._record(connection, sandbox_id)
            if current is None or current.deleted_at:
                raise Conflict(
                    "This micro VM has an unfinished action. Use its Retry button before starting another action."
                )
            if current.operation and not (
                current.operation.request_id == replace_operation_id
                and current.operation.kind == operation.kind == "integration"
                and current.operation.state == "needs_attention"
            ):
                raise Conflict(
                    "This micro VM has an unfinished action. Use its Retry button before starting another action."
                )
            self._check_quota(
                connection,
                current.owner,
                resource_usage,
                quota,
                retained_usage,
                sandbox_id,
            )
            self._revise(
                connection,
                sandbox_id,
                expected_revision,
                manifest=candidate.manifest,
                requested_mode=candidate.requested_mode,
                resource_usage=resource_usage,
                operation=operation.model_dump(mode="json"),
            )
            return self._record(connection, sandbox_id)

    def finish_operation(
        self,
        sandbox_id,
        *,
        expected_revision,
        resource_usage,
        deleted=False,
        lease=None,
        operation_id=None,
    ):
        try:
            with self._transaction(write=True) as connection:
                expected_revision = self._operation_revision(
                    connection, sandbox_id, expected_revision, lease, operation_id
                )
                # The same row serializes deletion and CAIPE admission on PostgreSQL;
                # SQLite write transactions are already serialized.
                connection.execute(
                    sa.select(sandboxes.c.id)
                    .where(sandboxes.c.id == str(sandbox_id))
                    .with_for_update()
                )
                current = self._record(connection, sandbox_id)
                if current is None or current.deleted_at or current.operation is None:
                    raise Conflict("Sandbox operation changed; refresh and retry")
                cancelled_creation = (
                    lease is not None
                    and current.binding is None
                    and current.operation.kind == "create"
                    and current.operation.state == "needs_attention"
                    and current.operation.parameters.get("_creation_rejected") is True
                )
                if (
                    deleted
                    and current.operation.kind != "delete"
                    and not cancelled_creation
                ):
                    raise Conflict("Deletion has not been requested")
                if deleted:
                    for integration in self.metadata_integrations.values():
                        integration["cleanup_sandbox"](connection, current)
                self._revise(
                    connection,
                    sandbox_id,
                    expected_revision,
                    operation=None,
                    resource_usage=resource_usage,
                    deleted_at=datetime.now(UTC) if deleted else None,
                )
                return self._record(connection, sandbox_id)
        except Conflict:
            # Concurrent inventory reads can confirm the same completed deletion.
            current = self.get_sandbox(sandbox_id) if deleted else None
            if current is not None and current.deleted_at:
                return current
            raise

    def operation_needs_attention(
        self,
        sandbox_id,
        *,
        expected_revision,
        error=None,
        creation_rejected=False,
        lease=None,
        operation_id=None,
    ):
        with self._transaction(write=True) as connection:
            expected_revision = self._operation_revision(
                connection, sandbox_id, expected_revision, lease, operation_id
            )
            current = self._record(connection, sandbox_id)
            if current is None or current.operation is None:
                raise Conflict("Sandbox operation changed; refresh and retry")
            operation = current.operation.model_copy(
                update={
                    "state": "needs_attention",
                    "parameters": {
                        **current.operation.parameters,
                        "_error": error,
                        **(
                            {"_creation_rejected": True}
                            if creation_rejected and current.operation.kind == "create"
                            else {}
                        ),
                    },
                }
            )
            self._revise(
                connection,
                sandbox_id,
                expected_revision,
                operation=operation.model_dump(mode="json"),
            )
            return self._record(connection, sandbox_id)
