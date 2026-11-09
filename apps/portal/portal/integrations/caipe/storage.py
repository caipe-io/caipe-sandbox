"""CAIPE conversation bindings stored in the portal metadata database."""

from datetime import UTC
from uuid import uuid4

import sqlalchemy as sa

from ...storage import ACPBindingConflict, ACPBusy, Conflict
from ...storage.schema import acp_bindings, leases, sandboxes

# The declaration is discoverable without assuming another integration's schema.
OWNED_TABLES = (acp_bindings,)


def cleanup_sandbox(connection, record):
    """Clean only idle CAIPE bindings after the native resource is gone."""
    if record.provider != "agentSandbox" or record.binding is None:
        return
    uid = record.binding.key
    row = connection.execute(
        sa.select(acp_bindings.c.active_run_id)
        .where(acp_bindings.c.sandbox_uid == uid)
        .with_for_update()
    ).first()
    if row is not None and row.active_run_id is not None:
        raise Conflict(
            "CAIPE process is active or unconfirmed; reconcile it before cleanup"
        )
    connection.execute(acp_bindings.delete().where(acp_bindings.c.sandbox_uid == uid))


class CAIPEStorage:
    def admit_acp(
        self,
        identity,
        run_id,
        *,
        sandbox_id=None,
        expected_revision=None,
        scope_identity=None,
        policy_lease=None,
    ):
        """Retain one conversation per sandbox; uncertain processes never expire."""
        try:
            return self._admit_acp(
                identity,
                run_id,
                sandbox_id=sandbox_id,
                expected_revision=expected_revision,
                scope_identity=scope_identity,
                policy_lease=policy_lease,
            )
        except (ACPBindingConflict, ACPBusy):
            raise
        except Conflict:
            # Another replica may win the first insert before this transaction.
            # Read only after rollback; classify its retained identity, not text.
            retained = self.acp_binding(identity["sandbox_uid"])
            if retained and all(
                retained[key] == value for key, value in identity.items()
            ):
                raise ACPBusy(
                    "Sandbox has an active or unconfirmed process; do not resend"
                ) from None
            if retained:
                raise ACPBindingConflict(
                    "Sandbox is already bound to another conversation or policy"
                ) from None
            raise

    def _admit_acp(
        self,
        identity,
        run_id,
        *,
        sandbox_id=None,
        expected_revision=None,
        scope_identity=None,
        policy_lease=None,
    ):
        with self._transaction(write=True) as connection:
            if scope_identity:
                self._lock_scope(connection, *scope_identity)
                siblings = self._scope_records(connection, *scope_identity)
                if len(siblings) != 1 or siblings[0]["id"] != str(sandbox_id):
                    raise ACPBusy("ACP coding sandboxes require an exclusive namespace")
            # Serialize admission with deletion, including first-ever bindings.
            native = connection.execute(
                sa.select(
                    sandboxes.c.deleted_at,
                    sandboxes.c.operation,
                    sandboxes.c.revision,
                    sandboxes.c.native_key,
                )
                .where(
                    sandboxes.c.id == str(sandbox_id)
                    if sandbox_id
                    else sandboxes.c.native_key == identity["sandbox_uid"]
                )
                .with_for_update()
            ).first()
            if (
                sandbox_id is not None
                and (
                    native is None
                    or native.native_key != identity["sandbox_uid"]
                    or native.revision != expected_revision
                )
            ) or (
                native is not None
                and (native.deleted_at is not None or native.operation is not None)
            ):
                raise ACPBusy("Sandbox has an unfinished operation or was deleted")
            if policy_lease is not None:
                held = connection.execute(
                    sa.select(leases.c.token, leases.c.expires_at)
                    .where(leases.c.name == policy_lease.name)
                    .with_for_update()
                ).first()
                if (
                    held is None
                    or held.token != str(policy_lease.token)
                    or (
                        held.expires_at.replace(tzinfo=UTC)
                        if held.expires_at.tzinfo is None
                        else held.expires_at
                    )
                    <= self._database_time(connection)
                ):
                    raise ACPBusy("Namespace policy ownership expired; retry admission")
            row = (
                connection.execute(
                    sa.select(acp_bindings).where(
                        acp_bindings.c.sandbox_uid == identity["sandbox_uid"]
                    )
                )
                .mappings()
                .first()
            )
            token = str(uuid4())
            if row is None:
                connection.execute(
                    acp_bindings.insert().values(
                        **identity, active_run_id=run_id, process_token=token
                    )
                )
            else:
                if any(row[key] != value for key, value in identity.items()):
                    raise ACPBindingConflict(
                        "Sandbox is already bound to another conversation or policy"
                    )
                result = connection.execute(
                    acp_bindings.update()
                    .where(
                        acp_bindings.c.sandbox_uid == identity["sandbox_uid"],
                        acp_bindings.c.active_run_id.is_(None),
                    )
                    .values(active_run_id=run_id, process_token=token)
                )
                if result.rowcount != 1:
                    raise ACPBusy(
                        "Sandbox has an active or unconfirmed process; do not resend"
                    )
            return token

    def finish_acp(self, sandbox_uid, run_id, token):
        """Called only after acknowledged remote process-tree drain."""
        with self._transaction(write=True) as connection:
            result = connection.execute(
                acp_bindings.update()
                .where(
                    acp_bindings.c.sandbox_uid == sandbox_uid,
                    acp_bindings.c.active_run_id == run_id,
                    acp_bindings.c.process_token == token,
                )
                .values(active_run_id=None, process_token=None)
            )
            return result.rowcount == 1

    def acp_binding(self, sandbox_uid):
        with self._transaction() as connection:
            row = (
                connection.execute(
                    sa.select(acp_bindings).where(
                        acp_bindings.c.sandbox_uid == sandbox_uid
                    )
                )
                .mappings()
                .first()
            )
            return dict(row) if row else None
