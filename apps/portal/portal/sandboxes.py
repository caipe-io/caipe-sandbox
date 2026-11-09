"""Database-owned intent and authorization; native lifecycle stays in integrations."""

import hashlib
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

from fastapi import HTTPException
from kubernetes.utils.quantity import parse_quantity
from pydantic import ValidationError

from .controls import (
    Controls,
    SandboxControl,
    creation_blocked,
    disabled,
    notice,
    now,
    sandbox_control,
)
from .coordination import claim
from .integrations import Integrations, prepare_creation, sandbox_ui
from .integrations.caipe.storage import OWNED_TABLES as CAIPE_TABLES
from .integrations.caipe.storage import cleanup_sandbox as cleanup_caipe_sandbox
from .integrations.errors import CreationRejected
from .inventory import Sandbox
from .namespace_access import NamespaceAccess
from .namespaces import namespace_config
from .profiles import MAX_SNAPSHOT_BYTES, Profile, Profiles, applied, encoded, helper
from .storage import Conflict, PendingOperation, SandboxIntent, StorageError, open_store
from .storage.database import DatabaseSettings


def view(sandbox):
    return sandbox.view()


def shares(sandbox):
    return sandbox.grants


class Store:
    def __init__(
        self,
        settings,
        custom=None,
        core=None,
        namespaces=None,
        *,
        integrations=None,
        controls=None,
        metadata=None,
    ):
        self.settings = settings
        self.profiles = Profiles(settings)
        self.metadata = metadata or open_store(
            DatabaseSettings(
                url=settings.database_url, expected_backend=settings.database_backend
            )
        )
        # Disabled integrations retain their data and process fences.
        if callable(
            getattr(self.metadata, "register_metadata_integration", None)
        ) and json.loads(settings.acp_connections):
            self.metadata.register_metadata_integration(
                "caipe", tables=CAIPE_TABLES, cleanup_sandbox=cleanup_caipe_sandbox
            )
        self.owns_metadata = metadata is None
        self.controls = controls or Controls(self.metadata)
        self.integrations = integrations or Integrations(self, custom, core, namespaces)
        self.namespace_access = NamespaceAccess(self)
        self.observers = ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="sandbox-status"
        )

    def close(self):
        self.observers.shutdown(wait=True, cancel_futures=True)
        try:
            self.integrations.close()
        finally:
            if self.owns_metadata:
                self.metadata.close()

    def _backend(self, record):
        backend = self.integrations.items.get(record.provider)
        if backend is None or backend.provider_instance != record.provider_instance:
            raise HTTPException(
                409, "Saved sandbox provider is unavailable or has changed"
            )
        return backend

    def _pages(self, principal=None):
        after = None
        while True:
            page = (
                self.metadata.list_authorized_sandboxes(
                    principal, after=after, limit=200
                )
                if principal is not None
                else self.metadata.list_sandboxes(after=after, limit=200)
            )
            yield from page
            if len(page) < 200:
                return
            after = page[-1].id

    def _record(self, name, *, owner=None, scope=None):
        try:
            identity = uuid.UUID(name)
        except ValueError:
            identity = None
        record = (
            self.metadata.get_sandbox(identity)
            if identity
            else self.metadata.find_sandbox(name, owner=owner, scope=scope)
        )
        if record and (
            (owner is not None and record.owner != owner)
            or (scope is not None and record.scope != scope)
            or record.deleted_at
        ):
            record = None
        if record is None:
            raise HTTPException(404, "Sandbox not found")
        return record

    def _observe(self, record):
        snapshot = record.profile_snapshot
        try:
            allocation = self._backend(record).allocation(
                record.manifest, snapshot=snapshot
            )
        except HTTPException:
            allocation = None
        try:
            control = SandboxControl.model_validate(record.control)
        except ValidationError:
            control = SandboxControl(
                disabled=True,
                reason="Saved sandbox controls are invalid; administrator repair is required",
            )
        sandbox = Sandbox(
            provider=record.provider,
            name=record.name,
            scope=record.scope,
            uid=record.binding.key if record.binding else str(record.id),
            resource_version=str(record.revision),
            owner=record.owner,
            title=record.title,
            created_at=record.created_at.isoformat(),
            state="Provisioning",
            message="Creating this micro VM",
            requested_mode=record.requested_mode.title(),
            deleting=bool(record.operation and record.operation.kind == "delete"),
            allocation=allocation.model_dump() if allocation is not None else None,
            profile_snapshot=snapshot,
            grants=record.grants,
            control=control,
            reference=None,
            record=record,
        )
        if record.deleted_at:
            return replace(sandbox, state="Deleted", message="Sandbox deleted")
        if record.binding:
            try:
                observed = self._backend(record).observe(record.binding)
                sandbox = replace(
                    sandbox,
                    reference=observed.reference,
                    allocation=sandbox.allocation or observed.allocation,
                    state=observed.state,
                    message=observed.message,
                    observed_mode=observed.requested_mode,
                    deleting=observed.deleting or sandbox.deleting,
                )
                if not record.operation and self._backend(record).drift(
                    record.manifest, observed.reference
                ):
                    sandbox = replace(
                        sandbox,
                        configuration_drift=True,
                        message="Native configuration differs from the saved configuration; review it before making changes",
                    )
            except (HTTPException, OSError) as exc:
                status = getattr(exc, "status_code", None)
                if status == 404 and sandbox.deleting:
                    try:
                        deleted = self.metadata.finish_operation(
                            record.id,
                            expected_revision=record.revision,
                            resource_usage={},
                            deleted=True,
                        )
                    except (StorageError, OSError):
                        logging.getLogger(__name__).warning(
                            "integration_cleanup_pending provider=%s sandbox=%s",
                            record.provider,
                            record.name,
                        )
                        return replace(
                            sandbox,
                            state="Deleting",
                            message="Sandbox cleanup is pending. Retry after any active or unconfirmed CAIPE process is reconciled.",
                        )
                    from .telemetry import event

                    event(
                        "operation_completed",
                        category="audit",
                        action="delete",
                        operation_id=str(record.operation.request_id),
                        requested_by=record.operation.actor,
                        sandbox_id=str(record.id),
                        provider=record.provider,
                        namespace=record.scope,
                        native_id=record.binding.key,
                        outcome="completed",
                    )

                    return self._observe(deleted)
                sandbox = replace(
                    sandbox,
                    state="Unknown",
                    reference=None,
                    observed_mode=None,
                    message="Native allocation is missing; administrator investigation is required"
                    if status == 404
                    else "Provider unavailable or identity changed; execution is blocked",
                )
        if sandbox.deleting:
            sandbox = replace(
                sandbox,
                state="Deleting",
                message="Deletion requested; retry to confirm completion"
                if record.operation
                else "The provider is deleting this allocation; its saved configuration is retained",
            )
        elif record.operation and record.binding:
            sandbox = replace(
                sandbox,
                message="Checking whether the previous action completed",
            )
        if record.operation and record.operation.state == "needs_attention":
            sandbox = replace(
                sandbox,
                state="Error" if record.binding is None else sandbox.state,
                message=record.operation.error
                or "The portal could not confirm whether the previous action completed. "
                "Retry the action to check its result safely.",
            )
        return sandbox

    def _observed(self, records):
        return [
            s
            for s in self.observers.map(self._observe, records)
            if s.state != "Deleted"
        ]

    def get(self, name, owner):
        sandbox = self._observe(self._record(name, owner=owner))
        if sandbox.state == "Deleted":
            raise HTTPException(404, "Sandbox not found")
        return sandbox

    def list(self, owner):
        return self._observed(r for r in self._pages(owner) if r.owner == owner)

    def admin_list(self):
        return self._observed(self._pages())

    def admin_get(self, name, namespace):
        sandbox = self._observe(self._record(name, scope=namespace))
        if sandbox.state == "Deleted":
            raise HTTPException(404, "Sandbox not found")
        return sandbox

    def shared_get(self, name, actor, owner, shell=False):
        try:
            uuid.UUID(name)
            record = self._record(name)
        except ValueError:
            record = self.metadata.find_sandbox(
                name, owner=owner
            ) or self.metadata.find_sandbox(name, scope_owner=owner)
        if record is None or owner not in {record.owner, record.scope_owner}:
            raise HTTPException(404, "Sandbox not found")
        if actor not in {record.owner, record.scope_owner} and record.grants.get(
            actor
        ) not in ({"shell"} if shell else {"view", "shell"}):
            raise HTTPException(404, "Sandbox not found")
        return self._observe(record)

    def shared_list(self, actor, owner):
        return self._observed(
            r
            for r in self._pages(actor)
            if r.scope_owner == owner or (actor == owner and r.owner == owner)
        )

    def status_view(self, sandbox):
        row = view(sandbox)
        row["control_panels"] = [
            item.descriptor
            for item in sandbox_ui(sandbox.record).values()
            if callable(getattr(item, "read", None))
        ]
        snapshot = applied(sandbox)
        profile = Profile.model_validate(snapshot["definition"]) if snapshot else None
        row["resource_bounds"] = self.profiles.bounds(profile)
        if sandbox.reference is None:
            try:
                row = self.integrations.for_sandbox(sandbox).status(None, row)
            except (HTTPException, OSError):
                pass
            row.update(state=sandbox.state, message=sandbox.message)
            return self.integrations.status(sandbox, row)
        try:
            row = self._backend(sandbox.record).status(sandbox.reference, row)
        except (HTTPException, OSError):
            row.update(
                state="Unknown",
                message="Provider status unavailable; execution is blocked",
            )
        if sandbox.record.operation or sandbox.configuration_drift:
            row["message"] = sandbox.message
        return self.integrations.status(sandbox, row)

    def status_views(self, sandboxes):
        return list(self.observers.map(self.status_view, sandboxes))

    def configuration(self, sandbox):
        record = sandbox.record
        snapshot = applied(sandbox)
        result = {
            "creation": snapshot,
            "profile": snapshot["definition"] if snapshot else None,
            "namespace": sandbox.scope,
            "desired": record.manifest,
            "requested_mode": record.requested_mode,
            "observed": {},
            "configuration_drift": sandbox.configuration_drift,
            "profile_spec": None,
            "uid": sandbox.uid,
            "revision": record.revision,
            "can_sync": (
                callable(
                    getattr(
                        self.integrations.items.get(record.provider), "reconcile", None
                    )
                )
                and sandbox.reference is not None
                and not sandbox.deleting
                and not record.operation
            ),
        }
        try:
            return self._backend(record).configuration(sandbox.reference, result)
        except (HTTPException, OSError):
            pass
        return {**result, "observation_error": sandbox.message}

    def check_access(self, sandbox):
        sandbox.require_metadata()
        reason = disabled(sandbox, self.controls.read()[0])
        if reason:
            raise HTTPException(403, reason)
        return sandbox

    def _require_acp_idle(self, sandbox):
        snapshot = applied(sandbox)
        if snapshot and snapshot["definition"].get("acp") and sandbox.uid:
            binding = self.metadata.acp_binding(sandbox.uid)
            if binding and binding["active_run_id"]:
                raise HTTPException(
                    409,
                    "Stop the CAIPE run before changing this sandbox. An unconfirmed process requires operator reconciliation; deleting the sandbox ends its environment but does not retry the run.",
                )

    def _native(self, sandbox):
        if sandbox.reference is None or sandbox.deleting:
            raise HTTPException(409, sandbox.message)
        return sandbox.reference

    def helper(self, name, owner, helper_id):
        return helper(self.check_access(self.get(name, owner)), helper_id)

    def sharing(self, name, owner, members, revision=None):
        sandbox = self.check_access(self.shared_get(name, owner, owner))
        snapshot = applied(sandbox)
        if (
            snapshot
            and snapshot["definition"].get("acp")
            and "shell" in members.values()
        ):
            raise HTTPException(
                409, "Private ACP sandboxes cannot grant shared shell access"
            )
        if sandbox.record.scope_owner != owner:
            raise HTTPException(403, "Only the namespace owner can change sharing")
        if owner in members:
            raise HTTPException(422, "The owner already has access")
        record = self.metadata.set_scope_grants(
            sandbox.record.id,
            members,
            expected_revision=revision or sandbox.record.revision,
        )
        from .telemetry import event

        event(
            "namespace_sharing_changed",
            category="audit",
            actor=owner,
            sandbox_id=str(record.id),
            namespace=record.scope,
            provider=record.provider,
            revision=record.revision,
            members=members,
            outcome="saved",
        )
        return self._observe(record)

    def _usage(self, backend, manifest):
        return {k: str(v) for k, v in backend.usage(manifest).items()}

    def _quota(self, owner):
        configured = json.loads(self.settings.namespace_policy).get("quota", {})
        limits = {key: parse_quantity(value) for key, value in configured.items()}
        maximum = self.settings.max_sandboxes_per_user
        if maximum:
            key = "count/sandboxes.agents.x-k8s.io"
            limits[key] = min(limits.get(key, maximum), maximum)
        if not limits:
            return {}
        uids = {r.binding.key for r in self._pages(owner) if r.binding}
        return {
            "quota": {key: str(value) for key, value in limits.items()},
            "retained_usage": {
                key: str(value)
                for key, value in self.integrations.retained_usage(owner, uids).items()
            },
        }

    def creation_request(self, owner, request_id):
        record = self.metadata.find_creation(owner, request_id)
        if record and record.deleted_at:
            raise HTTPException(
                409,
                "This creation request belongs to a deleted sandbox; start a new request",
            )
        return self._observe(record) if record else None

    def create(
        self,
        owner,
        title="My sandbox",
        request_id=None,
        size=None,
        profile_id=None,
        profile_revision=None,
        namespace_strategy=None,
        namespace=None,
        integration_configuration=None,
    ):
        integration_configuration = integration_configuration or {}
        reason = creation_blocked(owner, self.controls.read()[0])
        if reason:
            raise HTTPException(403, reason)
        request_id = uuid.UUID(str(request_id)) if request_id else uuid.uuid4()
        existing = self.creation_request(owner, request_id)
        if existing:
            snapshot = applied(existing) or {}
            if (
                existing.title != title
                or integration_configuration
                != snapshot.get("integration_configuration", {})
                or (size is not None and size.model_dump() != snapshot["resources"])
                or (profile_id is not None and profile_id != snapshot["id"])
                or (namespace is not None and namespace != existing.scope)
                or (
                    namespace_strategy is not None
                    and namespace_strategy != snapshot["namespaceStrategy"]
                )
                or (
                    profile_revision is not None
                    and profile_revision != snapshot["revision"]
                )
            ):
                raise HTTPException(
                    409,
                    "Creation request was already used for different sandbox settings",
                )
            return (
                self._perform(existing.record)
                if existing.record.operation
                and existing.record.operation.kind == "create"
                else existing
            )
        profile = self.profiles.get(profile_id, profile_revision)
        if profile.acp:
            if namespace is not None or namespace_strategy not in {None, "perSandbox"}:
                raise HTTPException(
                    422, "ACP coding profiles require a new private namespace"
                )
            namespace_strategy = "perSandbox"
        size = self.profiles.size(profile, size)
        backend = self.integrations.for_profile(profile)
        scope_owner, namespace_uid = owner, None
        if namespace is not None:
            if namespace_strategy not in {None, "perUser"}:
                raise HTTPException(
                    422, "Choose a new namespace or an existing namespace"
                )
            namespace_strategy = "perUser"
            scope_owner, namespace_uid = self.namespace_access.target(
                owner, backend, namespace
            )
        placement = namespace_config(self.settings).select(namespace_strategy)
        draft = backend.prepare(
            owner,
            title,
            request_id,
            size,
            profile,
            namespace_strategy=placement.strategy,
            namespace=namespace,
            namespace_owner=scope_owner if namespace is not None else None,
            namespace_uid=namespace_uid,
        )
        manifest = backend.manifest(draft.reference)
        manifest = prepare_creation(profile, manifest, integration_configuration)
        snapshot = deepcopy(draft.profile_snapshot)
        if integration_configuration:
            snapshot["integration_configuration"] = deepcopy(integration_configuration)
            if len(encoded(snapshot).encode()) > MAX_SNAPSHOT_BYTES:
                raise HTTPException(
                    422, "Resolved creation settings exceed the 128 KiB snapshot limit"
                )
        if not self.namespace_access.allowed(
            owner,
            draft.provider,
            backend.provider_instance,
            draft.scope,
            scope_owner,
            self.controls.read()[0],
        ):
            raise HTTPException(403, "You cannot create micro VMs in this namespace")
        record = self.metadata.reserve_create(
            SandboxIntent(
                id=uuid.uuid5(uuid.NAMESPACE_URL, f"{owner}/{request_id}"),
                name=draft.name,
                scope=draft.scope,
                scope_owner=scope_owner,
                owner=owner,
                title=title,
                provider=draft.provider,
                provider_instance=backend.provider_instance,
                manifest=manifest,
                profile_snapshot=snapshot,
                resource_usage=self._usage(backend, manifest),
            ),
            request_id,
            **self._quota(owner),
        )
        return self._perform(record)

    def _begin(self, sandbox, kind, manifest, mode, actor, *, parameters=None):
        record = sandbox.record
        backend = self._backend(record)
        usage = (
            self._usage(backend, manifest)
            if kind == "configure"
            else record.resource_usage
        )
        # Keep the larger reservation until an uncertain resize is confirmed.
        reservation = {
            key: str(
                max(
                    Decimal(usage.get(key, "0")),
                    Decimal(record.resource_usage.get(key, "0")),
                )
            )
            for key in usage.keys() | record.resource_usage.keys()
        }
        return self.metadata.begin_operation(
            record.id,
            PendingOperation(
                kind=kind,
                request_id=uuid.uuid4(),
                actor=actor,
                parameters=parameters or {},
            ),
            expected_revision=record.revision,
            manifest=manifest,
            requested_mode=mode.lower(),
            resource_usage=reservation,
            **(
                {"replace_operation_id": record.operation.request_id}
                if kind == "integration" and record.operation
                else {}
            ),
            **(self._quota(record.owner) if kind == "configure" else {}),
        )

    @contextmanager
    def scope_operation(self, backend, scope, *, required=True):
        identity = json.dumps(
            [backend.key, backend.provider_instance, scope], separators=(",", ":")
        )
        key = "scope/" + hashlib.sha256(identity.encode()).hexdigest()
        with claim(
            self.metadata,
            key,
            seconds=self.settings.operation_lease_seconds,
            required=required,
        ) as owner:
            yield owner

    def _perform(self, record):
        from .telemetry import event, operation

        with operation(record):
            result = self._perform_attempt(record)
            if record.operation:
                event(
                    "operation_attempt_finished",
                    outcome="pending" if result.record.operation else "completed",
                    native_id=result.record.binding.key
                    if result.record.binding
                    else "",
                )
            return result

    def _perform_attempt(self, record):
        if record.operation is None:
            return self._observe(record)
        with claim(
            self.metadata,
            f"sandbox/{record.id}",
            seconds=self.settings.operation_lease_seconds,
        ) as owner:
            current = self.metadata.get_sandbox(record.id)
            if current is None:
                raise Conflict("Sandbox no longer exists")
            if current.operation is None:
                return self._observe(current)
            if current.operation.request_id != record.operation.request_id:
                raise Conflict("Sandbox operation changed; refresh and retry")
            return self._perform_owned(current, owner)

    def _check_operation_access(self, record):
        current = self.metadata.get_sandbox(record.id)
        if (
            current is None
            or current.operation is None
            or current.operation.request_id != record.operation.request_id
        ):
            raise Conflict("Sandbox operation changed; refresh and retry")
        if record.operation.kind == "delete" or (
            record.operation.kind == "mode" and record.requested_mode == "suspended"
        ):
            return
        policy, _ = self.controls.read()
        try:
            local = SandboxControl.model_validate(current.control)
        except ValidationError:
            raise StorageError("Saved sandbox controls are invalid") from None
        reason = disabled(SimpleNamespace(owner=current.owner, control=local), policy)
        if not reason and record.operation.kind == "create":
            reason = creation_blocked(current.owner, policy)
            if not reason and not self.namespace_access.allowed(
                current.owner,
                current.provider,
                current.provider_instance,
                current.scope,
                current.scope_owner,
                policy,
            ):
                reason = "You cannot create micro VMs in this namespace"
        if reason:
            raise HTTPException(403, reason)

    def _perform_owned(self, record, owner):
        operation = record.operation
        if operation is None:
            return self._observe(record)
        backend = self._backend(record)
        fence = {"lease": owner.lease, "operation_id": operation.request_id}
        try:
            owner.check()
            self._check_operation_access(record)
            if operation.kind == "create":
                native = backend.find_created(record.manifest, operation.request_id)
                if native is None:
                    if operation.parameters.get("_creation_rejected") is True:
                        raise Conflict(
                            "The runtime rejected this creation. Cancel creation in the micro VM's actions, then create a new micro VM."
                        )
                    owner.check()
                    self._check_operation_access(record)
                    native = backend.create(record.manifest, operation.request_id)
                backend.validate_created(
                    native, record.manifest, snapshot=record.profile_snapshot
                )
                record = self.metadata.confirm_binding(
                    record.id,
                    backend.binding(native),
                    expected_revision=record.revision,
                    **fence,
                )
            else:
                try:
                    observed = backend.observe(record.binding)
                except HTTPException as exc:
                    status = exc.status_code
                    if status != 404 or operation.kind != "delete":
                        raise
                    record = self.metadata.finish_operation(
                        record.id,
                        expected_revision=record.revision,
                        **fence,
                        resource_usage={},
                        deleted=True,
                    )
                    return self._observe(record)
                owner.check()
                self._check_operation_access(record)
                if operation.kind == "configure":
                    size = backend.allocation(record.manifest)
                    backend.configure(observed.reference, size)
                elif operation.kind == "mode":
                    backend.mode(
                        observed.reference,
                        record.requested_mode.title(),
                        request_id=operation.request_id,
                    )
                elif operation.kind == "delete":
                    backend.delete(observed.reference, request_id=operation.request_id)
                    return self._observe(self.metadata.get_sandbox(record.id))
                elif operation.kind == "integration":
                    controller = sandbox_ui(record).get(
                        operation.parameters.get("integration")
                    )
                    if controller is None:
                        raise HTTPException(
                            409,
                            "Integration is unavailable; restore it before retrying",
                        )
                    controller.apply(
                        backend,
                        observed.reference,
                        record.manifest,
                        operation.parameters["configuration"],
                        operation.request_id,
                    )
                record = self.metadata.finish_operation(
                    record.id,
                    expected_revision=record.revision,
                    **fence,
                    resource_usage=self._usage(backend, record.manifest)
                    if operation.kind == "configure"
                    else record.resource_usage,
                )
        except (HTTPException, OSError) as exc:
            error = (
                exc.detail
                if isinstance(exc, HTTPException) and isinstance(exc.detail, str)
                else "The portal lost contact with the runtime. The previous action may "
                "have completed. Retry the action to check its result safely."
            )
            self.metadata.operation_needs_attention(
                record.id,
                expected_revision=record.revision,
                error=error[:8192],
                creation_rejected=isinstance(exc, CreationRejected),
                **fence,
            )
            raise
        return self._observe(record)

    def retry(self, name, owner):
        sandbox = self._observe(self._record(name, owner=owner))
        if sandbox.state == "Deleted":
            return sandbox
        self.check_access(sandbox)
        if sandbox.record.operation and sandbox.record.operation.kind == "create":
            reason = creation_blocked(owner, self.controls.read()[0])
            if reason:
                raise HTTPException(403, reason)
        return self._perform(sandbox.record)

    def admin_retry(self, name, namespace, uid):
        sandbox = self._observe(self._record(name, scope=namespace))
        if sandbox.uid != uid:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        if sandbox.state == "Deleted":
            return sandbox
        record = sandbox.record
        if record.operation and record.operation.kind not in {"delete", "mode"}:
            self.check_access(sandbox)
        if (
            record.operation
            and record.operation.kind == "mode"
            and record.requested_mode == "running"
        ):
            self.check_access(sandbox)
        return self._perform(record)

    def configure(self, name, owner, size):
        sandbox = self.check_access(self.get(name, owner))
        self._require_acp_idle(sandbox)
        snapshot = applied(sandbox)
        profile = Profile.model_validate(snapshot["definition"]) if snapshot else None
        size = self.profiles.validate_size(profile, size)
        backend = self._backend(sandbox.record)
        planned = backend.plan_configure(
            self._native(sandbox), size, manifest=sandbox.record.manifest
        )
        return self._perform(
            self._begin(
                sandbox,
                "configure",
                backend.manifest(planned),
                sandbox.requested_mode,
                owner,
            )
        )

    def _panel_backend(self, sandbox, panel):
        backend = self._backend(sandbox.record)
        controller = sandbox_ui(sandbox.record).get(panel)
        if controller is None or not callable(getattr(controller, "read", None)):
            raise HTTPException(404, "Integration control panel is unavailable")
        return backend, controller

    def integration_panel(self, sandbox, panel):
        backend, controller = self._panel_backend(sandbox, panel)
        native = (
            self._native(sandbox)
            if getattr(controller, "requires_native", True)
            else None
        )
        result = controller.read(backend, native, sandbox.record)
        blocked = disabled(sandbox, self.controls.read()[0])
        if blocked:
            result = {**result, "editable": False, "reason": blocked}
        return {
            **result,
            "uid": sandbox.uid,
            "revision": sandbox.record.revision,
            "admin_only": getattr(controller, "admin_only", False),
        }

    def update_integration(self, sandbox, panel, update, actor, *, admin=False):
        backend, controller = self._panel_backend(sandbox, panel)
        if getattr(controller, "admin_only", False) and not admin:
            raise HTTPException(403, "Only platform admins can edit these policies")
        if actor != sandbox.owner and not admin:
            raise HTTPException(
                403,
                "Only the micro VM creator or platform admins can edit integrations",
            )
        self.check_access(sandbox)
        self._require_acp_idle(sandbox)
        record = sandbox.record
        if sandbox.uid != update.uid:
            raise Conflict("Sandbox configuration changed; refresh before applying")
        if callable(getattr(controller, "update", None)):
            return controller.update(backend, sandbox, update, actor)
        if record.revision != update.revision:
            raise Conflict("Sandbox configuration changed; refresh before applying")
        if not all(
            callable(getattr(controller, method, None)) for method in ("plan", "apply")
        ):
            raise HTTPException(405, "This integration control panel is read-only")
        manifest, parameters = controller.plan(
            backend,
            self._native(sandbox),
            record,
            update.configuration,
            update.native_revision,
        )
        logging.getLogger(__name__).info(
            "integration_update actor=%s sandbox=%s panel=%s", actor, record.id, panel
        )
        return self._perform(
            self._begin(
                sandbox,
                "integration",
                manifest,
                sandbox.requested_mode,
                actor,
                parameters={"integration": panel, "configuration": parameters},
            )
        )

    def mode(self, name, owner, mode):
        sandbox = self.check_access(self.get(name, owner))
        self._require_acp_idle(sandbox)
        self._native(sandbox)
        record = sandbox.record
        if record.operation:
            if (
                record.operation.kind == "mode"
                and record.requested_mode == mode.lower()
            ):
                return self._perform(record)
            raise Conflict(
                "This micro VM has an unfinished action. Use its Retry button before starting another action."
            )
        manifest = self._backend(record).plan_mode(record.manifest, mode)
        return self._perform(self._begin(sandbox, "mode", manifest, mode, owner))

    def _cancel_creation(self, sandbox):
        record = sandbox.record
        with claim(
            self.metadata,
            f"sandbox/{record.id}",
            seconds=self.settings.operation_lease_seconds,
        ) as owner:
            current = self.metadata.get_sandbox(record.id)
            if current is None or current.deleted_at:
                return {"status": "deleted"}
            if (
                current.binding is not None
                or current.operation is None
                or current.operation.kind != "create"
                or current.operation.state != "needs_attention"
                or current.operation.request_id != record.operation.request_id
            ):
                raise Conflict("Creation changed; refresh before cancelling it")
            backend = self._backend(current)
            fence = {"lease": owner.lease, "operation_id": current.operation.request_id}
            with self.scope_operation(backend, current.scope) as scope_owner:
                owner.check()
                scope_owner.check()
                native = backend.find_created(
                    current.manifest, current.operation.request_id
                )
                if native is not None:
                    current = self.metadata.confirm_binding(
                        current.id,
                        backend.binding(native),
                        expected_revision=current.revision,
                        **fence,
                    )
                else:
                    backend.verify_creation_absent(
                        current.manifest,
                        rejected=current.operation.parameters.get("_creation_rejected")
                        is True,
                    )
                    owner.check()
                    scope_owner.check()
                    self.metadata.finish_operation(
                        current.id,
                        expected_revision=current.revision,
                        resource_usage={},
                        deleted=True,
                        **fence,
                    )
                    logging.getLogger(__name__).info(
                        "creation_cancelled sandbox=%s request=%s",
                        current.id,
                        current.operation.request_id,
                    )
                    return {"status": "deleted"}
        return self._delete(self._observe(current))

    def _delete(self, sandbox):
        record = sandbox.record
        if record.operation:
            if record.operation.kind == "delete":
                self._perform(record)
                return {"status": "deleting"}
            if (
                record.operation.kind == "create"
                and record.operation.state == "needs_attention"
                and record.binding is None
            ):
                return self._cancel_creation(sandbox)
            raise Conflict(
                "This micro VM has an unfinished action. Use its Retry button before starting another action."
            )
        self._native(sandbox)
        record = self._begin(
            sandbox, "delete", record.manifest, sandbox.requested_mode, record.owner
        )
        self._perform(record)
        return {"status": "deleting"}

    def delete(self, name, owner, expected_uid=None):
        sandbox = self.get(name, owner)
        if expected_uid is None:
            self.check_access(sandbox)
        if expected_uid and sandbox.uid != expected_uid:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        return self._delete(sandbox)

    def admin_delete(self, name, namespace, uid):
        sandbox = self.admin_get(name, namespace)
        if sandbox.uid != uid:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        return self._delete(sandbox)

    def admin_control(self, name, namespace, uid, update, actor):
        sandbox = self.admin_get(name, namespace)
        if sandbox.uid != uid or sandbox.resource_version != update.resource_version:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        values = sandbox_control(sandbox).model_dump()
        for key in ("disabled", "reason"):
            if getattr(update, key) is not None:
                values[key] = getattr(update, key)
        if update.notice is not None:
            values["notice"] = notice(update.notice, actor)
        control = SandboxControl(**{**values, "updated_by": actor, "updated_at": now()})
        blocked = disabled(replace(sandbox, control=control), self.controls.read()[0])
        if update.operating_mode == "Running" and blocked:
            raise HTTPException(409, "Re-enable sandbox access before resuming it")
        record = self.metadata.save_sandbox_control(
            sandbox.record.id,
            control.model_dump(mode="json"),
            expected_revision=sandbox.record.revision,
        )
        mode = "Suspended" if blocked else update.operating_mode
        sandbox = self._observe(record)
        if (
            mode
            and not record.operation
            and record.binding
            and sandbox.observed_mode != mode
        ):
            manifest = self._backend(record).plan_mode(record.manifest, mode)
            return self._perform(self._begin(sandbox, "mode", manifest, mode, actor))
        return sandbox

    def reconcile_controls(self):
        policy, _ = self.controls.read()
        failures = []
        seen = set()
        for sandbox in self.admin_list():
            key = (
                sandbox.record.provider,
                sandbox.record.provider_instance,
                sandbox.scope,
            )
            if key not in seen:
                seen.add(key)
                for controller in sandbox_ui(sandbox.record).values():
                    reconcile = getattr(controller, "reconcile_scope", None)
                    if not callable(reconcile):
                        continue
                    try:
                        reconcile(self._backend(sandbox.record), sandbox.record)
                    except (HTTPException, StorageError):
                        logging.getLogger(__name__).warning(
                            "scope_controls_reconcile_failed integration=%s scope=%s",
                            controller.descriptor["id"],
                            sandbox.scope,
                        )
                        failures.append(
                            {
                                "namespace": sandbox.scope,
                                "error": "Integration policies need administrator attention",
                            }
                        )
            if (
                not disabled(sandbox, policy)
                or sandbox.observed_mode == "Suspended"
                or sandbox.deleting
            ):
                continue
            try:
                record = sandbox.record
                if record.operation:
                    if (
                        record.operation.kind == "mode"
                        and record.requested_mode == "suspended"
                    ):
                        self._perform(record)
                        continue
                    raise Conflict("Resolve the pending operation before suspending")
                manifest = self._backend(record).plan_mode(record.manifest, "Suspended")
                self._perform(
                    self._begin(sandbox, "mode", manifest, "Suspended", "administrator")
                )
            except (HTTPException, Conflict):
                logging.getLogger(__name__).warning(
                    "admin_suspension_failed sandbox=%s", sandbox.name
                )
                failures.append(
                    {
                        "name": sandbox.name,
                        "namespace": sandbox.scope,
                        "error": "Sandbox suspension needs administrator attention",
                    }
                )
        return failures

    def _sync(self, record, *, uid=None, revision=None, required=True, stopping=None):
        with claim(
            self.metadata,
            f"sandbox/{record.id}",
            seconds=self.settings.operation_lease_seconds,
            required=required,
        ) as guard:
            if guard is None:
                return False
            current = self.metadata.get_sandbox(record.id)
            if current is None or current.deleted_at or current.operation:
                raise Conflict(
                    "Resolve the pending operation before syncing configuration"
                )
            if not current.binding:
                raise Conflict(
                    "Sandbox identity is not confirmed; retry its pending operation"
                )
            if (uid is not None and uid != current.binding.key) or (
                revision is not None and revision != current.revision
            ):
                raise Conflict(
                    "Sandbox configuration changed; refresh and review it before syncing"
                )
            backend = self._backend(current)
            reconcile = getattr(backend, "reconcile", None)
            if not callable(reconcile):
                raise HTTPException(
                    409, "This integration does not support configuration sync"
                )

            def check():
                if stopping and stopping():
                    raise Conflict("Portal is draining; configuration sync stopped")
                guard.check()
                latest = self.metadata.get_sandbox(current.id)
                if latest != current:
                    raise Conflict(
                        "Sandbox configuration changed while syncing; refresh and retry"
                    )
                try:
                    control = SandboxControl.model_validate(current.control)
                except ValidationError:
                    raise StorageError("Saved sandbox controls are invalid") from None
                sandbox = SimpleNamespace(owner=current.owner, control=control)
                if (
                    disabled(sandbox, self.controls.read()[0])
                    and current.requested_mode != "suspended"
                ):
                    raise HTTPException(
                        403,
                        "Sandbox is disabled; suspension must be applied before syncing",
                    )

            check()
            observed = backend.observe(current.binding)
            changed = reconcile(current.manifest, observed.reference, check=check)
            if changed:
                logging.getLogger(__name__).info(
                    "configuration_synced provider=%s sandbox=%s",
                    current.provider,
                    current.name,
                    extra={
                        "event_fields": {
                            "sandbox_id": str(current.id),
                            "namespace": current.scope,
                            "provider": current.provider,
                            "category": "audit",
                            "action": "configuration_sync",
                            "outcome": "applied",
                        }
                    },
                )
            return changed

    def sync(self, name, owner, uid, revision):
        record = self._record(name, owner=owner)
        self._sync(record, uid=uid, revision=revision)
        return self.get(name, owner)

    def admin_sync(self, name, namespace, uid, revision):
        record = self._record(name, scope=namespace)
        self._sync(record, uid=uid, revision=revision)
        return self.admin_get(name, namespace)

    def reconcile_resources(self, *, stopping=None):
        failures = []
        with claim(
            self.metadata,
            "maintenance/configuration-sync",
            seconds=self.settings.operation_lease_seconds,
            required=False,
        ) as guard:
            if guard is None:
                return failures
            for record in self._pages():
                if stopping and stopping():
                    break
                guard.check()
                try:
                    if (
                        record.operation
                        or not record.binding
                        or not callable(
                            getattr(self._backend(record), "reconcile", None)
                        )
                    ):
                        continue
                    self._sync(record, required=False, stopping=stopping)
                except (HTTPException, StorageError):
                    if stopping and stopping():
                        break
                    logging.getLogger(__name__).warning(
                        "configuration_sync_failed provider=%s sandbox=%s",
                        record.provider,
                        record.name,
                        extra={
                            "event_fields": {
                                "sandbox_id": str(record.id),
                                "namespace": record.scope,
                                "provider": record.provider,
                                "action": "configuration_sync",
                                "outcome": "error",
                            }
                        },
                    )
                    failures.append({"name": record.name, "namespace": record.scope})
        return failures

    def cleanup_namespaces(self):
        with claim(
            self.metadata,
            "maintenance/namespace-cleanup",
            seconds=self.settings.operation_lease_seconds,
            required=False,
        ) as owner:
            if owner is None:
                return
            for record in self._pages():
                if record.operation and record.operation.kind == "delete":
                    owner.check()
                    self._observe(record)
            owner.check()
            self.integrations.cleanup_namespaces()

    def execution(self, name, owner, sharing_owner=None):
        sandbox = self.shared_get(name, owner, sharing_owner or owner, shell=True)
        self.check_access(sandbox)
        self._native(sandbox)
        if sandbox.record.operation:
            raise HTTPException(
                409, "Resolve the pending sandbox operation before opening a shell"
            )
        return self.integrations.execution(sandbox)

    def admin_execution(self, name, namespace):
        sandbox = self.admin_get(name, namespace)
        self._native(sandbox)
        return self.integrations.execution(sandbox, admin=True)
