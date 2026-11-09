"""Provider-independent metadata records and persistence contract."""

import hashlib
import json
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

if TYPE_CHECKING:
    from .database import DatabaseSettings


class StorageError(Exception):
    """A sanitized persistence failure, safe to report without database details."""


def scope_key(provider, instance, scope):
    return hashlib.sha256(json.dumps([provider, instance, scope]).encode()).hexdigest()


class Conflict(StorageError):
    """A request, revision or native identity conflicts with a saved record."""


class ACPBusy(Conflict):
    """The same private binding still has an active or unconfirmed producer."""


class ACPBindingConflict(Conflict):
    """The environment belongs to a different immutable execution binding."""


class SchemaMismatch(StorageError):
    """The database schema is incompatible with this portal image."""


class SchemaUpgradeRequired(SchemaMismatch):
    """Only known, unapplied revisions separate the database from this image."""


class Lease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=160)
    token: UUID
    expires_at: datetime


class ManifestUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    manifest: dict[str, JsonValue]
    requested_mode: Literal["running", "suspended"] = "running"


class SandboxIntent(ManifestUpdate):
    id: UUID
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,15}$")
    owner: str = Field(min_length=1, max_length=254)
    title: str = Field(default="My sandbox", min_length=1, max_length=80)
    provider: str = Field(min_length=1, max_length=40)
    provider_instance: str = Field(min_length=1, max_length=254)
    profile_snapshot: dict[str, JsonValue] | None = None
    scope: str = Field(min_length=1, max_length=512)
    scope_owner: str = Field(default="", max_length=254)
    resource_usage: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def namespace_owner(cls, values):
        if isinstance(values, dict) and not values.get("scope_owner"):
            return {**values, "scope_owner": values.get("owner", "")}
        return values


class PendingOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["create", "configure", "mode", "delete", "integration"]
    request_id: UUID
    actor: str
    state: Literal["pending", "needs_attention"] = "pending"
    parameters: dict[str, JsonValue] = Field(default_factory=dict)

    @property
    def error(self) -> str | None:
        value = self.parameters.get("_error")
        return value if isinstance(value, str) else None


class NativeBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    key: str = Field(min_length=1, max_length=512)
    reference: dict[str, JsonValue]


class SandboxRecord(SandboxIntent):
    binding: NativeBinding | None = None
    revision: int
    created_at: datetime
    updated_at: datetime
    grants: dict[str, Literal["view", "shell"]] = Field(default_factory=dict)
    control: dict[str, JsonValue] = Field(default_factory=dict)
    operation: PendingOperation | None = None
    deleted_at: datetime | None = None


class PortalControls(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    policy: dict[str, JsonValue]
    revision: int = Field(ge=1)


class MetadataStore(Protocol):
    """Shared guarantees; authorization and provider calls belong to the caller."""

    def register_metadata_integration(
        self, integration_id: str, *, tables: tuple, cleanup_sandbox
    ) -> None:
        """Declare integration-owned tables and an idempotent deletion hook."""
        ...

    def admit_acp(self, identity: dict[str, str], run_id: str) -> str:
        """Bind one conversation; reject active or unconfirmed processes."""
        ...

    def finish_acp(self, sandbox_uid: str, run_id: str, token: str) -> bool:
        """Release only the exact process after acknowledged remote drain."""
        ...

    def acp_binding(self, sandbox_uid: str) -> dict[str, str | None] | None: ...

    def reserve_create(
        self,
        intent: SandboxIntent,
        request_id: UUID,
        *,
        quota: dict[str, str] | None = None,
        retained_usage: dict[str, str] | None = None,
    ) -> SandboxRecord:
        """Reserve once per owner/request; changed retry input raises Conflict."""
        ...

    def get_sandbox(self, sandbox_id: UUID) -> SandboxRecord | None: ...

    def find_creation(self, owner: str, request_id: UUID) -> SandboxRecord | None: ...

    def find_sandbox(
        self,
        name: str,
        *,
        owner: str | None = None,
        scope: str | None = None,
        scope_owner: str | None = None,
    ) -> SandboxRecord | None: ...

    def list_sandboxes(
        self,
        *,
        after: UUID | None = None,
        limit: int = 100,
        owner: str | None = None,
        include_deleted: bool = False,
    ) -> list[SandboxRecord]: ...

    def list_scopes(self) -> list[dict]: ...

    def get_scope_grants(
        self, owner: str, provider: str, provider_instance: str, scope: str
    ) -> dict[str, str]: ...

    def clear_scope_grants(
        self, provider: str, provider_instance: str, scope: str
    ) -> None: ...

    def list_authorized_sandboxes(
        self, principal: str, *, after: UUID | None = None, limit: int = 100
    ) -> list[SandboxRecord]: ...

    def confirm_binding(
        self,
        sandbox_id: UUID,
        binding: NativeBinding,
        *,
        expected_revision: int,
        lease: Lease | None = None,
        operation_id: UUID | None = None,
    ) -> SandboxRecord:
        """Bind one native identity; an identical confirmed binding is retry-safe."""
        ...

    def revise_manifest(
        self,
        sandbox_id: UUID,
        manifest: dict[str, JsonValue],
        *,
        expected_revision: int,
        requested_mode: Literal["running", "suspended"],
    ) -> SandboxRecord: ...

    def set_scope_grants(
        self,
        sandbox_id: UUID,
        members: dict[str, Literal["view", "shell"]],
        *,
        expected_revision: int,
    ) -> SandboxRecord:
        """Replace access to the allocation's owner/provider/instance/scope atomically."""
        ...

    def save_sandbox_control(
        self, sandbox_id: UUID, control: dict[str, JsonValue], *, expected_revision: int
    ) -> SandboxRecord: ...

    def begin_operation(
        self,
        sandbox_id: UUID,
        operation: PendingOperation,
        *,
        expected_revision: int,
        manifest: dict[str, JsonValue],
        requested_mode: Literal["running", "suspended"],
        resource_usage: dict[str, str],
        quota: dict[str, str] | None = None,
        retained_usage: dict[str, str] | None = None,
        replace_operation_id: UUID | None = None,
    ) -> SandboxRecord: ...

    def finish_operation(
        self,
        sandbox_id: UUID,
        *,
        expected_revision: int,
        resource_usage: dict[str, str],
        deleted: bool = False,
        lease: Lease | None = None,
        operation_id: UUID | None = None,
    ) -> SandboxRecord: ...

    def operation_needs_attention(
        self,
        sandbox_id: UUID,
        *,
        expected_revision: int,
        error: str | None = None,
        creation_rejected: bool = False,
        lease: Lease | None = None,
        operation_id: UUID | None = None,
    ) -> SandboxRecord: ...

    def acquire_lease(self, name: str, *, seconds: int) -> Lease | None:
        """Claim with database time; an unexpired claim returns None."""
        ...

    def renew_lease(self, lease: Lease, *, seconds: int) -> bool: ...

    def release_lease(self, lease: Lease) -> None: ...

    def scope_has_sandboxes(
        self, provider: str, provider_instance: str, scope: str
    ) -> bool: ...

    def get_controls(self) -> PortalControls:
        """Read the required record seeded by the explicit schema migration."""
        ...

    def save_controls(
        self, policy: dict[str, JsonValue], *, expected_revision: int
    ) -> PortalControls: ...

    def check_schema(self) -> None: ...

    def migrate(self) -> None: ...

    def close(self) -> None: ...


def open_store(settings: "DatabaseSettings") -> MetadataStore:
    from .sql import SQLMetadataStore

    return SQLMetadataStore(settings)
