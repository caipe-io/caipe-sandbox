"""Sandbox values shared by management and UI, independent of native APIs."""

from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException

from .controls import SandboxControl, sandbox_control
from .storage import scope_key


@dataclass(frozen=True)
class Sandbox:
    provider: str
    name: str
    scope: str
    uid: str | None
    resource_version: str | None
    owner: str | None
    title: str
    created_at: str | None
    state: str
    message: str
    requested_mode: str
    deleting: bool
    allocation: dict | None
    profile_snapshot: dict | None
    grants: dict[str, str]
    control: SandboxControl | None
    # Only the owning integration interprets this native value.
    reference: Any = field(repr=False, compare=False)
    metadata_error: str | None = None
    record: Any = field(default=None, repr=False, compare=False)
    observed_mode: str | None = None
    configuration_drift: bool = False

    def require_metadata(self):
        if self.metadata_error:
            raise HTTPException(409, self.metadata_error)

    def view(self):
        self.require_metadata()
        snapshot = self.profile_snapshot
        definition = snapshot["definition"] if snapshot else None
        return {
            "id": self.name,
            "portal_id": str(self.record.id) if self.record else None,
            "uid": self.uid,
            "namespace": self.scope,
            "resource_version": self.resource_version,
            "owner": self.owner,
            "namespace_owner": self.record.scope_owner if self.record else self.owner,
            "namespace_key": scope_key(
                self.provider, self.record.provider_instance, self.scope
            )
            if self.record
            else None,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.record.updated_at.isoformat() if self.record else None,
            "state": self.state,
            "message": self.message,
            "allocation": self.allocation,
            "integrations": [],
            "admin_control": sandbox_control(self).model_dump(),
            "profile": {
                "id": snapshot["id"],
                "revision": snapshot["revision"],
                "title": definition["title"],
            }
            if snapshot
            else None,
            "namespace_strategy": snapshot["namespaceStrategy"] if snapshot else None,
            "acp_available": bool(definition and definition.get("acp")),
            "helpers": [
                {
                    "id": h["id"],
                    "title": h["title"],
                    "icon": h["icon"],
                    "status_available": bool(h.get("status")),
                }
                for h in definition["helpers"]
            ]
            if definition
            else [],
            "operation": {
                "kind": self.record.operation.kind,
                "state": self.record.operation.state,
                "error": self.record.operation.error,
                "creation_rejected": self.record.operation.parameters.get(
                    "_creation_rejected"
                )
                is True,
            }
            if self.record and self.record.operation
            else None,
            "configuration_drift": self.configuration_drift,
        }
