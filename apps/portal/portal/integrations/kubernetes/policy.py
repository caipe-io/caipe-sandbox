"""Namespace connection policies; workload lifecycle remains with its provider."""

import hashlib
import json
import logging
from copy import deepcopy

from fastapi import HTTPException
from kubernetes.client import ApiException
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ...controls import NamespaceControl, now
from ...coordination import claim
from ...storage import Conflict, StorageError, scope_key

NAME = "portal-connections"
APP, LABEL, PREFIX = (
    "agent-sandbox-portal",
    "app.kubernetes.io/name",
    "sandbox.caipe.io/",
)
descriptor = {
    "id": "kubernetes",
    "title": "Kubernetes",
    "icon": "kubernetes",
    "category": "security",
    "admin_only": True,
}
admin_only = True
requires_native = False


class PolicyState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace_uid: str = Field(min_length=1)
    spec: dict[str, JsonValue]
    updated_by: str
    updated_at: str


def supports_sandbox(record):
    from .. import agent_sandbox, registered

    providers = (agent_sandbox, *registered())
    return any(
        module.Integration.key == record.provider
        and module.Integration.__dict__.get("namespace_network_selector") is not None
        for module in providers
    )


def supports_profile(profile):
    return False


def context(backend, record):
    namespaces = backend.catalog.namespaces
    try:
        namespace = backend.namespace_info(record.scope_owner, record.scope)
    except ApiException:
        raise HTTPException(
            503,
            "Kubernetes namespace information is unavailable; refresh before retrying",
        ) from None
    if not namespace:
        raise HTTPException(409, "Namespace is no longer available")
    key = scope_key(record.provider, record.provider_instance, record.scope)
    return namespaces, namespace["uid"], key


def policies(namespaces, namespace):
    result, continuation = [], None
    while True:
        try:
            page = namespaces.networking.list_namespaced_network_policy(
                namespace, limit=200, _continue=continuation, _request_timeout=15
            )
        except ApiException:
            raise HTTPException(
                503,
                "Kubernetes network policies could not be read; ask an administrator to check namespace access",
            ) from None
        result.extend(namespaces.data(item) for item in page.items)
        continuation = page.metadata._continue
        if not continuation:
            return result


def body(backend, record, namespace_uid, spec):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": NAME,
            "namespace": record.scope,
            "labels": {
                LABEL: APP,
                PREFIX + "instance": backend.store.settings.namespace_access_role,
            },
            "annotations": {PREFIX + "namespace-uid": namespace_uid},
            "ownerReferences": [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "name": record.scope,
                    "uid": namespace_uid,
                }
            ],
        },
        "spec": spec,
    }


def owned(policy, expected):
    if not policy:
        return
    meta, wanted = policy["metadata"], expected["metadata"]
    if (
        any(meta.get("labels", {}).get(k) != v for k, v in wanted["labels"].items())
        or meta.get("annotations", {}).get(PREFIX + "namespace-uid")
        != wanted["annotations"][PREFIX + "namespace-uid"]
    ):
        raise HTTPException(409, "The connection policy belongs to another controller")


def native_spec(value):
    return {
        "podSelector": value.get("podSelector", {}),
        "policyTypes": value.get("policyTypes", ["Egress"]),
        "egress": value.get("egress") or [],
    }


def read(backend, cr, record):
    namespaces, namespace_uid, key = context(backend, record)
    controls, _ = backend.store.controls.read()
    saved = controls.namespaces.get(key, NamespaceControl()).network_policy
    if saved:
        try:
            saved = PolicyState.model_validate(saved).model_dump(mode="json")
        except ValueError:
            raise StorageError("Saved namespace network policy is invalid") from None
    if saved and saved["namespace_uid"] != namespace_uid:
        raise HTTPException(
            409, "Namespace identity changed; administrator investigation is required"
        )
    current = policies(namespaces, record.scope)
    connection = next(
        (item for item in current if item["metadata"]["name"] == NAME), None
    )
    spec = (
        saved["spec"]
        if saved
        else {
            "podSelector": deepcopy(backend.namespace_network_selector),
            "policyTypes": ["Egress"],
            "egress": [],
        }
    )
    expected = body(backend, record, namespace_uid, spec)
    owned(connection, expected)
    drift = bool(saved and (not connection or native_spec(connection["spec"]) != spec))
    revision = hashlib.sha256(
        json.dumps([namespace_uid, saved, connection], sort_keys=True).encode()
    ).hexdigest()
    return {
        "state": "pending" if drift else "configured",
        "editable": bool(record.binding),
        "reason": ""
        if record.binding
        else "Wait for micro VM creation to be confirmed before editing namespace policies.",
        "native_revision": revision,
        "namespace": record.scope,
        "namespace_uid": namespace_uid,
        "scope_count": sum(
            item["count"]
            for item in backend.store.metadata.list_scopes()
            if item["scope"] == record.scope
            and item["provider_instance"] == record.provider_instance
            and item["provider"] == record.provider
        ),
        "policy": expected,
        "policies": current,
        "drift": drift,
        "updated_by": saved["updated_by"] if saved else None,
        "detail": "Policy objects are present; network-plugin enforcement is not verified by this view.",
    }


def validate(backend, record, current, configuration):
    if set(configuration) != {"policy"}:
        raise HTTPException(422, "Provide the dedicated Kubernetes connection policy")
    policy = configuration["policy"]
    if (
        not isinstance(policy, dict)
        or set(policy) != {"apiVersion", "kind", "metadata", "spec"}
        or any(
            policy.get(k) != current["policy"][k]
            for k in ("apiVersion", "kind", "metadata")
        )
    ):
        raise HTTPException(
            422, "Policy identity and namespace are managed by the platform"
        )
    spec = policy["spec"]
    if (
        not isinstance(spec, dict)
        or set(spec) != {"podSelector", "policyTypes", "egress"}
        or spec["podSelector"] != backend.namespace_network_selector
        or spec["policyTypes"] != ["Egress"]
        or not isinstance(spec["egress"], list)
    ):
        raise HTTPException(
            422,
            "Edit outbound connection rules only; workload selection is platform-controlled",
        )
    try:
        oversized = len(json.dumps(policy, allow_nan=False).encode()) > 65536
    except ValueError:
        raise HTTPException(
            422, "Policy must contain valid finite JSON values"
        ) from None
    if oversized or len(spec["egress"]) > 100:
        raise HTTPException(422, "Connection policy exceeds 64 KiB or 100 rules")
    return deepcopy(policy)


def write(namespaces, namespace, candidate, existing, *, dry_run=False):
    candidate = deepcopy(candidate)
    options = {"_request_timeout": 15, "field_validation": "Strict"}
    if dry_run:
        options["dry_run"] = "All"
    try:
        if existing:
            candidate["metadata"].update(
                {k: existing["metadata"][k] for k in ("uid", "resourceVersion")}
            )
            return namespaces.data(
                namespaces.networking.replace_namespaced_network_policy(
                    NAME, namespace, candidate, **options
                )
            )
        return namespaces.data(
            namespaces.networking.create_namespaced_network_policy(
                namespace, candidate, **options
            )
        )
    except ApiException as exc:
        if exc.status in {400, 422}:
            try:
                detail = json.loads(exc.body or "{}").get(
                    "message", "Native validation failed"
                )
            except (ValueError, AttributeError):
                detail = "Native validation failed"
            raise HTTPException(
                422, "Kubernetes rejected the connection policy: " + str(detail)[:2000]
            ) from None
        if exc.status == 409:
            raise Conflict(
                "Namespace connection policy changed; refresh and review again"
            ) from None
        if exc.status == 403:
            raise HTTPException(
                503,
                "The portal lacks permission to manage namespace policies. Ask an administrator to check the chart RBAC and admission settings.",
            ) from None
        raise HTTPException(
            503,
            "Kubernetes did not confirm the connection policy. Refresh to inspect saved and current configuration before retrying.",
        ) from None


def update(backend, sandbox, request, actor):
    store, record = backend.store, sandbox.record
    if (record.profile_snapshot or {}).get("definition", {}).get("acp"):
        raise Conflict("Network policy changes are disabled for ACP coding sandboxes")
    with claim(
        store.metadata,
        f"namespace-network/{scope_key(record.provider, record.provider_instance, record.scope)}",
        seconds=store.settings.operation_lease_seconds,
    ) as guard:
        current = read(backend, None, record)
        if current["native_revision"] != request.native_revision:
            raise Conflict(
                "Namespace policies changed; refresh and review before applying"
            )
        candidate = validate(backend, record, current, request.configuration)
        namespaces, namespace_uid, key = context(backend, record)
        existing = next(
            (p for p in current["policies"] if p["metadata"]["name"] == NAME), None
        )
        normalized = write(namespaces, record.scope, candidate, existing, dry_run=True)
        guard.check()
        controls, revision = store.controls.read()
        entry = controls.namespaces.get(key, NamespaceControl())
        state = PolicyState(
            namespace_uid=namespace_uid,
            spec=native_spec(normalized["spec"]),
            updated_by=actor,
            updated_at=now(),
        )
        entries = {
            **controls.namespaces,
            key: entry.model_copy(
                update={"network_policy": state.model_dump(mode="json")}
            ),
        }
        if len(entries) > 1000:
            raise HTTPException(422, "Too many namespace control entries")
        saved = controls.model_copy(
            update={"namespaces": entries, "updated_by": actor, "updated_at": now()}
        )
        store.metadata.save_controls(
            saved.model_dump(mode="json"), expected_revision=int(revision)
        )
        logging.getLogger(__name__).info(
            "namespace_network_saved actor=%s namespace=%s",
            actor,
            record.scope,
            extra={
                "event_fields": {
                    "category": "audit",
                    "actor": actor,
                    "sandbox_id": str(record.id),
                    "namespace": record.scope,
                    "provider": record.provider,
                    "revision": int(revision) + 1,
                    "policy_sha256": hashlib.sha256(
                        json.dumps(state.spec, sort_keys=True).encode()
                    ).hexdigest(),
                    "outcome": "saved",
                }
            },
        )
        guard.check()
        if context(backend, record)[1] != namespace_uid:
            raise Conflict("Namespace identity changed while applying the policy")
        write(
            namespaces,
            record.scope,
            body(backend, record, namespace_uid, state.spec),
            existing,
        )
    return sandbox


def reconcile_scope(backend, record):
    store = backend.store
    key = scope_key(record.provider, record.provider_instance, record.scope)
    if (
        not store.controls.read()[0]
        .namespaces.get(key, NamespaceControl())
        .network_policy
    ):
        return
    with claim(
        store.metadata,
        f"namespace-network/{key}",
        seconds=store.settings.operation_lease_seconds,
        required=False,
    ) as guard:
        if guard is None:
            return
        current = read(backend, None, record)
        if not current["drift"]:
            return
        namespaces, _, _ = context(backend, record)
        existing = next(
            (p for p in current["policies"] if p["metadata"]["name"] == NAME), None
        )
        guard.check()
        write(namespaces, record.scope, current["policy"], existing)
