"""Native lifecycle and resource accounting for Kubernetes Agent Sandbox."""

import json
import time
from copy import deepcopy

from fastapi import HTTPException
from kubernetes.client import ApiException
from kubernetes.utils.quantity import parse_quantity

from .execution import target
from .inventory import Inventory, describe
from .metadata import binding, contains, manifest, native_errors, verify_binding
from .status import enrich, suspended

GROUP, VERSION, PLURAL = "agents.x-k8s.io", "v1beta1", "sandboxes"
PREFIX = "sandbox.caipe.io/"
BOOTSTRAP_RETRY_DELAYS = (0.1, 0.2, 0.4, 0.8, 1.6)


class Integration:
    key = "agentSandbox"
    namespace_network_selector = {}

    def __init__(self, store, *, catalog=None):
        self.store = store
        self.catalog = catalog or Inventory(store)
        self.provider_instance = store.settings.namespace_access_role

    binding = staticmethod(binding)
    manifest = staticmethod(manifest)

    @staticmethod
    def allocation(reference, *, snapshot=None):
        from ...resources import allocation

        return allocation(reference)

    @native_errors
    def observe(self, saved):
        ref = saved.reference
        cr = self.catalog.custom.get_namespaced_custom_object(
            GROUP, VERSION, ref["namespace"], PLURAL, ref["name"], _request_timeout=15
        )
        verify_binding(cr, saved)
        if self.catalog.backend_for(cr) is not self:
            raise HTTPException(409, "Sandbox provider identity changed")
        return self.describe(cr)

    @native_errors
    def find_created(self, manifest, request_id):
        meta = manifest["metadata"]
        try:
            cr = self.catalog.custom.get_namespaced_custom_object(
                GROUP,
                VERSION,
                meta["namespace"],
                PLURAL,
                meta["name"],
                _request_timeout=15,
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        annotations = cr["metadata"].get("annotations", {})
        if (
            cr["metadata"].get("labels", {}).get("app.kubernetes.io/name")
            != "agent-sandbox-portal"
            or self.catalog.namespaces.get(
                meta["annotations"].get(
                    PREFIX + "namespace-owner", meta["annotations"][PREFIX + "owner"]
                ),
                meta["namespace"],
            )
            != meta["namespace"]
            or annotations.get(PREFIX + "request-id") != str(request_id)
            or annotations.get(PREFIX + "owner")
            != meta["annotations"][PREFIX + "owner"]
            or self.catalog.backend_for(cr) is not self
        ):
            raise HTTPException(
                409, "Creation request conflicts with an existing allocation"
            )
        return cr

    @native_errors
    def create(self, body, request_id):
        with self.store.scope_operation(self, body["metadata"]["namespace"]) as owner:
            owner.check()
            self.ensure(body)
            owner.check()
            return self._create(body, request_id, owner.check)


    @native_errors
    def verify_creation_absent(self, manifest, *, rejected):
        if not rejected:
            raise HTTPException(
                409,
                "The original creation outcome is still unknown; an administrator must verify runtime cleanup before cancellation",
            )
        meta = manifest["metadata"]
        claims = [
            claim["metadata"]["name"] + "-" + meta["name"]
            for claim in manifest["spec"].get("volumeClaimTemplates", [])
        ]
        self.catalog.verify_creation_absent(meta["namespace"], meta["name"], claims)

    def _create(self, body, request_id, check):
        meta = body["metadata"]
        # A freshly created RoleBinding can take a short time to become visible
        # to the API server's authorizer. Retry only its exact RBAC denial on
        # the side-effect-free dry run; validation/admission errors stay final.
        for attempt in range(len(BOOTSTRAP_RETRY_DELAYS) + 1):
            check()
            try:
                self.catalog.custom.create_namespaced_custom_object(
                    GROUP,
                    VERSION,
                    meta["namespace"],
                    PLURAL,
                    body,
                    dry_run="All",
                    field_validation="Strict",
                )
                break
            except ApiException as exc:
                if not self._bootstrap_authorization_denied(exc, meta["namespace"]):
                    raise
                if attempt == len(BOOTSTRAP_RETRY_DELAYS):
                    raise HTTPException(
                        503,
                        "Sandbox service permission is unavailable. Retry or contact an administrator.",
                    ) from None
                time.sleep(BOOTSTRAP_RETRY_DELAYS[attempt])
        # Recheck the scope lease immediately before the only mutating call.
        check()
        try:
            return self.catalog.custom.create_namespaced_custom_object(
                GROUP,
                VERSION,
                meta["namespace"],
                PLURAL,
                body,
                field_validation="Strict",
            )
        except ApiException as exc:
            if exc.status != 409:
                raise
            existing = self.catalog.custom.get_namespaced_custom_object(
                GROUP,
                VERSION,
                meta["namespace"],
                PLURAL,
                meta["name"],
                _request_timeout=15,
            )
            annotations = existing["metadata"].get("annotations", {})
            if (
                existing["metadata"].get("labels", {}).get("app.kubernetes.io/name")
                != meta["labels"]["app.kubernetes.io/name"]
                or annotations.get(PREFIX + "owner")
                != meta["annotations"][PREFIX + "owner"]
                or annotations.get(PREFIX + "request-id") != str(request_id)
                or self.catalog.backend_for(existing) is not self
            ):
                raise HTTPException(
                    409,
                    "Creation request was already used for different sandbox settings",
                ) from None
            return existing

    def _bootstrap_authorization_denied(self, exc, namespace):
        if exc.status != 403:
            return False
        try:
            body = json.loads(exc.body or "")
        except (TypeError, ValueError):
            return False
        if not isinstance(body, dict) or body.get("reason") != "Forbidden":
            return False
        settings = self.store.settings
        expected = (
            f'{PLURAL}.{GROUP} is forbidden: User "system:serviceaccount:'
            f'{settings.portal_namespace}:{settings.portal_service_account}" '
            f'cannot create resource "{PLURAL}" in API group "{GROUP}" '
            f'in the namespace "{namespace}"'
        )
        message = body.get("message")
        return isinstance(message, str) and message.startswith(expected)

    def plan_configure(self, cr, size, *, manifest=None):
        from ...resources import allocation

        current = allocation(cr)
        if size.workspace_gib != current.workspace_gib:
            raise HTTPException(
                409,
                "Disk size is set at creation; this controller's volume-claim template is immutable",
            )
        if size == current:
            return self._resize(manifest or cr, size)
        if not suspended(cr):
            raise HTTPException(
                409, "Suspend the sandbox completely before changing CPU or memory"
            )
        meta = cr["metadata"]
        try:
            self.catalog.core.read_namespaced_pod(meta["name"], meta["namespace"])
        except ApiException as exc:
            if exc.status != 404:
                raise
        else:
            raise HTTPException(
                409, "Wait for the sandbox Pod to terminate before changing resources"
            )
        return self._resize(manifest or cr, size)

    def _resize(self, cr, size):
        containers = deepcopy(cr["spec"]["podTemplate"]["spec"]["containers"])
        host = next(c for c in containers if c["name"] == "host")
        for kind, values in size.container_resources().items():
            for resource in ("cpu", "memory"):
                host["resources"][kind][resource] = values[resource]
        candidate = deepcopy(cr)
        candidate["spec"]["podTemplate"]["spec"]["containers"] = containers
        return candidate

    @native_errors
    def configure(self, cr, size):
        candidate = self.plan_configure(cr, size)
        meta = cr["metadata"]
        containers = candidate["spec"]["podTemplate"]["spec"]["containers"]
        return self.catalog.custom.patch_namespaced_custom_object(
            GROUP,
            VERSION,
            meta["namespace"],
            PLURAL,
            meta["name"],
            {
                "metadata": {
                    "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
                "spec": {"podTemplate": {"spec": {"containers": containers}}},
            },
        )

    def drift(self, saved, reference):
        return not contains(reference["spec"], saved["spec"]) or any(
            not contains(
                reference["metadata"].get(key, {}), saved["metadata"].get(key, {})
            )
            for key in ("labels", "annotations")
        )

    @native_errors
    def reconcile(self, saved, reference, *, check):
        if reference["metadata"].get("deletionTimestamp"):
            raise HTTPException(
                409, "Sandbox is being deleted; configuration cannot be synced"
            )
        if not self.drift(saved, reference):
            return False
        meta = reference["metadata"]
        check()
        if saved["spec"].get("operatingMode", "Running") == "Running":
            self.ensure(saved)
            check()
        self.catalog.custom.patch_namespaced_custom_object(
            GROUP,
            VERSION,
            meta["namespace"],
            PLURAL,
            meta["name"],
            {
                "metadata": {
                    "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                    **{
                        key: deepcopy(saved["metadata"].get(key, {}))
                        for key in ("labels", "annotations")
                    },
                },
                "spec": deepcopy(saved["spec"]),
            },
            _request_timeout=15,
        )
        return True

    def validate_created(self, native, saved, *, snapshot=None):
        if self.allocation(native) != self.allocation(saved):
            raise HTTPException(
                409,
                "Native allocation differs from the reserved resources; administrator investigation is required",
            )

    def plan_mode(self, saved, mode):
        candidate = deepcopy(saved)
        candidate["spec"].update(operatingMode=mode, shutdownTime=None)
        return candidate

    @native_errors
    def mode(self, cr, mode, *, request_id=None):
        meta = cr["metadata"]
        if mode == "Running":
            self.catalog.namespaces.ensure(
                meta["annotations"].get(
                    PREFIX + "namespace-owner", meta["annotations"][PREFIX + "owner"]
                ),
                meta["name"],
                namespace=meta["namespace"],
                strategy=meta["annotations"].get(PREFIX + "namespace-strategy"),
                expected_uid=meta["annotations"].get(PREFIX + "namespace-uid"),
            )
        # Resume the retained native spec without today's profile defaults.
        return self.catalog.custom.patch_namespaced_custom_object(
            GROUP,
            VERSION,
            meta["namespace"],
            PLURAL,
            meta["name"],
            {
                "metadata": {
                    "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
                "spec": {"operatingMode": mode, "shutdownTime": None},
            },
        )

    @native_errors
    def delete(self, cr, *, request_id=None):
        meta = cr["metadata"]
        result = {"status": "deleting"}
        owner = meta.get("annotations", {}).get(
            PREFIX + "namespace-owner",
            meta.get("annotations", {}).get(PREFIX + "owner"),
        )
        if (
            owner
            and meta.get("labels", {}).get("app.kubernetes.io/name")
            == "agent-sandbox-portal"
            and json.loads(self.store.settings.namespace_policy).get("deleteWhenEmpty")
        ):
            try:
                if (
                    self.catalog.namespaces.get(owner, meta["namespace"])
                    == meta["namespace"]
                ):
                    result["namespace_cleanup"] = "pending"
            except HTTPException:
                pass
        self.catalog.custom.delete_namespaced_custom_object(
            GROUP,
            VERSION,
            meta["namespace"],
            PLURAL,
            meta["name"],
            body={
                "propagationPolicy": "Foreground",
                "preconditions": {
                    "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
            },
        )
        return result

    def usage(self, cr):
        usage = {
            "pods": 1,
            "count/sandboxes.agents.x-k8s.io": 1,
            "requests.storage": 0,
            "persistentvolumeclaims": 0,
        }
        pod = cr["spec"]["podTemplate"]["spec"]
        for kind in ("requests", "limits"):
            for resource in ("cpu", "memory"):
                main = sum(
                    parse_quantity(
                        c.get("resources", {}).get(kind, {}).get(resource, "0")
                    )
                    for c in pod["containers"]
                )
                init = max(
                    (
                        parse_quantity(
                            c.get("resources", {}).get(kind, {}).get(resource, "0")
                        )
                        for c in pod.get("initContainers", [])
                    ),
                    default=0,
                )
                usage[kind + "." + resource] = max(main, init)
        for claim in cr["spec"].get("volumeClaimTemplates", []):
            usage["requests.storage"] += parse_quantity(
                claim["spec"]["resources"]["requests"]["storage"]
            )
            usage["persistentvolumeclaims"] += 1
        return usage

    @native_errors
    def status(self, cr, row):
        if cr is None:
            return row
        return enrich(self.catalog.core, cr, row)

    @native_errors
    def configuration(self, cr, result):
        return self.catalog.configuration(cr, result)

    def execution(self, cr, *, admin=False):
        return target(cr, self.catalog.core, admin=admin)

    def cleanup_namespace(self, namespace):
        pass

    def close(self):
        pass

    def describe(self, cr):
        return describe(cr, self.key, generic=True)

    def prepare(
        self,
        owner,
        title,
        request_id,
        size,
        profile,
        *,
        namespace_strategy=None,
        namespace=None,
        namespace_owner=None,
        namespace_uid=None,
    ):
        return self.catalog.prepare(
            owner,
            title,
            request_id,
            size,
            profile,
            self,
            namespace_strategy=namespace_strategy,
            namespace=namespace,
            namespace_owner=namespace_owner,
            namespace_uid=namespace_uid,
        )

    @native_errors
    def namespace_info(self, owner, name):
        return self.catalog.namespace_info(owner, name, self)

    @native_errors
    def ensure(self, reference):
        return self.catalog.ensure(reference)

    @native_errors
    def retained_usage(self, owner, uids):
        return self.catalog.retained_usage(owner, uids)

    def cleanup(self):
        self.catalog.cleanup_namespaces()
