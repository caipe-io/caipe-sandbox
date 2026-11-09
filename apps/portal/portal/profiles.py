"""Deployment-owned presets and retained, nonsecret allocation configuration."""

import hashlib
import json
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Literal

from fastapi import HTTPException
from kubernetes.utils.quantity import parse_quantity
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .commands import Command, Identifier, Probe
from .config import runtime_classes, sandbox_security_context
from .integrations import profile_backend, registered
from .integrations.openshell.profile import OpenShell
from .resource_controls import ProfileUI
from .resources import allocation, chosen, policy

PREFIX = "sandbox.caipe.io/"
ICONS = Literal[
    "terminal",
    "code",
    "git",
    "package",
    "folder",
    "file",
    "logs",
    "key",
    "play",
    "refresh",
    "download",
    "upload",
    "settings",
    "info",
    "external",
    "server",
    "database",
    "network",
    "globe",
    "shield",
    "disk",
    "cpu",
    "memory",
    "box",
    "claude",
    "codex",
    "caipe",
    "omnigent",
]
MAX_SNAPSHOT_BYTES = 128 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def definition_revision(value):
    return "sha256:" + hashlib.sha256(encoded(value).encode()).hexdigest()


class Helper(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Identifier
    title: str = Field(min_length=1, max_length=60)
    icon: ICONS = "terminal"
    script: str = Field(min_length=1, max_length=8192)
    status: Probe | None = None

    @model_validator(mode="after")
    def valid_text(self):
        if (
            not self.title.strip()
            or not self.title.isprintable()
            or "\x00" in self.script
        ):
            raise ValueError("Helper title/script contains invalid characters")
        return self

    def public(self):
        return {
            "id": self.id,
            "title": self.title,
            "icon": self.icon,
            "status_available": self.status is not None,
        }


class AgentSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: dict


class Terminal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: Command = Field(default_factory=lambda: ["/bin/sh", "-i"])

    @model_validator(mode="after")
    def executable(self):
        if not self.command[0]:
            raise ValueError("Terminal command executable must not be empty")
        return self


class ACPProcess(BaseModel):
    """A profile-owned executable, never a command supplied by a client."""

    model_config = ConfigDict(extra="forbid")
    command: Command
    workspace_root: str = Field(pattern=r"^/[^\x00\r\n]+$", max_length=1024)

    @model_validator(mode="after")
    def bounded(self):
        if not self.command[0] or "/../" in self.workspace_root + "/":
            raise ValueError(
                "ACP requires an executable and an absolute workspace root"
            )
        return self


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Identifier
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)
    agentSandbox: AgentSandbox | None = None
    openShell: OpenShell | None = None
    envoyEgress: dict | None = None
    terminal: Terminal = Field(default_factory=Terminal)
    helpers: list[Helper] = Field(default_factory=list, max_length=16)
    ui: ProfileUI | None = None
    acp: ACPProcess | None = None

    @model_validator(mode="after")
    def supported(self):
        if not self.title.strip() or not self.title.isprintable():
            raise ValueError("Profile title must be printable")
        backend_keys = ("agentSandbox", *(p.key for p in registered()))
        if sum(getattr(self, key, None) is not None for key in backend_keys) != 1:
            raise ValueError("Choose exactly one of " + " or ".join(backend_keys))
        if self.envoyEgress is not None:
            raise ValueError(
                "envoyEgress is deployment-owned and is not integrated yet"
            )
        if self.acp and self.agentSandbox:
            hosts = (
                self.agentSandbox.spec.get("podTemplate", {})
                .get("spec", {})
                .get("containers", [])
            )
            mounts = next(
                (
                    host.get("volumeMounts", [])
                    for host in hosts
                    if host.get("name") == "host"
                ),
                [],
            )
            if not any(
                mount.get("name") == "home"
                and not mount.get("readOnly")
                and PurePosixPath(self.acp.workspace_root).is_relative_to(
                    PurePosixPath(mount.get("mountPath", "relative"))
                )
                for mount in mounts
            ):
                raise ValueError(
                    "ACP workspace_root must be inside the writable persistent home mount"
                )
        if self.acp and not self.agentSandbox:
            raise ValueError(
                "ACP coding profiles currently require the qualified Agent Sandbox backend; use a direct agentSandbox profile"
            )
        if len({h.id for h in self.helpers}) != len(self.helpers):
            raise ValueError("Helper IDs must be unique within a profile")
        if len(encoded(self.model_dump(exclude_none=True)).encode()) > 48 * 1024:
            raise ValueError("Profile definition exceeds 48 KiB")
        return self

    @property
    def revision(self):
        return definition_revision(self.model_dump(exclude_none=True))

    def public(self, settings=None):
        backend = profile_backend(self)
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "revision": self.revision,
            "helpers": [h.public() for h in self.helpers],
            "backend": backend.key if backend else "agentSandbox",
            "capabilities": backend.profile.capabilities(settings)
            if backend
            else {"resize": True},
        }


class Profiles:
    def __init__(self, settings):
        self.settings = settings
        if len(settings.profiles.encode()) > 512 * 1024:
            raise ValueError("Profile catalog exceeds 512 KiB")
        raw = json.loads(settings.profiles)
        if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
            raise ValueError("Profiles must contain between 1 and 32 definitions")
        values = [Profile.model_validate(item) for item in raw]
        self.items = {p.id: p for p in values}
        if len(self.items) != len(values) or settings.default_profile not in self.items:
            raise ValueError(
                "Profile IDs must be unique and defaultProfile must reference a seeded profile"
            )
        for profile in values:
            backend = profile_backend(profile)
            if backend:
                backend.profile.validate_settings(settings)
            if profile.ui and profile.ui.resources:
                for size in (
                    profile.ui.resources.minimum,
                    profile.ui.resources.maximum,
                ):
                    policy(settings).validate_allocation(size.allocation())
            try:
                self.render(profile, self.size(profile))
            except (KeyError, TypeError, AttributeError, StopIteration) as exc:
                raise ValueError(
                    f"Profile {profile.id} does not match the supported native Sandbox layout"
                ) from exc

    def get(self, profile_id=None, revision=None):
        profile = self.items.get(profile_id or self.settings.default_profile)
        if profile is None:
            raise HTTPException(422, "Select an available profile")
        if revision and revision != profile.revision:
            raise HTTPException(
                409, "Profile revision changed; refresh before creating"
            )
        return profile

    def bounds(self, profile=None):
        limits = policy(self.settings)
        result = {}
        for field in limits.defaults.model_dump():
            key = (
                "cpu_millicores"
                if field.startswith("cpu_")
                else "memory_mib"
                if field.startswith("memory_")
                else "workspace_gib"
            )
            result[field] = getattr(limits, key).model_dump()
        if profile and profile.ui and profile.ui.resources:
            for field, bounds in profile.ui.resources.bounds().items():
                result[field] = {
                    "min": max(result[field]["min"], bounds["min"]),
                    "max": min(result[field]["max"], bounds["max"]),
                }
        backend = profile_backend(profile)
        if backend:
            result.update(backend.profile.resource_bounds(self.settings))
        return result

    def validate_size(self, profile, requested):
        size = chosen(self.settings, requested)
        if profile and profile.ui and profile.ui.resources:
            try:
                profile.ui.resources.validate_allocation(size)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        backend = profile_backend(profile)
        if backend:
            try:
                backend.profile.validate_size(size, self.settings)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        return size

    def size(self, profile, requested=None):
        if requested is not None:
            return self.validate_size(profile, requested)
        if profile.ui and profile.ui.resources:
            return self.validate_size(
                profile, profile.ui.resources.default.allocation()
            )
        backend = profile_backend(profile)
        if backend:
            return self.validate_size(
                profile, backend.profile.size(profile, self.settings)
            )
        spec = deepcopy(profile.agentSandbox.spec)
        host = next(
            (
                c
                for c in spec.get("podTemplate", {})
                .get("spec", {})
                .get("containers", [])
                if c.get("name") == "host"
            ),
            {},
        )
        resources = policy(self.settings).defaults.container_resources()
        for kind in ("requests", "limits"):
            resources[kind].update(host.get("resources", {}).get(kind, {}))
        claims = spec.get("volumeClaimTemplates") or [
            {
                "metadata": {"name": "home"},
                "spec": {
                    "resources": {
                        "requests": {
                            "storage": f"{policy(self.settings).defaults.workspace_gib}Gi"
                        }
                    }
                },
            }
        ]
        if len(claims) != 1 or claims[0].get("metadata", {}).get("name") != "home":
            raise ValueError(
                "The portal currently requires one persistent claim named home"
            )
        claims[0].setdefault("spec", {}).setdefault("resources", {}).setdefault(
            "requests", {}
        ).setdefault("storage", f"{policy(self.settings).defaults.workspace_gib}Gi")
        size = allocation(
            {
                "spec": {
                    "podTemplate": {
                        "spec": {
                            "containers": [{"name": "host", "resources": resources}]
                        }
                    },
                    "volumeClaimTemplates": claims,
                }
            }
        )
        normalized = size.container_resources()
        for kind in ("requests", "limits"):
            for resource in ("cpu", "memory"):
                if parse_quantity(resources[kind][resource]) != parse_quantity(
                    normalized[kind][resource]
                ):
                    raise ValueError(
                        "Portal sizes require whole millicores and whole MiB"
                    )
        storage = claims[0]["spec"]["resources"]["requests"]["storage"]
        if parse_quantity(storage) != size.workspace_gib * 1024**3:
            raise ValueError("Portal disk sizes require whole GiB")
        return chosen(self.settings, size)

    def render(self, profile, size):
        settings = self.settings
        backend = profile_backend(profile)
        if backend:
            return backend.profile.render(profile, size, settings)
        spec = deepcopy(profile.agentSandbox.spec)
        pod = spec.setdefault("podTemplate", {}).setdefault("spec", {})
        containers = pod.get("containers", [])
        if (
            len(containers) != 1
            or containers[0].get("name") != "host"
            or not containers[0].get("image")
        ):
            raise ValueError(
                "The portal currently requires one workload container named host with an image"
            )
        for metadata in [
            spec["podTemplate"].get("metadata", {}),
            *(c.get("metadata", {}) for c in spec.get("volumeClaimTemplates", [])),
        ]:
            if set(metadata) & {
                "namespace",
                "uid",
                "ownerReferences",
                "resourceVersion",
                "finalizers",
                "generateName",
            }:
                raise ValueError(
                    "Native workload identity/ownership metadata is platform-controlled"
                )
            for entries in (
                metadata.get("labels", {}),
                metadata.get("annotations", {}),
            ):
                if any(
                    key.startswith(PREFIX) or key == "app.kubernetes.io/name"
                    for key in entries
                ):
                    raise ValueError(
                        "Portal workload metadata keys are platform-controlled"
                    )
        if profile.ui and profile.ui.resources:
            supplied = containers[0].get("resources", {})
            if any(
                resource in supplied.get(kind, {})
                for kind in ("requests", "limits")
                for resource in ("cpu", "memory")
            ):
                raise ValueError(
                    "Define editable CPU/memory defaults only in ui.resources.default"
                )
            for entry in spec.get("volumeClaimTemplates", []):
                if "storage" in entry.get("spec", {}).get("resources", {}).get(
                    "requests", {}
                ):
                    raise ValueError(
                        "Define editable storage defaults only in ui.resources.default"
                    )
        pod.setdefault("runtimeClassName", settings.runtime_class)
        runtime = pod["runtimeClassName"]
        if ("" if runtime is None else runtime) not in runtime_classes(settings):
            raise ValueError(
                "Profile runtimeClassName must be an approved runtime class"
            )
        # Retain an explicit default in saved intent; Kubernetes omits the null field.
        if runtime == "":
            pod["runtimeClassName"] = None
        protected = {
            "serviceAccountName": settings.runner_service_account,
            "automountServiceAccountToken": False,
            "hostNetwork": False,
            "hostPID": False,
            "hostIPC": False,
            "securityContext": sandbox_security_context(settings),
        }
        for key, value in protected.items():
            if key in pod and pod[key] != value:
                raise ValueError(
                    f"Profile conflicts with platform-controlled pod field {key}"
                )
            pod[key] = value
        if "imagePullSecrets" in pod:
            raise ValueError("imagePullSecrets are supplied by the platform")
        if (
            spec.get("operatingMode", "Running") != "Running"
            or spec.get("shutdownPolicy", "Retain") != "Retain"
        ):
            raise ValueError(
                "Initial operatingMode and shutdownPolicy are platform-controlled"
            )
        spec.update(operatingMode="Running", shutdownPolicy="Retain")
        claims = spec.setdefault(
            "volumeClaimTemplates",
            [
                {
                    "metadata": {"name": "home"},
                    "spec": {"accessModes": ["ReadWriteOnce"]},
                }
            ],
        )
        if len(claims) != 1 or claims[0].get("metadata", {}).get("name") != "home":
            raise ValueError(
                "The portal currently requires one persistent claim named home"
            )
        claim = claims[0].setdefault("spec", {})
        if (
            "storageClassName" in claim
            and claim["storageClassName"] != settings.storage_class
        ):
            raise ValueError("storageClassName is platform-controlled")
        if settings.storage_class:
            claim["storageClassName"] = settings.storage_class
        else:
            claim.pop("storageClassName", None)
        claim.setdefault("resources", {}).setdefault("requests", {})["storage"] = (
            f"{size.workspace_gib}Gi"
        )
        for container in [*containers, *pod.get("initContainers", [])]:
            if container.get("restartPolicy"):
                raise ValueError(
                    "Sidecar init containers are not supported by portal resource accounting"
                )
            security = container.setdefault("securityContext", {})
            for key in ("runAsUser", "runAsGroup"):
                if (
                    key in security
                    and security[key] != protected["securityContext"][key]
                ):
                    raise ValueError(
                        f"Profile conflicts with platform-controlled container field {key}"
                    )
            for key, value in {
                "allowPrivilegeEscalation": False,
                "privileged": False,
                "capabilities": {"drop": ["ALL"]},
            }.items():
                if key in security and security[key] != value:
                    raise ValueError(
                        f"Profile conflicts with platform-controlled container field {key}"
                    )
                security[key] = value
            supplied = container.get("resources", {})
            budget = size.container_resources()
            for kind in ("requests", "limits"):
                for resource, value in supplied.get(kind, {}).items():
                    if resource not in budget[kind]:
                        raise ValueError(
                            "The portal resource editor does not support extended resources"
                        )
                    if resource == "ephemeral-storage" and parse_quantity(
                        value
                    ) != parse_quantity(budget[kind][resource]):
                        raise ValueError(
                            "Ephemeral storage budgets are platform-controlled"
                        )
            if container is containers[0] or not supplied:
                container["resources"] = budget
            else:
                effective = deepcopy(budget)
                for kind in ("requests", "limits"):
                    effective[kind].update(supplied.get(kind, {}))
                    for resource in ("cpu", "memory"):
                        value = parse_quantity(effective[kind][resource])
                        if value <= 0 or value > parse_quantity(budget[kind][resource]):
                            raise ValueError(
                                "Init container resources must fit the selected sandbox allocation"
                            )
                for resource in ("cpu", "memory"):
                    if parse_quantity(effective["requests"][resource]) > parse_quantity(
                        effective["limits"][resource]
                    ):
                        raise ValueError("Init container requests must fit its limits")
                container["resources"] = effective
        for volume in pod.get("volumes", []):
            if "hostPath" in volume or any(
                "serviceAccountToken" in source
                for source in volume.get("projected", {}).get("sources", [])
            ):
                raise ValueError(
                    "Host paths and service-account token projections are not supported"
                )
        return spec


def applied(sandbox):
    sandbox.require_metadata()
    return sandbox.profile_snapshot


def helper(cr, helper_id):
    snapshot = applied(cr)
    if snapshot:
        for entry in snapshot["definition"]["helpers"]:
            if entry["id"] == helper_id:
                return Helper.model_validate(entry)
    raise HTTPException(404, "Helper is not defined in this sandbox's applied profile")
