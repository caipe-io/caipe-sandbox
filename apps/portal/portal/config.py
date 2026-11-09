"""Operator-owned configuration; users cannot supply pod templates."""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    TypeAdapter,
)

from .resources import DEFAULT_POLICY
from .resources import policy as resource_policy


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default="sqlite:////var/lib/portal/metadata.db", repr=False
    )
    database_backend: str = ""
    operation_lease_seconds: int = 120
    terminal_io_workers: int = 32
    reconcile_interval_seconds: int = 30
    max_sandboxes_per_user: int = 0
    drain_file: str = "/tmp/portal-drain"
    drain_seconds: int = 180
    drain_propagation_seconds: int = 10
    origin: str = "http://127.0.0.1:4193"
    header_links: str = (
        '[{"title":"Docs","url":"https://upgraded-adventure-w96874e.pages.github.io/"}]'
    )
    auth_omnigent_url: str = ""
    namespace_prefix: str = "agent"
    namespace: str = '{"strategy":"perSandbox","allowedStrategies":["perSandbox","perUser"],"labels":{},"annotations":{}}'
    profiles: str = "[]"
    profiles_file: str = ""
    default_profile: str = "engineering"
    openshell_endpoint: str = ""
    openshell_gateway_id: str = ""
    openshell_gateway_service_account: str = ""
    openshell_runner_service_account: str = ""
    openshell_storage_gib: int = 20
    openshell_storage_mode: str = "gateway"
    openshell_gateway_pod_selector: str = '{"app.kubernetes.io/name":"openshell"}'
    openshell_namespace_label: str = "sandbox.caipe.io/openshell"
    openshell_supervisor_resources: str = "{}"
    portal_namespace: str = "sandbox-system"
    portal_service_account: str = "agent-sandbox-portal"
    namespace_access_role: str = "agent-sandbox-portal-access"
    namespace_policy: str = '{"podSecurityVersion":"latest","baselineNetworkPolicy":false,"quota":{},"extraEgress":[],"deleteWhenEmpty":true}'
    runtime_class: str = ""
    allowed_runtime_classes: str = "null"
    runner_service_account: str = "sandbox-runner"
    runner_image_pull_secrets: str = "[]"
    sandbox_security_context: str = (
        '{"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000}'
    )
    storage_class: str = ""
    resource_policy: str = json.dumps(DEFAULT_POLICY)
    auth_mode: str = "oidc"
    admin_emails: str = "[]"
    oidc_policy: str = "{}"
    oidc_client_secret: str = ""
    session_secret: str = ""
    caipe_policy: str = "{}"
    caipe_verification_key: str = field(default="", repr=False)
    terminal_url: str = ""
    base_path: str = "/agent-sandbox-portal"
    acp_connections: str = "{}"
    acp_service_token: str = field(default="", repr=False)

    @classmethod
    def from_env(cls):
        fields = {}
        for name, default in cls().__dict__.items():
            value = os.environ.get("PORTAL_" + name.upper(), default)
            fields[name] = int(value) if type(default) is int else value
        if fields["profiles_file"]:
            from pathlib import Path

            source = Path(fields["profiles_file"])
            if source.stat().st_size > 512 * 1024:
                raise ValueError("Profile catalog exceeds 512 KiB")
            if fields["profiles"] != "[]":
                raise ValueError("Use either PORTAL_PROFILES or PORTAL_PROFILES_FILE")
            fields["profiles"] = source.read_text(encoding="utf-8")
        settings = cls(**fields)
        if settings.terminal_io_workers < 1:
            raise ValueError("PORTAL_TERMINAL_IO_WORKERS must be a positive integer")
        if settings.reconcile_interval_seconds < 0:
            raise ValueError("PORTAL_RECONCILE_INTERVAL_SECONDS must be nonnegative")
        if settings.max_sandboxes_per_user < 0:
            raise ValueError("PORTAL_MAX_SANDBOXES_PER_USER must be nonnegative")
        if (
            not 0 <= settings.drain_seconds <= 600
            or not 0 <= settings.drain_propagation_seconds <= 60
        ):
            raise ValueError("Invalid portal drain budget")
        if not 30 <= settings.operation_lease_seconds <= 600:
            raise ValueError(
                "PORTAL_OPERATION_LEASE_SECONDS must be between 30 and 600"
            )
        from .storage.database import DatabaseSettings

        DatabaseSettings(
            url=settings.database_url, expected_backend=settings.database_backend
        ).parsed_url()
        urls = [settings.origin]
        if settings.auth_mode == "omnigent":
            urls.append(settings.auth_omnigent_url)
        for value in urls:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username
            ):
                raise ValueError("Configured URLs must be absolute HTTP(S) URLs")
        if urlsplit(settings.origin).path not in {"", "/"}:
            raise ValueError("PORTAL_ORIGIN must not contain a path")
        if settings.base_path and (
            not settings.base_path.startswith("/") or settings.base_path.endswith("/")
        ):
            raise ValueError(
                "PORTAL_BASE_PATH must be empty or an absolute path without a trailing slash"
            )
        if not settings.base_path and settings.auth_mode not in {"oidc", "caipe"}:
            raise ValueError("Serving the portal at / requires OIDC or CAIPE login")
        if settings.terminal_url:
            parsed = urlsplit(settings.terminal_url)
            if (
                parsed.scheme not in {"ws", "wss"}
                or not parsed.hostname
                or not re.fullmatch(r"[a-zA-Z0-9.:-]+", parsed.hostname)
                or parsed.username is not None
                or parsed.query
                or parsed.fragment
                or settings.terminal_url.endswith("/")
                or any(c.isspace() for c in settings.terminal_url)
                or (
                    parsed.scheme == "ws"
                    and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
                )
            ):
                raise ValueError(
                    "PORTAL_TERMINAL_URL must be an absolute WSS base URL without credentials, query or trailing slash (WS is allowed on loopback)"
                )
            parsed.port
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", settings.namespace_prefix):
            raise ValueError("PORTAL_NAMESPACE_PREFIX must be a short DNS label")
        policy = json.loads(settings.namespace_policy)
        if not isinstance(policy, dict):
            raise ValueError("PORTAL_NAMESPACE_POLICY must be an object")
        if type(policy.get("baselineNetworkPolicy", False)) is not bool:
            raise ValueError("Namespace baselineNetworkPolicy must be a boolean")
        labels = policy.get("labels", {})
        if not isinstance(labels, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()
        ):
            raise ValueError("Namespace policy labels must be a string map")
        from .namespaces import namespace_config
        from .profiles import Profiles

        namespace_config(settings)
        header_links(settings)
        Profiles(settings)
        runner_pull_secrets(settings)
        resource_policy(settings)
        from .auth import Authentication

        Authentication(settings)
        return settings


class HeaderLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=40)
    ]
    url: HttpUrl


def header_links(settings):
    links = TypeAdapter(Annotated[list[HeaderLink], Field(max_length=3)]).validate_json(
        settings.header_links
    )
    return [link.model_dump(mode="json") for link in links]


def runtime_classes(settings):
    classes = json.loads(settings.allowed_runtime_classes)
    if classes is None:
        if not settings.runtime_class:
            raise ValueError(
                'Set allowedRuntimeClasses to [""] to approve the cluster default runtime'
            )
        classes = [settings.runtime_class]
    if (
        not isinstance(classes, list)
        or not classes
        or any(
            not isinstance(name, str)
            or len(name) > 253
            or (
                name != ""
                and not re.fullmatch(
                    r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*",
                    name,
                )
            )
            for name in classes
        )
    ):
        raise ValueError(
            "Allowed runtime classes must be DNS names or an explicitly approved empty default"
        )
    if len(set(classes)) != len(classes):
        raise ValueError("Allowed runtime classes must be unique")
    if settings.runtime_class not in classes:
        raise ValueError(
            "Allowed runtime classes must include the default runtimeClass"
        )
    return classes


def runner_pull_secrets(settings):
    secrets = json.loads(settings.runner_image_pull_secrets)
    if not isinstance(secrets, list) or any(
        not isinstance(item, dict)
        or set(item) != {"name"}
        or not isinstance(item["name"], str)
        or not item["name"]
        for item in secrets
    ):
        raise ValueError("Runner image pull secrets must be a list of name references")
    return secrets


def sandbox_security_context(settings):
    identity = json.loads(settings.sandbox_security_context)
    fields = {"runAsUser", "runAsGroup", "fsGroup"}
    if (
        not isinstance(identity, dict)
        or set(identity) != fields
        or any(
            type(value) is not int or not 1 <= value <= 2147483647
            for value in identity.values()
        )
    ):
        raise ValueError(
            "Sandbox security context requires runAsUser, runAsGroup and fsGroup "
            "as integers between 1 and 2147483647"
        )
    return {
        **identity,
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
