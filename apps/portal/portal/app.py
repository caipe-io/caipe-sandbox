"""Authenticated sandbox management over provider-owned inventory and execution."""

import asyncio
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import httpx
from authlib.integrations.base_client.errors import OAuthError
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from joserfc.errors import JoseError
from kubernetes.client import ApiException
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator
from starlette.middleware.sessions import SessionMiddleware
from websocket import WebSocketException

from .acp import install as install_acp
from .auth import COOKIE, Authentication
from .config import Settings, header_links
from .controls import (
    GlobalUpdate,
    NamespaceControl,
    NamespaceUpdate,
    SandboxUpdate,
    creation_blocked,
    disabled,
)
from .drain import Drain, duration_label
from .execution import connect as connect_execution
from .integrations import creation_ui, profile_backend
from .namespaces import namespace_config
from .profiles import Helper, Identifier, Profiles, applied
from .profiles import helper as applied_helper
from .resources import Allocation, policy
from .sandboxes import Store, shares, view
from .storage import Conflict, StorageError
from .storage.database import DatabaseSettings
from .telemetry import RequestTelemetry, Tracing, bind, event, span
from .terminal import TerminalDrain, TerminalIO, attach_exec, warn_restart
from .tools import ToolStatus
from .workspace import Workspace, WorkspaceRequest

STATIC = Path(__file__).parent / "static"
AUTH_RECHECK_SECONDS = 30
TERMINAL_CONNECT_SECONDS = 10


class CreateSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: Identifier | None = None
    profile_revision: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    title: str = Field(default="My sandbox", min_length=1, max_length=80)
    request_id: UUID = Field(default_factory=uuid4)
    resources: Allocation | None = None
    namespace_strategy: Literal["perUser", "perSandbox"] | None = None
    namespace: str | None = Field(default=None, min_length=1, max_length=512)
    integrations: dict[Identifier, dict[str, JsonValue]] = Field(
        default_factory=dict, max_length=16
    )

    @field_validator("title")
    @classmethod
    def title_is_printable(cls, value):
        value = value.strip()
        if not value or not value.isprintable():
            raise ValueError("Enter a sandbox name")
        return value


class Sharing(BaseModel):
    revision: int | None = Field(default=None, ge=1)
    members: dict[str, Literal["view", "shell"]] = Field(
        default_factory=dict, max_length=50
    )

    @field_validator("members")
    @classmethod
    def valid_emails(cls, members):
        import re

        if any(
            len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
            for email in members
        ):
            raise ValueError("Enter valid collaborator email addresses")
        normalized = {email.lower(): role for email, role in members.items()}
        if len(normalized) != len(members):
            raise ValueError("Collaborator emails must be unique")
        return normalized


class SyncConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(min_length=1, max_length=512)
    revision: int = Field(ge=1)


class IntegrationUpdate(SyncConfiguration):
    native_revision: str = Field(min_length=1, max_length=512)
    configuration: dict[str, JsonValue]


def create_app(settings=None, store=None, upstream=None, workspace=None):
    settings = settings or Settings.from_env()
    DatabaseSettings(
        url=settings.database_url, expected_backend=settings.database_backend
    ).parsed_url()
    auth = Authentication(settings)
    profiles = Profiles(settings)
    links = header_links(settings)
    placement = namespace_config(settings)
    drain = Drain(settings.drain_file)
    telemetry = Tracing()

    def public_profile(profile):
        return {
            **profile.public(settings),
            "integrations": creation_ui(profile),
            "resources": profiles.size(profile).model_dump(),
            "resource_bounds": profiles.bounds(profile),
            "provider": selected.key
            if (selected := profile_backend(profile))
            else "agentSandbox",
        }

    @asynccontextmanager
    async def lifespan(app):
        drain.reset()
        app.state.store = store or await asyncio.to_thread(Store, settings)
        try:
            if app.state.store.metadata is not None:
                await asyncio.to_thread(app.state.store.metadata.check_schema)
            await asyncio.to_thread(app.state.store.controls.read)
            app.state.terminal_io = TerminalIO(settings.terminal_io_workers)
        except (HTTPException, StorageError, ValueError) as exc:
            app.state.store.close()
            await asyncio.to_thread(telemetry.close)
            message = exc.detail if isinstance(exc, HTTPException) else str(exc)
            raise RuntimeError(message) from None
        app.state.tools = ToolStatus()
        app.state.workspace = workspace or Workspace()
        async with httpx.AsyncClient(
            base_url=settings.auth_omnigent_url or "http://127.0.0.1",
            timeout=15,
            follow_redirects=False,
        ) as client:
            app.state.upstream = upstream or client

            async def announce_drain():
                while drain.remaining() is None:
                    await asyncio.sleep(0.25)
                logging.getLogger("uvicorn.error").info(
                    "Waiting %s for user terminal sessions to drain",
                    duration_label(settings.drain_seconds),
                )

            tasks = [asyncio.create_task(announce_drain())]
            reconciliation_stop = threading.Event()

            async def maintenance(action, function, **kwargs):
                with span(action, tracer=telemetry.tracer, actor="system"):
                    return await asyncio.to_thread(function, **kwargs)

            if settings.reconcile_interval_seconds:

                async def reconcile_resources():
                    while True:
                        await asyncio.sleep(settings.reconcile_interval_seconds)
                        if drain.remaining() is not None:
                            return
                        work = asyncio.create_task(
                            maintenance(
                                "configuration.reconcile",
                                app.state.store.reconcile_resources,
                                stopping=lambda: (
                                    reconciliation_stop.is_set()
                                    or drain.remaining() is not None
                                ),
                            )
                        )
                        try:
                            failures = await asyncio.shield(work)
                            if failures:
                                logging.getLogger("uvicorn.error").warning(
                                    "configuration_reconcile_failed count=%s",
                                    len(failures),
                                )
                        except asyncio.CancelledError:
                            await work
                            raise
                        except (HTTPException, StorageError):
                            logging.getLogger("uvicorn.error").warning(
                                "configuration_reconcile_unavailable"
                            )

                tasks.append(asyncio.create_task(reconcile_resources()))
            if auth.admins or json.loads(settings.namespace_policy).get(
                "deleteWhenEmpty"
            ):

                async def reconcile():
                    while True:
                        if drain.remaining() is not None:
                            return
                        try:
                            failures = (
                                await maintenance(
                                    "controls.reconcile",
                                    app.state.store.reconcile_controls,
                                )
                                if auth.admins
                                else []
                            )
                            await maintenance(
                                "namespace.cleanup", app.state.store.cleanup_namespaces
                            )
                            if failures:
                                logging.getLogger("uvicorn.error").warning(
                                    "admin_reconcile_failed count=%s", len(failures)
                                )
                        except (ApiException, HTTPException, StorageError):
                            logging.getLogger("uvicorn.error").warning(
                                "admin_reconcile_unavailable"
                            )
                        await asyncio.sleep(10)

                tasks.append(asyncio.create_task(reconcile()))
            try:
                yield
            finally:
                reconciliation_stop.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                app.state.terminal_io.close()
                await asyncio.to_thread(app.state.store.close)
                await asyncio.to_thread(telemetry.close)

    app = FastAPI(
        title="CAIPE Sandbox", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    prefix = settings.base_path
    install_acp(app, settings, auth, drain)
    app.add_middleware(RequestTelemetry, telemetry=telemetry)


    app.state.auth = auth
    app.state.drain = drain
    if auth.oidc:
        app.add_middleware(
            SessionMiddleware,
            secret_key=settings.session_secret,
            session_cookie=COOKIE,
            max_age=auth.policy.session_seconds,
            path=prefix + "/",
            same_site="lax",
            https_only=True,
        )

    async def current_principal(connection):
        principal = await auth.principal(connection, app.state.upstream)
        bind(actor=principal.owner, actor_role=principal.role)
        connection.state.actor = principal.owner
        return principal

    async def identity(connection, write=False):
        principal = await current_principal(connection)
        if write:
            principal.require_user()
        return principal.owner

    def origin(connection, *, allow_cross_site=False):
        if connection.headers.get("origin") != settings.origin.rstrip("/"):
            raise HTTPException(403, "Request origin is not permitted")
        if (
            not allow_cross_site
            and connection.headers.get("sec-fetch-site") == "cross-site"
        ):
            raise HTTPException(403, "Cross-site requests are not permitted")

    async def mutate(request):
        origin(request)
        drain.require_accepting()
        return await identity(request, write=True)

    @app.exception_handler(ApiException)
    async def kubernetes_error(request, exc):
        # Kubernetes error bodies may contain manifests and Secret values.
        code = 422 if exc.status in {400, 422} else 409 if exc.status == 409 else 503
        message = (
            "Sandbox changed; refresh and retry"
            if code == 409
            else "Sandbox configuration was rejected by Kubernetes validation/admission; check the profile and platform policy"
            if code == 422
            else "Kubernetes operation failed; check portal service-account access and controller health"
        )
        return JSONResponse({"detail": message}, status_code=code)

    @app.exception_handler(httpx.HTTPError)
    async def upstream_error(request, exc):
        return JSONResponse(
            {"detail": "Omnigent is unavailable; try again"}, status_code=503
        )

    @app.exception_handler(StorageError)
    async def metadata_error(request, exc):
        return JSONResponse(
            {
                "detail": str(exc)
                if isinstance(exc, Conflict)
                else "Portal metadata is unavailable; try again"
            },
            status_code=409 if isinstance(exc, Conflict) else 503,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        request_id = getattr(request.state, "request_id", str(uuid4()))
        logging.getLogger(__name__).error(
            "unexpected_failure",
            exc_info=exc,
            extra={
                "event_fields": {
                    "request_id": request_id,
                    "trace_id": getattr(request.state, "trace_id", ""),
                    "actor": getattr(request.state, "actor", "anonymous"),
                }
            },
        )
        return JSONResponse(
            {"detail": f"An unexpected portal error occurred. Reference: {request_id}"},
            status_code=500,
            headers={"X-Request-ID": request_id},
        )

    @app.get(prefix + "/auth/config")
    def auth_config():
        return {
            "mode": settings.auth_mode,
            "login_url": auth.login_url,
            "header_links": links,
            **(
                {
                    "terminal_credentials": True,
                    "terminal_url": settings.terminal_url,
                    "embedded": True,
                    "login_message": auth.hosted.signin_message,
                }
                if auth.terminal_credentials
                else {}
            ),
        }

    @app.get(prefix + "/auth/login")
    async def login(request: Request, owner: str | None = None):
        if not auth.login_url:
            raise HTTPException(401, auth.hosted.signin_message)
        if not auth.oidc:
            return RedirectResponse(auth.login_url)
        request.session.clear()
        if owner:
            try:
                normalized = Sharing.valid_emails({owner: "view"})
            except ValueError:
                raise HTTPException(422, "Enter a valid sharing owner email") from None
            request.session["sharing_owner"] = next(iter(normalized))
        try:
            metadata = await auth.client.load_server_metadata()
            if metadata.get("issuer") != auth.policy.issuer:
                raise HTTPException(
                    503, "OIDC discovery issuer does not match configuration"
                )
            return await auth.client.authorize_redirect(
                request, settings.origin.rstrip("/") + prefix + "/auth/callback"
            )
        except (httpx.HTTPError, OAuthError, ValueError):
            raise HTTPException(503, "OIDC login is unavailable") from None

    @app.get(prefix + "/auth/callback")
    async def callback(request: Request):
        if not auth.oidc:
            raise HTTPException(404)
        try:
            token = await auth.client.authorize_access_token(
                request,
                claims_options={
                    "iss": {"essential": True, "value": auth.policy.issuer}
                },
                leeway=0,
            )
            if not token.get("id_token") or not token.get("userinfo"):
                raise HTTPException(401, "OIDC did not return a verified ID token")
            claims = dict(token["userinfo"])
            if auth.policy.use_userinfo:
                userinfo = await auth.client.userinfo(token=token)
                if userinfo.get("sub") != claims.get("sub"):
                    raise HTTPException(
                        401, "OIDC UserInfo subject does not match the ID token"
                    )
                for field in {
                    auth.policy.email_claim,
                    auth.policy.groups_claim,
                    "email_verified",
                }:
                    if field in userinfo:
                        claims[field] = userinfo[field]
            record = auth.session(claims)
        except HTTPException:
            request.session.clear()
            raise
        except (
            httpx.HTTPError,
            OAuthError,
            JoseError,
            ValueError,
            KeyError,
            TypeError,
        ):
            request.session.clear()
            raise HTTPException(
                401, "OIDC sign-in could not be verified; start again"
            ) from None
        sharing_owner = request.session.get("sharing_owner")
        request.session.clear()
        request.session["identity"] = record
        event("sign_in", category="audit", actor=record["owner"], outcome="accepted")
        target = (
            prefix + "/" + ("?owner=" + quote(sharing_owner) if sharing_owner else "")
        )
        return RedirectResponse(target, status_code=303)

    @app.post(prefix + "/auth/logout")
    async def logout(request: Request):
        origin(request)
        if not auth.oidc:
            raise HTTPException(404)
        event(
            "sign_out",
            category="audit",
            session_owner=request.session.get("identity", {}).get("owner", ""),
            outcome="accepted",
        )
        request.session.clear()
        return {"status": "signed-out"}

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/readyz")
    def ready():
        drain.require_accepting()
        if app.state.store.metadata is not None:
            app.state.store.metadata.check_schema()
        app.state.store.controls.read()
        return {"status": "ok"}

    @app.get(prefix + "/")
    def page():
        terminal_origin = urlsplit(settings.terminal_url)
        connect_source = (
            (" " + terminal_origin.scheme + "://" + terminal_origin.netloc)
            if terminal_origin.netloc
            else ""
        )
        return HTMLResponse(
            (STATIC / "index.html")
            .read_text(encoding="utf-8")
            .replace("__PORTAL_BASE_PATH__", quote(prefix, safe="/"))
            .replace("__PORTAL_BODY_CLASS__", "embedded" if auth.terminal_credentials else ""),
            headers={
                "Content-Security-Policy": f"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'{connect_source}; frame-ancestors 'self'; object-src 'none'; base-uri 'none'",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    if prefix:
        app.add_api_route(prefix, page, methods=["GET"], include_in_schema=False)

    @app.get(prefix + "/assets/{name}")
    def assets(name: str):
        if name not in {
            "portal.js",
            "terminal-runtime.js",
            "portal.css",
            "licenses.txt",
            "caipe-sandbox-logo.png",
        }:
            raise HTTPException(404)
        return FileResponse(
            STATIC / name, headers={"X-Content-Type-Options": "nosniff"}
        )

    @app.get(prefix + "/assets/integrations/{name}")
    def integration_image(name: str):
        import re

        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*\.(svg|png|webp|jpe?g)", name):
            raise HTTPException(404)
        path = STATIC / "integrations" / name
        if not path.is_file():
            raise HTTPException(404)
        return FileResponse(path, headers={"X-Content-Type-Options": "nosniff"})

    @app.get(prefix + "/api/sandboxes")
    async def list_sandboxes(request: Request, owner: str | None = None):
        principal = await current_principal(request)
        actor = principal.owner
        owner = owner or actor
        items = await asyncio.to_thread(app.state.store.shared_list, actor, owner)
        control_policy, _ = await asyncio.to_thread(app.state.store.controls.read)
        observations = await asyncio.to_thread(app.state.store.status_views, items)
        rows = []
        for item, row in zip(items, observations, strict=True):
            row["disabled_reason"] = disabled(item, control_policy)
            row["disabled"] = bool(row["disabled_reason"])
            row["namespace_locked"] = control_policy.namespaces.get(
                row["namespace_key"], NamespaceControl()
            ).creation_disabled
            mine = item.owner == actor
            row["can_manage"] = (
                mine and principal.role in {"user", "admin"} and not row["disabled"]
            )
            row["can_shell"] = (
                principal.role in {"user", "admin"}
                and (
                    mine
                    or item.record.scope_owner == actor
                    or shares(item).get(actor) == "shell"
                )
                and not row["disabled"]
                and item.reference is not None
                and not item.record.operation
            )
            row["can_share"] = (
                item.record.scope_owner == actor
                and principal.role in {"user", "admin"}
                and not row["disabled"]
            )
            row["sharing"] = shares(item) if row["can_share"] else {}
            rows.append(row)
        namespaces = sorted({row["namespace"] for row in rows})
        return JSONResponse(
            {
                "user_id": actor,
                "role": principal.role,
                "can_manage": principal.role in {"user", "admin"} and owner == actor,
                "creation_disabled_reason": creation_blocked(actor, control_policy),
                "announcement": control_policy.announcement.model_dump()
                if control_policy.announcement
                else None,
                "namespace": namespaces[0]
                if len(namespaces) == 1
                else f"{len(namespaces)} namespaces",
                "namespace_strategy": placement.strategy,
                "namespace_choices": placement.choices,
                "profiles": [public_profile(p) for p in profiles.items.values()],
                "default_profile": settings.default_profile,
                "resource_policy": policy(settings).model_dump(),
                "sandboxes": rows,
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/api/admin/sandboxes")
    async def admin_sandboxes(request: Request):
        principal = await current_principal(request)
        principal.require_admin()
        items = await asyncio.to_thread(app.state.store.admin_list)
        control_policy, version = await asyncio.to_thread(app.state.store.controls.read)
        observations = await asyncio.to_thread(app.state.store.status_views, items)
        rows = []
        for sandbox, row in zip(items, observations, strict=True):
            row["disabled_reason"] = disabled(sandbox, control_policy)
            row["disabled"] = bool(row["disabled_reason"])
            row["namespace_locked"] = control_policy.namespaces.get(
                row["namespace_key"], NamespaceControl()
            ).creation_disabled
            rows.append(row)
        return JSONResponse(
            {
                "user_id": principal.owner,
                "role": principal.role,
                "can_manage": False,
                "controls": {
                    **control_policy.model_dump(),
                    "resource_version": version,
                },
                "announcement": control_policy.announcement.model_dump()
                if control_policy.announcement
                else None,
                "namespace": "All namespaces",
                "namespace_strategy": placement.strategy,
                "namespace_choices": placement.choices,
                "profiles": [public_profile(p) for p in profiles.items.values()],
                "default_profile": settings.default_profile,
                "resource_policy": policy(settings).model_dump(),
                "sandboxes": rows,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def administrator(request):
        origin(request)
        principal = await current_principal(request)
        principal.require_admin()
        return principal.owner

    @app.get(prefix + "/api/namespaces")
    async def namespace_choices(request: Request):
        actor = await identity(request, write=True)
        return JSONResponse(
            {
                "namespaces": await asyncio.to_thread(
                    app.state.store.namespace_access.list, actor
                )
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.put(prefix + "/api/admin/namespaces/{key}")
    async def namespace_lock(key: str, request: Request, body: NamespaceUpdate):
        actor = await administrator(request)
        version = await asyncio.to_thread(
            app.state.store.namespace_access.save, key, body, actor
        )
        event(
            "namespace_lock_changed",
            category="audit",
            namespace_key=key,
            locked=body.locked,
            outcome="saved",
        )
        return {"resource_version": version}

    @app.put(prefix + "/api/admin/controls")
    async def global_controls(request: Request, body: GlobalUpdate):
        actor = await administrator(request)

        def save():
            policy, version = app.state.store.controls.save(body, actor)
            event(
                "global_controls_changed",
                category="audit",
                creation_disabled=body.creation_disabled,
                sandboxes_disabled=body.sandboxes_disabled,
                user_controls_count=len(body.users),
                revision=version,
                outcome="saved",
            )
            try:
                failures = app.state.store.reconcile_controls()
            except (ApiException, HTTPException):
                raise HTTPException(
                    503,
                    "Restrictions were saved, but suspension could not be checked. The portal will retry; inspect controller health before assuming workloads have stopped.",
                ) from None
            return {
                "controls": {**policy.model_dump(), "resource_version": version},
                "suspension_failures": failures,
            }

        result = await asyncio.to_thread(save)
        return result

    @app.put(prefix + "/api/admin/sandboxes/{name}/control")
    async def sandbox_controls(
        name: str,
        request: Request,
        body: SandboxUpdate,
        namespace: str = Query(min_length=1),
        uid: str = Query(min_length=1),
    ):
        actor = await administrator(request)
        sandbox = await asyncio.to_thread(
            app.state.store.admin_control, name, namespace, uid, body, actor
        )
        event(
            "sandbox_control_changed",
            category="audit",
            sandbox_id=str(sandbox.record.id),
            namespace=namespace,
            provider=sandbox.record.provider,
            disabled=body.disabled,
            mode=body.operating_mode,
            notice_changed=body.notice is not None,
            outcome="saved",
        )
        return view(sandbox)

    async def user_target(request, name):
        actor = await mutate(request)
        sandbox = await asyncio.to_thread(app.state.store.get, name, actor)
        await asyncio.to_thread(app.state.store.check_access, sandbox)
        return actor

    @app.delete(prefix + "/api/admin/sandboxes/{name}", status_code=202)
    async def admin_delete(
        name: str,
        request: Request,
        namespace: str = Query(min_length=1),
        uid: str = Query(min_length=1),
    ):
        origin(request)
        principal = await current_principal(request)
        principal.require_admin()
        result = await asyncio.to_thread(
            app.state.store.admin_delete, name, namespace, uid
        )
        event(
            "sandbox_delete_requested",
            category="audit",
            namespace=namespace,
            native_id=uid,
            outcome="accepted",
        )
        return result

    async def terminal_target(connection, name, owner, namespace):
        principal = await current_principal(connection)
        principal.require_user()
        if connection.url.path.startswith(prefix + "/api/admin/"):
            principal.require_admin()
            if not namespace:
                raise HTTPException(422, "Sandbox namespace is required")
            target = await asyncio.to_thread(
                app.state.store.admin_execution, name, namespace
            )
        else:
            target = await asyncio.to_thread(
                app.state.store.execution, name, principal.owner, owner
            )
        return principal.owner, target

    def terminal_binding(connection, name, owner, namespace, helper, target):
        admin = connection.url.path.startswith(prefix + "/api/admin/")
        return {
            "name": name,
            "owner": None if admin else owner,
            "namespace": namespace,
            "helper": helper,
            "admin": admin,
            "scope": target.scope,
            "uid": target.sandbox_uid,
        }

    @app.post(prefix + "/api/admin/sandboxes/{name}/terminal-credentials")
    @app.post(prefix + "/api/sandboxes/{name}/terminal-credentials")
    async def terminal_credentials(
        request: Request,
        name: str,
        owner: str | None = None,
        namespace: str | None = None,
        helper: str | None = Query(
            default=None, max_length=40, pattern=r"^[a-z][a-z0-9-]*$"
        ),
    ):
        if not auth.terminal_credentials:
            raise HTTPException(404)
        origin(request)
        drain.require_accepting()
        _, target = await terminal_target(request, name, owner, namespace)
        binding = terminal_binding(request, name, owner, namespace, helper, target)
        return JSONResponse(
            auth.terminal_credentials.issue(request.state.terminal_identity, binding),
            headers={"Cache-Control": "no-store"},
        )

    @app.post(prefix + "/api/sandboxes", status_code=201)
    async def create_sandbox(request: Request, body: CreateSandbox | None = None):
        owner = await mutate(request)
        body = body or CreateSandbox()
        return view(
            await asyncio.to_thread(
                app.state.store.create,
                owner,
                body.title,
                body.request_id,
                body.resources,
                body.profile,
                body.profile_revision,
                body.namespace_strategy,
                body.namespace,
                body.integrations,
            )
        )

    @app.get(prefix + "/api/profiles")
    async def list_profiles(request: Request):
        await identity(request)
        return JSONResponse(
            {
                "default": settings.default_profile,
                "profiles": [public_profile(p) for p in profiles.items.values()],
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/api/admin/profiles")
    async def admin_profiles(request: Request):
        principal = await current_principal(request)
        principal.require_admin()
        items = await asyncio.to_thread(app.state.store.admin_list)
        return JSONResponse(
            {
                "source": "deployment/GitOps",
                "default": settings.default_profile,
                "namespace": placement.model_dump(),
                "profiles": [
                    {
                        **public_profile(p),
                        "definition": p.model_dump(exclude_none=True),
                        "sandboxes": [
                            {
                                "id": sandbox.name,
                                "namespace": sandbox.scope,
                                "revision": snapshot["revision"],
                            }
                            for sandbox in items
                            if (snapshot := applied(sandbox)) and snapshot["id"] == p.id
                        ],
                    }
                    for p in profiles.items.values()
                ],
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/api/sandboxes/{name}/configuration")
    async def sandbox_configuration(
        name: str, request: Request, owner: str | None = None
    ):
        principal = await current_principal(request)
        actor = principal.owner
        sandbox = await asyncio.to_thread(
            app.state.store.shared_get, name, actor, owner or actor
        )
        data = await asyncio.to_thread(app.state.store.configuration, sandbox)
        data["can_sync"] = (
            data["can_sync"]
            and actor == sandbox.owner
            and principal.role in {"user", "admin"}
        )
        return JSONResponse(
            data,
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/api/admin/sandboxes/{name}/configuration")
    async def admin_configuration(name: str, request: Request, namespace: str):
        principal = await current_principal(request)
        principal.require_admin()
        sandbox = await asyncio.to_thread(app.state.store.admin_get, name, namespace)
        return JSONResponse(
            await asyncio.to_thread(app.state.store.configuration, sandbox),
            headers={"Cache-Control": "no-store"},
        )

    async def workspace_target(name, request, uid, owner, write=False):
        drain.require_accepting()
        actor = await mutate(request) if write else await identity(request, write=True)
        sandbox = await asyncio.to_thread(
            app.state.store.shared_get, name, actor, owner or actor, True
        )
        if sandbox.uid != uid:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        if sandbox.requested_mode == "Suspended" or sandbox.deleting:
            raise HTTPException(
                409, "Resume the sandbox before editing startup and services"
            )
        target = await asyncio.to_thread(app.state.store.execution, name, actor, owner)
        if target.sandbox_uid != uid:
            raise HTTPException(409, "Sandbox changed; refresh and retry")
        return target

    @app.get(prefix + "/api/sandboxes/{name}/workspace")
    async def workspace_state(
        name: str,
        request: Request,
        uid: str = Query(min_length=1),
        owner: str | None = None,
    ):
        target = await workspace_target(name, request, uid, owner)
        result = await asyncio.to_thread(
            app.state.workspace.run, target, {"action": "inspect"}
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post(prefix + "/api/sandboxes/{name}/workspace")
    async def workspace_update(
        name: str,
        request: Request,
        body: WorkspaceRequest,
        uid: str = Query(min_length=1),
        owner: str | None = None,
    ):
        target = await workspace_target(name, request, uid, owner, True)
        result = await asyncio.to_thread(
            app.state.workspace.run, target, body.model_dump(exclude_none=True)
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.put(prefix + "/api/sandboxes/{name}/sharing")
    async def sharing(name: str, request: Request, body: Sharing):
        owner = await mutate(request)
        sandbox = await asyncio.to_thread(
            app.state.store.sharing, name, owner, body.members, body.revision
        )
        return {
            "members": shares(sandbox),
            "namespace": sandbox.scope,
            "scope": "namespace",
        }

    @app.put(prefix + "/api/sandboxes/{name}/resources")
    async def configure(name: str, request: Request, body: Allocation):
        owner = await user_target(request, name)
        return view(
            await asyncio.to_thread(app.state.store.configure, name, owner, body)
        )

    @app.get(prefix + "/api/sandboxes/{name}/integrations/{panel}")
    async def integration_panel(
        name: str, panel: str, request: Request, owner: str | None = None
    ):
        principal = await current_principal(request)
        sandbox = await asyncio.to_thread(
            app.state.store.shared_get, name, principal.owner, owner or principal.owner
        )
        result = await asyncio.to_thread(
            app.state.store.integration_panel, sandbox, panel
        )
        result["can_edit"] = (
            principal.role == "admin" and sandbox.owner == principal.owner
            if result.get("admin_only")
            else principal.role in {"user", "admin"}
            and sandbox.owner == principal.owner
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.put(prefix + "/api/sandboxes/{name}/integrations/{panel}")
    async def update_integration(
        name: str, panel: str, request: Request, body: IntegrationUpdate
    ):
        actor = await user_target(request, name)
        principal = await current_principal(request)
        sandbox = await asyncio.to_thread(app.state.store.get, name, actor)
        result = await asyncio.to_thread(
            app.state.store.update_integration,
            sandbox,
            panel,
            body,
            actor,
            admin=principal.role == "admin",
        )
        return view(result)

    @app.get(prefix + "/api/admin/sandboxes/{name}/integrations/{panel}")
    async def admin_integration_panel(
        name: str, panel: str, request: Request, namespace: str
    ):
        principal = await current_principal(request)
        principal.require_admin()
        sandbox = await asyncio.to_thread(app.state.store.admin_get, name, namespace)
        result = await asyncio.to_thread(
            app.state.store.integration_panel, sandbox, panel
        )
        return JSONResponse(
            {**result, "can_edit": True}, headers={"Cache-Control": "no-store"}
        )

    @app.put(prefix + "/api/admin/sandboxes/{name}/integrations/{panel}")
    async def admin_update_integration(
        name: str, panel: str, request: Request, body: IntegrationUpdate, namespace: str
    ):
        actor = await administrator(request)
        sandbox = await asyncio.to_thread(app.state.store.admin_get, name, namespace)
        result = await asyncio.to_thread(
            app.state.store.update_integration, sandbox, panel, body, actor, admin=True
        )
        return view(result)

    @app.post(prefix + "/api/sandboxes/{name}/suspend")
    async def suspend(name: str, request: Request):
        owner = await user_target(request, name)
        return view(
            await asyncio.to_thread(app.state.store.mode, name, owner, "Suspended")
        )

    @app.post(prefix + "/api/sandboxes/{name}/resume")
    async def resume(name: str, request: Request):
        owner = await user_target(request, name)
        return view(
            await asyncio.to_thread(app.state.store.mode, name, owner, "Running")
        )

    @app.post(prefix + "/api/sandboxes/{name}/retry")
    async def retry_operation(name: str, request: Request):
        owner = await mutate(request)
        return view(await asyncio.to_thread(app.state.store.retry, name, owner))

    @app.post(prefix + "/api/sandboxes/{name}/sync")
    async def sync_configuration(name: str, request: Request, body: SyncConfiguration):
        owner = await mutate(request)
        return view(
            await asyncio.to_thread(
                app.state.store.sync, name, owner, body.uid, body.revision
            )
        )

    @app.post(prefix + "/api/admin/sandboxes/{name}/sync")
    async def admin_sync_configuration(
        name: str, request: Request, body: SyncConfiguration, namespace: str
    ):
        await administrator(request)
        result = await asyncio.to_thread(
            app.state.store.admin_sync, name, namespace, body.uid, body.revision
        )
        event(
            "configuration_sync_requested",
            category="audit",
            sandbox_id=str(result.record.id),
            namespace=namespace,
            provider=result.record.provider,
            outcome="applied",
        )
        return view(result)

    @app.post(prefix + "/api/admin/sandboxes/{name}/retry")
    async def admin_retry_operation(
        name: str, request: Request, namespace: str, uid: str
    ):
        await administrator(request)
        return view(
            await asyncio.to_thread(app.state.store.admin_retry, name, namespace, uid)
        )

    @app.delete(prefix + "/api/sandboxes/{name}", status_code=202)
    async def delete(name: str, request: Request):
        owner = await user_target(request, name)
        return await asyncio.to_thread(app.state.store.delete, name, owner)

    @app.get(prefix + "/api/sandboxes/{name}/tools")
    async def tool_status(
        name: str, request: Request, owner: str | None = None, fresh: bool = False
    ):
        drain.require_accepting()
        actor = await identity(request, write=True)
        target = await asyncio.to_thread(app.state.store.execution, name, actor, owner)
        sandbox = await asyncio.to_thread(
            app.state.store.shared_get, name, actor, owner or actor, True
        )
        snapshot = applied(sandbox)
        probes = (
            [
                Helper.model_validate(h)
                for h in snapshot["definition"]["helpers"]
                if h.get("status")
            ]
            if snapshot
            else []
        )
        result = await asyncio.to_thread(
            app.state.tools.status,
            target,
            fresh=fresh,
            helpers=probes,
        )
        return JSONResponse({"tools": result}, headers={"Cache-Control": "no-store"})

    @app.websocket(prefix + "/api/admin/sandboxes/{name}/terminal")
    @app.websocket(prefix + "/api/sandboxes/{name}/terminal")
    async def terminal(
        ws: WebSocket,
        name: str,
        owner: str | None = None,
        namespace: str | None = None,
        helper: str | None = Query(
            default=None, max_length=40, pattern=r"^[a-z][a-z0-9-]*$"
        ),
    ):
        try:
            origin(ws, allow_cross_site=bool(auth.terminal_credentials))
        except HTTPException:
            event(
                "terminal_access_denied",
                category="audit",
                outcome="denied",
                code="origin",
            )
            await ws.close(code=1008)
            return
        await ws.accept()
        remaining = drain.remaining()
        if remaining is not None:
            await warn_restart(ws, remaining)
            await ws.close(code=1012)
            return
        request_id = getattr(ws.state, "request_id", str(uuid4()))
        connected_at = time.monotonic()
        stage = "authorization"
        conn = None
        session = TerminalDrain()
        watcher = asyncio.create_task(session.watch(drain, ws, asyncio.current_task()))
        logger = logging.getLogger("uvicorn.error")

        async def report(code, message):
            logger.warning(
                "terminal_error id=%s stage=%s code=%s sandbox=%s",
                request_id,
                stage,
                code,
                name,
                extra={
                    "event_fields": {
                        "request_id": request_id,
                        "stage": stage,
                        "code": code,
                        "sandbox": name,
                        "outcome": "error",
                        "category": "audit",
                    }
                },
            )
            try:
                await ws.send_bytes(
                    json.dumps(
                        {
                            "type": "error",
                            "code": code,
                            "stage": stage,
                            "message": message,
                            "request_id": request_id,
                        }
                    ).encode()
                )
            except (WebSocketDisconnect, RuntimeError, OSError):
                pass

        try:
            drain.require_accepting()
            if auth.terminal_credentials:
                await auth.terminal_credentials.accept(ws)
            actor, target = await asyncio.wait_for(
                terminal_target(ws, name, owner, namespace), TERMINAL_CONNECT_SECONDS
            )
            if auth.terminal_credentials:
                auth.terminal_credentials.check(
                    ws, terminal_binding(ws, name, owner, namespace, helper, target)
                )
            admin_terminal = ws.url.path.startswith(prefix + "/api/admin/")
            if admin_terminal:
                logger.info(
                    "admin_action=terminal actor=%s namespace=%s sandbox=%s",
                    actor,
                    target.scope,
                    name,
                )
            if admin_terminal:
                sandbox = await asyncio.to_thread(
                    app.state.store.admin_get, name, namespace
                )
            else:
                sandbox = await asyncio.to_thread(
                    app.state.store.shared_get, name, actor, owner or actor, True
                )
            entry = applied_helper(sandbox, helper) if helper else None
            snapshot = applied(sandbox)
            if entry:
                command = ["/bin/sh", "-c", entry.script]
            elif target.default_command and not snapshot:
                command = list(target.default_command)
            else:
                terminal = (
                    snapshot["definition"].get("terminal", {}) if snapshot else {}
                )
                command = [
                    "env",
                    "TERM=xterm-256color",
                    "COLORTERM=truecolor",
                    *terminal.get("command", ["/bin/sh", "-i"]),
                ]

            def attach():
                drain.require_accepting()
                return connect_execution(
                    target,
                    command,
                    stdin=True,
                    tty=True,
                    timeout=TERMINAL_CONNECT_SECONDS,
                )

            stage = "exec"
            with span(
                "terminal.attach",
                tracer=telemetry.tracer,
                request_id=request_id,
                sandbox_id=str(sandbox.record.id),
                namespace=target.scope,
                provider=sandbox.record.provider,
            ):
                conn = await attach_exec(
                    attach, TERMINAL_CONNECT_SECONDS, run=app.state.terminal_io.run
                )
                drain.require_accepting()
                session.active = True
                await ws.send_bytes(b'{"type":"ready"}')
                logger.info(
                    "terminal_ready id=%s namespace=%s sandbox=%s",
                    request_id,
                    target.scope,
                    name,
                    extra={
                        "event_fields": {
                            "request_id": request_id,
                            "sandbox_id": str(sandbox.record.id),
                            "namespace": target.scope,
                            "provider": sandbox.record.provider,
                            "category": "audit",
                            "outcome": "attached",
                        }
                    },
                )
            stage = "stream"

            def poll_output():
                conn.update(timeout=0.02)
                return conn.read_all()

            async def output():
                while conn.is_open():
                    text = await app.state.terminal_io.run(poll_output)
                    if text:
                        await ws.send_text(text)
                    await asyncio.sleep(0 if text else 0.01)

            async def input():
                while conn.is_open():
                    message = json.loads(await ws.receive_text())
                    if message.get("type") == "input" and isinstance(
                        message.get("data"), str
                    ):
                        await app.state.terminal_io.run(
                            conn.write_stdin, message["data"][:65536]
                        )
                    elif message.get("type") == "resize":
                        cols = max(10, min(500, int(message["cols"])))
                        rows = max(5, min(200, int(message["rows"])))
                        await app.state.terminal_io.run(
                            conn.write_channel,
                            4,
                            json.dumps({"Width": cols, "Height": rows}),
                        )

            async def revalidate():
                while conn.is_open():
                    await asyncio.sleep(min(AUTH_RECHECK_SECONDS, 5))
                    current_actor, _pod = await terminal_target(
                        ws, name, owner, namespace
                    )
                    if current_actor != actor:
                        raise HTTPException(403, "Terminal identity changed")
                    if auth.terminal_credentials:
                        auth.terminal_credentials.check(
                            ws,
                            terminal_binding(ws, name, owner, namespace, helper, _pod),
                        )

            tasks = [
                asyncio.create_task(output()),
                asyncio.create_task(input()),
                asyncio.create_task(revalidate()),
            ]
            try:
                _done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        raise result
                if entry and not conn.is_open():
                    await ws.send_bytes(
                        json.dumps(
                            {"type": "complete", "exit_code": conn.returncode}
                        ).encode()
                    )
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            if not session.restarting:
                raise
        except TimeoutError:
            await report(
                "server-timeout",
                f"Server timed out during {stage} after {TERMINAL_CONNECT_SECONDS} seconds.",
            )
        except HTTPException as exc:
            await report(f"http-{exc.status_code}", str(exc.detail))
        except StorageError:
            await report(
                "metadata-unavailable",
                "Portal metadata is unavailable; reconnect when access can be checked",
            )
        except ApiException as exc:
            await report(
                "kubernetes-api",
                f"Kubernetes API rejected terminal setup (HTTP {exc.status}). Check sandbox readiness and exec permissions.",
            )
        except WebSocketDisconnect:
            pass
        except (WebSocketException, OSError):
            await report(
                "exec-transport",
                "Connection to the sandbox execution transport failed. Check the runtime service and network connectivity.",
            )
        except (ValueError, KeyError, TypeError):
            await report(
                "terminal-protocol",
                "The terminal received an invalid message or connection state.",
            )
        finally:
            watcher.cancel()
            if session.active:
                event(
                    "terminal_disconnected",
                    category="audit",
                    request_id=request_id,
                    sandbox_id=str(sandbox.record.id),
                    namespace=target.scope,
                    provider=sandbox.record.provider,
                    outcome="disconnected",
                    duration_ms=round((time.monotonic() - connected_at) * 1000, 2),
                    restarting=session.restarting,
                )
            if conn:
                # Close the socket even when WebSocket disconnect cancels this task.
                conn.close()
            try:
                await ws.close(
                    code=1012
                    if session.restarting or drain.remaining() is not None
                    else 1000
                )
            except (
                TimeoutError,
                RuntimeError,
                OSError,
                WebSocketDisconnect,
            ):
                pass

    return app
