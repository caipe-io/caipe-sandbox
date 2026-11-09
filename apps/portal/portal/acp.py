"""Private, profile-bound ACP data plane over the existing execution transport."""

import asyncio
import base64
import hashlib
import hmac
import json
from contextlib import suppress
from urllib.parse import urlsplit

from anyio import CancelScope
from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from websocket import WebSocketException

from .controls import NamespaceControl
from .coordination import claim
from .execution import connect
from .profiles import ACPProcess, Identifier, applied, encoded
from .storage import ACPBindingConflict, ACPBusy, Conflict, scope_key
from .terminal import attach_exec

MAX_FRAME = 1024 * 1024
MAX_BODY = 512 * 1024
IDENTITY_KEYS = (
    "sandbox_uid",
    "owner_subject",
    "conversation_id",
    "binding_id",
    "policy_revision",
)


class Connection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="Claude coding sandbox", min_length=1, max_length=80)
    owner: str = Field(min_length=1, max_length=254)
    owner_subject: str = Field(min_length=1, max_length=254)
    sandbox_name: str = Field(min_length=1, max_length=36)
    sandbox_uid: str = Field(min_length=1, max_length=512)
    policy_revision: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class OpenProcess(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^open$")
    protocol: int = Field(ge=1, le=1, strict=True)
    sandbox_uid: str = Field(min_length=1, max_length=512)
    policy_revision: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    owner_subject: str = Field(min_length=1, max_length=254)
    binding_id: str = Field(min_length=1, max_length=254)
    conversation_id: str = Field(min_length=1, max_length=254)
    run_id: str = Field(min_length=1, max_length=254)


def configuration_revision(snapshot, settings):
    """Configuration identity, not an attestation of live network enforcement."""
    return (
        "sha256:"
        + hashlib.sha256(
            encoded(
                {
                    "profile": snapshot["revision"],
                    "namespace_policy": json.loads(settings.namespace_policy),
                }
            ).encode()
        ).hexdigest()
    )


def private_sandbox(store, name, owner):
    sandbox = store.get(name, owner)
    store.check_access(sandbox)
    if sandbox.provider != "agentSandbox":
        raise HTTPException(
            409,
            "This ACP connection requires the qualified Agent Sandbox backend. Create a direct coding sandbox; existing other runtime profiles remain available for their normal use.",
        )
    key = scope_key(
        sandbox.record.provider, sandbox.record.provider_instance, sandbox.record.scope
    )
    controls, _ = store.controls.read()
    if controls.namespaces.get(key, NamespaceControl()).network_policy:
        raise HTTPException(
            409, "ACP requires a namespace without a mutable network policy"
        )
    snapshot = applied(sandbox)
    if not snapshot or not snapshot["definition"].get("acp"):
        raise HTTPException(409, "Choose a sandbox created with an ACP coding profile")
    if (
        snapshot.get("namespaceStrategy") != "perSandbox"
        or sandbox.record.scope_owner != owner
    ):
        raise HTTPException(
            409, "ACP requires a private per-sandbox namespace owned by you"
        )
    if any(role == "shell" for role in sandbox.grants.values()):
        raise HTTPException(
            409, "Remove shared shell access before connecting this sandbox"
        )
    if sandbox.configuration_drift:
        raise HTTPException(
            409, "Resolve sandbox configuration drift before connecting"
        )
    return sandbox, snapshot


class Connections:
    def __init__(self, settings):
        self.settings = settings
        raw = json.loads(settings.acp_connections)
        if not isinstance(raw, dict):
            raise TypeError("PORTAL_ACP_CONNECTIONS must be an object")
        self.items = {}
        for alias, definition in raw.items():
            # Reuse the profile identifier grammar rather than inventing URL keys.
            TypeAdapter(Identifier).validate_python(alias)
            self.items[alias] = Connection.model_validate(definition)
        if self.items:
            parsed = urlsplit(settings.origin)
            if parsed.scheme != "https" and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                raise ValueError("ACP connections require HTTPS portal origin")
            if len(settings.acp_service_token) < 32:
                raise ValueError(
                    "ACP service token must contain at least 32 characters"
                )

    def authorize(self, ws, alias):
        expected = "Bearer " + self.settings.acp_service_token
        actual = ws.headers.get("authorization", "")
        entry = self.items.get(alias)
        if not self.settings.acp_service_token or not hmac.compare_digest(
            actual, expected
        ):
            raise HTTPException(401, "ACP service authentication is required")
        if (
            entry is None
            or ws.headers.get("x-harness-engine-subject") != entry.owner_subject
        ):
            raise HTTPException(403, "ACP connection is not admitted for this caller")
        # Browser cookies/origins never authorize the private machine data plane.
        if ws.headers.get("origin"):
            raise HTTPException(403, "Use the approved service connection")
        return entry


def install(app, settings, auth, drain):
    connections = Connections(settings)
    prefix = settings.base_path

    @app.get(prefix + "/api/sandboxes/{name}/acp")
    async def describe(name: str, request: Request):
        principal = await auth.principal(request, app.state.upstream)
        principal.require_user()
        sandbox, snapshot = await asyncio.to_thread(
            private_sandbox, app.state.store, name, principal.owner
        )
        revision = configuration_revision(snapshot, settings)
        hosts = (
            snapshot["definition"]
            .get("agentSandbox", {})
            .get("spec", {})
            .get("podTemplate", {})
            .get("spec", {})
            .get("containers", [])
        )
        declared_env = {
            item.get("name")
            for host in hosts
            if host.get("name") == "host"
            for item in host.get("env", [])
        }
        model_declared = bool(
            declared_env.intersection(
                {
                    "ANTHROPIC_AUTH_TOKEN",
                    "ANTHROPIC_API_KEY",
                    "CLAUDE_CODE_USE_BEDROCK",
                    "AWS_WEB_IDENTITY_TOKEN_FILE",
                }
            )
        )
        admitted = []
        for alias, entry in connections.items.items():
            if entry.owner != principal.owner or entry.sandbox_name != name:
                continue
            current = (
                entry.sandbox_uid == sandbox.uid and entry.policy_revision == revision
            )
            binding = await asyncio.to_thread(
                app.state.store.metadata.acp_binding, entry.sandbox_uid
            )
            admitted.append(
                {
                    "id": alias,
                    "title": entry.title,
                    "admitted": current,
                    "busy": bool(binding and binding["active_run_id"]),
                    "bound_conversation": binding["conversation_id"]
                    if binding
                    else None,
                }
            )
        return JSONResponse(
            {
                "sandbox_uid": sandbox.uid,
                "profile_revision": snapshot["revision"],
                "policy_revision": revision,
                "state": sandbox.state,
                "registration": {
                    "owner": principal.owner,
                    "sandbox_name": name,
                    "sandbox_uid": sandbox.uid,
                    "policy_revision": revision,
                },
                "connections": admitted,
                "message": "Choose your admitted connection in CAIPE Agent Builder."
                if any(row["admitted"] for row in admitted)
                else "Ask an operator to register this private sandbox connection in CAIPE; no credentials are copied from this page.",
                "model_access_note": "The retained profile declares model access. Your operator must verify the model route and authorization before use; registration does not test the provider login."
                if model_declared
                else "Model access has not been verified by this page. Ask your operator to configure and test the approved model route or workload identity before using CAIPE.",
                "policy_note": "This revision identifies the approved profile and namespace configuration. Network/filesystem enforcement belongs to the selected runtime and deployment policy.",
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.websocket(prefix + "/api/acp/connections/{alias}/stdio")
    async def stdio(ws: WebSocket, alias: str):
        conn = None
        token = None
        opened = None
        drained = False
        tasks = []
        try:
            drain.require_accepting()
            entry = connections.authorize(ws, alias)
            await ws.accept()
            raw = await asyncio.wait_for(ws.receive_text(), timeout=10)
            if len(raw.encode()) > MAX_FRAME:
                raise HTTPException(413, "ACP frame exceeds its limit")
            opened = OpenProcess.model_validate_json(raw)
            if any(
                getattr(opened, key) != getattr(entry, key)
                for key in ("sandbox_uid", "owner_subject", "policy_revision")
            ):
                raise HTTPException(
                    409, "ACP connection identity or approved configuration changed"
                )
            sandbox, snapshot = await asyncio.to_thread(
                private_sandbox, app.state.store, entry.sandbox_name, entry.owner
            )
            if (
                sandbox.uid != entry.sandbox_uid
                or configuration_revision(snapshot, settings) != entry.policy_revision
            ):
                raise HTTPException(
                    409, "Sandbox was replaced or its approved configuration changed"
                )
            target = await asyncio.to_thread(
                app.state.store.execution, entry.sandbox_name, entry.owner
            )
            if target.sandbox_uid != entry.sandbox_uid:
                raise HTTPException(409, "Sandbox execution identity changed")
            identity = {key: getattr(opened, key) for key in IDENTITY_KEYS}

            def reserve():
                scope = scope_key(
                    sandbox.record.provider,
                    sandbox.record.provider_instance,
                    sandbox.record.scope,
                )
                with claim(
                    app.state.store.metadata,
                    f"namespace-network/{scope}",
                    seconds=settings.operation_lease_seconds,
                ) as guard:
                    current, current_snapshot = private_sandbox(
                        app.state.store, entry.sandbox_name, entry.owner
                    )
                    if (
                        current.uid != entry.sandbox_uid
                        or current.record.revision != sandbox.record.revision
                        or configuration_revision(current_snapshot, settings)
                        != entry.policy_revision
                    ):
                        raise HTTPException(
                            409, "Sandbox or approved configuration changed"
                        )
                    return app.state.store.metadata.admit_acp(
                        identity,
                        opened.run_id,
                        sandbox_id=current.record.id,
                        expected_revision=current.record.revision,
                        scope_identity=(
                            current.record.provider,
                            current.record.provider_instance,
                            current.record.scope,
                        ),
                        policy_lease=guard.lease,
                    )

            token = await asyncio.to_thread(reserve)
            process = ACPProcess.model_validate(snapshot["definition"]["acp"])
            conn = await attach_exec(
                lambda: connect(
                    target,
                    [
                        "/opt/venv/bin/python",
                        "-I",
                        "/usr/local/lib/sandbox/acp_runner.py",
                    ],
                    stdin=True,
                    tty=False,
                    timeout=15,
                ),
                15,
                run=app.state.terminal_io.run,
            )
            await app.state.terminal_io.run(
                conn.write_stdin,
                json.dumps(
                    {
                        **identity,
                        "type": "start",
                        "run_id": opened.run_id,
                        "process_token": token,
                        "command": process.command,
                        "workspace_root": process.workspace_root,
                    }
                )
                + "\n",
            )
            pending_mcp = set()

            async def output():
                nonlocal drained
                buffer = ""
                while conn.is_open():
                    await app.state.terminal_io.run(conn.update, timeout=0.02)
                    buffer += conn.read_stdout()
                    # stderr is diagnostic only and never interpreted as a receipt.
                    conn.read_stderr()
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if len(line.encode()) > MAX_FRAME:
                            raise HTTPException(
                                502, "ACP runner exceeded its frame limit"
                            )
                        frame = json.loads(line)
                        if not isinstance(frame, dict):
                            raise TypeError("ACP runner frames must be objects")
                        kind = frame.get("type")
                        if kind == "ready":
                            if (
                                frame.get("process_id") != token
                                or frame.get("run_id") != opened.run_id
                                or any(
                                    frame.get(key) != value
                                    for key, value in identity.items()
                                )
                            ):
                                raise HTTPException(
                                    502,
                                    "ACP process receipt does not match its admission",
                                )
                        elif kind == "exit":
                            if (
                                frame.get("process_id") != token
                                or frame.get("run_id") != opened.run_id
                            ):
                                raise HTTPException(
                                    502, "ACP exit receipt does not match its admission"
                                )
                            drained = frame.get("drained") is True
                            if drained:
                                drained = await asyncio.to_thread(
                                    app.state.store.metadata.finish_acp,
                                    entry.sandbox_uid,
                                    opened.run_id,
                                    token,
                                )
                                frame["drained"] = drained
                        elif kind == "mcp_request":
                            key = frame.get("id")
                            if (
                                not isinstance(key, str)
                                or len(key) > 128
                                or key in pending_mcp
                                or len(pending_mcp) >= 8
                                or frame.get("method") != "POST"
                            ):
                                raise HTTPException(502, "Invalid ACP tool request")
                            pending_mcp.add(key)
                            if (
                                len(
                                    base64.b64decode(
                                        frame.get("body", ""), validate=True
                                    )
                                )
                                > MAX_BODY
                            ):
                                raise HTTPException(
                                    502, "ACP tool request exceeds its limit"
                                )
                        elif kind not in {"stdout", "stderr"}:
                            raise HTTPException(502, "Unknown ACP runner frame")
                        await ws.send_json(frame)
                        if kind == "exit":
                            return
                    if len(buffer.encode()) > MAX_FRAME:
                        raise HTTPException(502, "ACP runner exceeded its frame limit")
                    await asyncio.sleep(0.01)

            async def input_():
                while True:
                    raw = await ws.receive_text()
                    if len(raw.encode()) > MAX_FRAME:
                        raise HTTPException(413, "ACP frame exceeds its limit")
                    frame = json.loads(raw)
                    if not isinstance(frame, dict):
                        raise TypeError("ACP client frames must be objects")
                    kind = frame.get("type")
                    if kind == "stdin":
                        if (
                            len(base64.b64decode(frame.get("data", ""), validate=True))
                            > MAX_BODY
                        ):
                            raise HTTPException(413, "ACP input exceeds its limit")
                    elif kind == "mcp_response":
                        if frame.get("id") not in pending_mcp:
                            raise HTTPException(400, "Unknown ACP tool response")
                        pending_mcp.remove(frame["id"])
                        if (
                            len(base64.b64decode(frame.get("body", ""), validate=True))
                            > MAX_BODY
                        ):
                            raise HTTPException(
                                413, "ACP tool response exceeds its limit"
                            )
                    elif kind != "cancel":
                        raise HTTPException(400, "Unknown ACP client frame")
                    await app.state.terminal_io.run(
                        conn.write_stdin, json.dumps(frame) + "\n"
                    )

            async def revalidate():
                while True:
                    await asyncio.sleep(5)
                    drain.require_accepting()
                    current, current_snapshot = await asyncio.to_thread(
                        private_sandbox,
                        app.state.store,
                        entry.sandbox_name,
                        entry.owner,
                    )
                    current_target = await asyncio.to_thread(
                        app.state.store.execution, entry.sandbox_name, entry.owner
                    )
                    if (
                        current.uid != entry.sandbox_uid
                        or current_target.key != target.key
                        or configuration_revision(current_snapshot, settings)
                        != entry.policy_revision
                    ):
                        raise HTTPException(
                            409, "ACP sandbox placement or configuration changed"
                        )

            tasks = [
                asyncio.create_task(output()),
                asyncio.create_task(input_()),
                asyncio.create_task(revalidate()),
            ]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in tasks:
                if task.done():
                    task.result()
        except (
            HTTPException,
            Conflict,
            ValidationError,
            ValueError,
            TypeError,
            KeyError,
            OSError,
            WebSocketException,
        ) as exc:
            with suppress(RuntimeError, WebSocketDisconnect):
                await ws.send_json(
                    {
                        "type": "error",
                        "code": "sandbox_busy"
                        if isinstance(exc, ACPBusy)
                        else "sandbox_bound"
                        if isinstance(exc, ACPBindingConflict)
                        else "sandbox_unavailable",
                        "message": exc.detail
                        if isinstance(exc, HTTPException)
                        else "This conversation's sandbox has an active or unconfirmed process. Reopen it in CAIPE or ask an operator to reconcile it; this attempt did not start another process."
                        if isinstance(exc, ACPBusy)
                        else "ACP connection failed; an admitted process may require reconciliation.",
                        "admitted": token is not None,
                        **(
                            {
                                **{key: getattr(opened, key) for key in IDENTITY_KEYS},
                                "run_id": opened.run_id,
                            }
                            if opened
                            else {}
                        ),
                        "uncertain": token is not None and not drained,
                    }
                )
        except WebSocketDisconnect:
            pass
        except asyncio.CancelledError:
            # Subscriber/process loss remains unconfirmed; cleanup does not release it.
            pass
        finally:
            with CancelScope(shield=True):
                for task in tasks:
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                if conn:
                    # Closing exec never releases a reservation without a drain receipt.
                    with suppress(
                        OSError,
                        RuntimeError,
                        TimeoutError,
                        ValueError,
                        WebSocketException,
                    ):
                        await asyncio.wait_for(
                            app.state.terminal_io.run(
                                conn.write_stdin, '{"type":"cancel"}\n'
                            ),
                            2,
                        )
                    with suppress(
                        OSError,
                        RuntimeError,
                        TimeoutError,
                        ValueError,
                        WebSocketException,
                    ):
                        await asyncio.wait_for(app.state.terminal_io.run(conn.close), 2)
                with suppress(RuntimeError, WebSocketDisconnect):
                    await ws.close()
