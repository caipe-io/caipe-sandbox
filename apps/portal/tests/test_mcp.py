"""Real MCP wire/auth tests and live subprocess sessions through a fake provider."""

import asyncio
import json
import logging
import os
import selectors
import subprocess
import sys
import time
from copy import deepcopy
from dataclasses import replace
from uuid import UUID

import httpx
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from mcp.client import ClientSession
from mcp.client.streamable_http import streamable_http_client

from portal.app import create_app
from portal.execution import ExecutionTarget
from portal.mcp.auth import MCPPolicy
from portal.sandboxes import Store
from portal.namespaces import UserNamespaces
from portal.storage import MCPConfiguration
from test_portal import HEADERS, OWNER, OTHER, SETTINGS, Kubernetes, Omnigent

URL = "http://localhost/agent-sandbox-portal/api/mcp"
ISSUER = "http://localhost/issuer"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC = {
    **jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True),
    "kid": "test",
    "use": "sig",
}


def access(email=OWNER, **changes):
    claims = {
        "iss": ISSUER,
        "aud": URL,
        "sub": email,
        "email": email,
        "email_verified": True,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "scope": "sandbox:read sandbox:exec",
        **changes,
    }
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "test"})


class LocalExecution:
    """Exec adapter for tests only; launches no network, SSH or tunnel server."""

    def __init__(self, command, **kwargs):
        self.process = subprocess.Popen(
            [sys.executable, *command[1:]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.selector = selectors.DefaultSelector()
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        for name in self.buffers:
            stream = getattr(self.process, name)
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def write_stdin(self, data):
        self.process.stdin.write(data.encode())
        self.process.stdin.flush()

    def is_open(self):
        return self.process.poll() is None

    def update(self, timeout=0):
        for key, _ in self.selector.select(timeout):
            data = os.read(key.fd, 65536)
            if data:
                self.buffers[key.data].extend(data)
            else:
                self.selector.unregister(key.fileobj)

    def read_stdout(self, timeout=0):
        self.update(0)
        data = bytes(self.buffers["stdout"])
        self.buffers["stdout"].clear()
        return data.decode(errors="replace")

    def read_stderr(self, timeout=0):
        self.update(0)
        data = bytes(self.buffers["stderr"])
        self.buffers["stderr"].clear()
        return data.decode(errors="replace")

    @property
    def returncode(self):
        return self.process.poll()

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.selector.close()
        self.process.stdout.close()
        self.process.stderr.close()


def fixture_app(**changes):
    policy = {
        "enabled": True,
        "resource_url": URL,
        "issuer": ISSUER,
        "jwks_url": "http://localhost/jwks",
        "foreground_wait_seconds": 1,
        **changes,
    }
    settings = replace(
        SETTINGS,
        origin="http://localhost",
        session_secret="test-session-secret-" * 3,
        mcp_policy=json.dumps(policy),
        reconcile_interval_seconds=0,
    )
    kube = Kubernetes()
    store = Store(
        settings,
        custom=kube,
        core=kube,
        namespaces=UserNamespaces(settings, kube, kube, kube),
        metadata=kube.metadata,
    )
    sandbox = store.create(OWNER)
    identity = str(sandbox.record.id)
    store.configure_mcp(
        identity, OWNER, MCPConfiguration(enabled=True), sandbox.record.revision
    )
    created = []

    def execution(sandbox, **kwargs):
        def connector(command, **options):
            stream = LocalExecution(command, **options)
            created.append(stream)
            return stream

        return ExecutionTarget(
            ("test", identity), sandbox.scope, sandbox.uid, connector
        )

    store.integrations.execution = execution
    app = create_app(settings, store, Omnigent())
    original = app.state.mcp.verifier
    original.client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"keys": [PUBLIC]})
        )
    )
    return app, store, kube, identity, created


async def call_client(app, bearer, fn):
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        headers={"Authorization": "Bearer " + bearer},
    ) as http:
        async with streamable_http_client(URL, http_client=http) as (read, write):
            async with ClientSession(read, write) as client:
                return await fn(client)


def test_standard_client_foreground_background_output_and_cancel(caplog):
    caplog.set_level(logging.INFO)

    async def scenario():
        app, store, kube, identity, created = fixture_app()
        async with app.router.lifespan_context(app):

            async def workflow(client):
                await client.initialize()
                tools = await client.list_tools()
                assert {t.name for t in tools.tools} == {
                    "list_sandboxes",
                    "get_sandbox",
                    "run_command",
                    "read_execution",
                    "cancel_execution",
                }
                listing = await client.call_tool("list_sandboxes", {})
                assert (
                    listing.structured_content["sandboxes"][0]["sandbox_id"] == identity
                )
                done = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "printf 'hello'; printf 'problem' >&2; exit 7",
                    },
                )
                assert not done.is_error
                d = done.structured_content
                assert (
                    d["sandbox_id"],
                    d["state"],
                    d["stdout"],
                    d["stderr"],
                    d["exit_code"],
                ) == (identity, "completed", "hello", "problem", 7)
                started = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "printf 'started'; sleep 30",
                        "run_in_background": True,
                    },
                )
                s = started.structured_content
                assert s["sandbox_id"] == identity and s["session_id"]
                read = await client.call_tool(
                    "read_execution",
                    {"sandbox_id": identity, "session_id": s["session_id"]},
                )
                assert read.structured_content["sandbox_id"] == identity
                cancelled = await client.call_tool(
                    "cancel_execution",
                    {"sandbox_id": identity, "session_id": s["session_id"]},
                )
                assert cancelled.structured_content["cancel_requested"]
                for _ in range(60):
                    end = await client.call_tool(
                        "read_execution",
                        {
                            "sandbox_id": identity,
                            "session_id": s["session_id"],
                            "cursor": read.structured_content["next_cursor"],
                            "wait_ms": 100,
                        },
                    )
                    if end.structured_content["state"] == "completed":
                        break
                    read = end
                assert end.structured_content["state"] == "completed"
                assert end.structured_content["exit_code"] != 0
                assert len(created) == 2

            await call_client(app, access(), workflow)

    asyncio.run(scenario())
    events = [
        getattr(record, "event_fields", {})
        for record in caplog.records
        if record.message == "mcp_execution"
    ]
    assert events and all(
        event["sandbox_id"] and event["session_id"] for event in events
    )
    assert all(
        event["actor"] == OWNER and event["client_id"] == OWNER for event in events
    )
    assert any(
        event["outcome"] == "completed" and event["duration_ms"] >= 0
        for event in events
    )
    assert "printf 'hello'" not in caplog.text and "printf 'started'" not in caplog.text


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "https://another.example/mcp"},
        {"iss": "https://wrong.example"},
        {"exp": 1},
        {"email_verified": False},
        {"sub": ""},
        {"scope": "unrelated"},
    ],
)
def test_invalid_tokens_fail_closed_without_browser_fallback(changes):
    app, *_ = fixture_app()
    with TestClient(app) as browser:
        response = browser.post(
            URL,
            headers={
                "Authorization": "Bearer " + access(**changes),
                "Cookie": "session=alice",
            },
            json={},
        )
        assert response.status_code in {401, 403}
        assert "resource_metadata" in response.headers["www-authenticate"]


def test_discovery_and_missing_bearer():
    app, *_ = fixture_app()
    with TestClient(app) as browser:
        metadata = browser.get(
            "http://localhost/.well-known/oauth-protected-resource/agent-sandbox-portal/api/mcp"
        )
        assert metadata.status_code == 200 and metadata.json()["resource"] == URL
        assert (
            browser.post(URL, headers={"Cookie": "session=alice"}, json={}).status_code
            == 401
        )


def test_sharing_opt_in_immutable_ids_and_role_checks():
    async def scenario():
        app, store, kube, identity, created = fixture_app()
        async with app.router.lifespan_context(app):
            record = store.metadata.get_sandbox(UUID(identity))
            store.metadata.set_scope_grants(
                record.id, {OTHER: "view"}, expected_revision=record.revision
            )

            async def denied(client):
                await client.initialize()
                response = await client.call_tool(
                    "run_command", {"sandbox_id": identity, "command": "echo forbidden"}
                )
                assert (
                    response.is_error
                    and response.structured_content["sandbox_id"] == identity
                )
                assert response.structured_content["next_action"]

            await call_client(app, access(OTHER), denied)
            record = store.metadata.get_sandbox(UUID(identity))
            store.metadata.set_scope_grants(
                record.id, {OTHER: "shell"}, expected_revision=record.revision
            )

            async def allowed(client):
                await client.initialize()
                response = await client.call_tool(
                    "run_command", {"sandbox_id": identity, "command": "printf shared"}
                )
                assert response.structured_content["stdout"] == "shared"

            await call_client(app, access(OTHER), allowed)
            record = store.metadata.get_sandbox(UUID(identity))
            store.configure_mcp(
                identity, OWNER, MCPConfiguration(enabled=False), record.revision
            )
            await call_client(app, access(OWNER), denied)
            assert len(created) == 1

    asyncio.run(scenario())


def test_portal_owner_confirmation_api_revision_and_no_native_mutation():
    app, store, kube, identity, _ = fixture_app()
    before = deepcopy(kube.items)
    with TestClient(app) as browser:
        record = store.metadata.get_sandbox(UUID(identity))
        url = SETTINGS.base_path + "/api/sandboxes/" + identity + "/mcp"
        response = browser.put(
            url,
            headers={**HEADERS, "Origin": "http://localhost"},
            json={"revision": record.revision, "mcp": {"enabled": False}},
        )
        assert response.status_code == 200 and response.json()["mcp"] == {
            "enabled": False
        }
        stale = browser.put(
            url,
            headers={**HEADERS, "Origin": "http://localhost"},
            json={"revision": record.revision, "mcp": {"enabled": True}},
        )
        assert stale.status_code == 409
        forbidden = browser.put(
            url,
            headers={"Cookie": "session=bob", "Origin": "http://localhost"},
            json={"revision": record.revision + 1, "mcp": {"enabled": True}},
        )
        assert forbidden.status_code == 404
    assert kube.items == before


@pytest.mark.parametrize(
    "change",
    [
        {"algorithms": ["HS256"]},
        {"resource_url": "http://remote.example/mcp"},
        {"issuer": "https://user:pass@idp.example"},
        {"execute_scope": 'bad"scope'},
    ],
)
def test_operator_configuration_is_strict(change):
    with pytest.raises(ValueError):
        MCPPolicy.model_validate(
            {
                "enabled": True,
                "resource_url": URL,
                "issuer": ISSUER,
                "jwks_url": "http://localhost/jwks",
                **change,
            }
        )
