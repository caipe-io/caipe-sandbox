"""Failure/recovery contract: immutable targets, live output and no launch replay."""

import asyncio
import json
import time
from uuid import UUID, uuid4

import httpx
from fastapi.testclient import TestClient

from portal.mcp.sessions import Session
from portal.storage import MCPConfiguration
from test_mcp import access, call_client, fixture_app
from test_portal import OTHER, OWNER, SETTINGS


def test_every_targeted_result_and_error_retains_both_ids():
    async def scenario():
        app, _, _, identity, _ = fixture_app()
        async with app.router.lifespan_context(app):

            async def workflow(client):
                await client.initialize()
                for name, args in [
                    ("get_sandbox", {}),
                    ("run_command", {"command": ""}),
                    (
                        "run_command",
                        {"command": "echo wrong", "timeout_seconds": 100000},
                    ),
                    ("read_execution", {"session_id": "missing"}),
                    ("read_execution", {"session_id": "missing", "cursor": -1}),
                    ("cancel_execution", {"session_id": "missing"}),
                ]:
                    response = await client.call_tool(
                        name, {"sandbox_id": identity, **args}
                    )
                    assert response.structured_content is not None, (
                        name,
                        response.content,
                    )
                    assert response.structured_content["sandbox_id"] == identity
                    assert (
                        json.loads(response.content[0].text)
                        == response.structured_content
                    )
                    if "session_id" in args:
                        assert (
                            response.structured_content["session_id"]
                            == args["session_id"]
                        )
                    if name != "get_sandbox":
                        assert (
                            response.is_error
                            and response.structured_content["next_action"]
                        )
                for target in (str(uuid4()), "not-an-id"):
                    response = await client.call_tool(
                        "get_sandbox", {"sandbox_id": target}
                    )
                    assert (
                        response.is_error
                        and response.structured_content["sandbox_id"] == target
                    )

            await call_client(app, access(), workflow)

    asyncio.run(scenario())


def test_foreground_handoff_stdin_cwd_deadline_and_bounded_output(tmp_path):
    async def scenario():
        app, _, _, identity, created = fixture_app(output_bytes=4096)
        async with app.router.lifespan_context(app):

            async def workflow(client):
                await client.initialize()
                response = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "pwd; cat; sleep 2; printf done",
                        "cwd": str(tmp_path),
                        "stdin": "héllo\n",
                    },
                )
                data = response.structured_content
                assert data["state"] in {"starting", "running"}
                output = data["stdout"]
                while data["state"] in {"starting", "running"}:
                    response = await client.call_tool(
                        "read_execution",
                        {
                            "sandbox_id": identity,
                            "session_id": data["session_id"],
                            "cursor": data["next_cursor"],
                        },
                    )
                    data = response.structured_content
                    output += data["stdout"]
                assert str(tmp_path) in output
                assert (
                    "héllo" in output and output.endswith("done") and len(created) == 1
                )
                for _ in range(2):
                    reread = await client.call_tool(
                        "read_execution",
                        {
                            "sandbox_id": identity,
                            "session_id": data["session_id"],
                            "cursor": 0,
                        },
                    )
                    assert reread.structured_content["stdout"] == output
                large = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "python3 -c 'print(\"x\"*15000)'",
                    },
                )
                assert large.structured_content["truncated"]
                assert len(large.structured_content["stdout"].encode()) <= 4096
                timeout = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "sleep 10",
                        "timeout_seconds": 1,
                    },
                )
                data = timeout.structured_content
                while data["state"] in {"starting", "running"}:
                    timeout = await client.call_tool(
                        "read_execution",
                        {
                            "sandbox_id": identity,
                            "session_id": data["session_id"],
                            "cursor": data["next_cursor"],
                        },
                    )
                    data = timeout.structured_content
                assert data["exit_code"] == 124

            await call_client(app, access(), workflow)

    asyncio.run(scenario())


def test_capacity_rejection_no_replay_and_opt_out_ends_active_attachment():
    async def scenario():
        app, store, _, identity, created = fixture_app(max_sessions=1)
        async with app.router.lifespan_context(app):

            async def workflow(client):
                await client.initialize()
                first = await client.call_tool(
                    "run_command",
                    {
                        "sandbox_id": identity,
                        "command": "sleep 30",
                        "run_in_background": True,
                    },
                )
                second = await client.call_tool(
                    "run_command",
                    {"sandbox_id": identity, "command": "echo must-not-run"},
                )
                assert (
                    second.is_error
                    and second.structured_content["code"] == "CAPACITY_EXCEEDED"
                )
                assert (
                    second.structured_content["sandbox_id"] == identity
                    and len(created) <= 1
                )
                record = store.metadata.get_sandbox(UUID(identity))
                store.configure_mcp(
                    identity, OWNER, MCPConfiguration(enabled=False), record.revision
                )
                session = next(iter(app.state.mcp.sessions.sessions.values()))
                for _ in range(100):
                    if (
                        session.state == "unknown"
                        and created[0].process.poll() is not None
                    ):
                        break
                    await asyncio.sleep(0.05)
                assert len(created) == 1 and created[0].process.poll() is not None
                response = await client.call_tool(
                    "read_execution",
                    {
                        "sandbox_id": identity,
                        "session_id": first.structured_content["session_id"],
                    },
                )
                assert (
                    response.is_error
                    and response.structured_content["sandbox_id"] == identity
                )

            await call_client(app, access(), workflow)

    asyncio.run(scenario())


def test_peer_authentication_wrong_caller_and_restart_never_replay():
    app, store, _, identity, _ = fixture_app()
    with TestClient(app) as browser:
        sessions = app.state.mcp.sessions
        key = str(uuid4())
        handle = sessions.signer.dumps(
            {"instance": sessions.instance, "address": "127.0.0.1", "key": key}
        )
        session = Session(
            OWNER, OWNER, identity, "native", "test", handle, time.monotonic() + 10
        )
        session.state, session.exit_code = "completed", 0
        sessions.sessions[key] = session
        sessions._append(session, "stdout", "retained")
        url = SETTINGS.base_path + "/api/mcp-session/read"
        body = {"sandbox_id": identity, "session_id": handle}
        assert browser.post(url, json=body).status_code == 401
        response = browser.post(
            url, json=body, headers={"Authorization": "Bearer " + access()}
        )
        assert (
            response.json()["stdout"] == "retained"
            and response.json()["sandbox_id"] == identity
        )
        record = store.metadata.get_sandbox(UUID(identity))
        store.metadata.set_scope_grants(
            record.id, {OTHER: "shell"}, expected_revision=record.revision
        )
        forbidden = browser.post(
            url, json=body, headers={"Authorization": "Bearer " + access(OTHER)}
        )
        assert forbidden.json()["code"] == "SESSION_UNAVAILABLE"
        del sessions.sessions[key]
        lost = browser.post(
            url, json=body, headers={"Authorization": "Bearer " + access()}
        )
        assert (
            lost.json()["code"] == "SESSION_LOST"
            and lost.json()["sandbox_id"] == identity
        )


def test_unicode_output_truncation_always_advances_the_cursor():
    app, _, _, identity, _ = fixture_app(output_bytes=4096)
    with TestClient(app):
        sessions = app.state.mcp.sessions
        session = Session(
            OWNER, OWNER, identity, "native", "test", "session", time.monotonic() + 10
        )
        sessions._append(session, "stdout", "🙂" * 15000)
        data = sessions.snapshot(session)
        assert data["truncated"] and data["stdout"]
        assert len(data["stdout"].encode()) <= 4096
        assert data["next_cursor"] > 0 and not data["has_more"]
        session.chunks.clear()
        empty = sessions.snapshot(session)
        assert empty["next_cursor"] == data["next_cursor"] and not empty["has_more"]


def test_replica_forwarding_only_uses_signed_peer_and_never_replays_launch(monkeypatch):
    async def scenario():
        app, _, _, identity, created = fixture_app()
        async with app.router.lifespan_context(app):
            sessions = app.state.mcp.sessions
            handle = sessions.signer.dumps(
                {
                    "instance": "other-replica",
                    "address": "127.0.0.2",
                    "key": str(uuid4()),
                }
            )
            captured = []

            async def peer(request):
                captured.append(request)
                return httpx.Response(
                    200,
                    json={
                        "sandbox_id": identity,
                        "session_id": handle,
                        "state": "completed",
                        "stdout": "from-owning-replica",
                        "stderr": "",
                        "exit_code": 0,
                    },
                )

            real_client = httpx.AsyncClient
            monkeypatch.setattr(
                "portal.mcp.sessions.httpx.AsyncClient",
                lambda **kwargs: real_client(
                    transport=httpx.MockTransport(peer), **kwargs
                ),
            )

            async def workflow(client):
                await client.initialize()
                result = await client.call_tool(
                    "read_execution", {"sandbox_id": identity, "session_id": handle}
                )
                assert result.structured_content["stdout"] == "from-owning-replica"
                assert (
                    str(captured[0].url)
                    == "http://127.0.0.2:8000/agent-sandbox-portal/api/mcp-session/read"
                )
                assert captured[0].headers["authorization"].startswith("Bearer ")
                assert not created
                tampered = await client.call_tool(
                    "cancel_execution",
                    {"sandbox_id": identity, "session_id": handle + "tampered"},
                )
                assert (
                    tampered.is_error
                    and tampered.structured_content["sandbox_id"] == identity
                )
                assert len(captured) == 1

            await call_client(app, access(), workflow)

    asyncio.run(scenario())
