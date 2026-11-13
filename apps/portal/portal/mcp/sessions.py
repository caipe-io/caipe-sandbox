"""Bounded live exec sessions. Handles route to their owning replica, never replay."""

import asyncio
import hashlib
import ipaddress
import json
import queue
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import httpx
from itsdangerous import BadData, URLSafeTimedSerializer

from ..execution import connect
from ..telemetry import event

RUNNER = Path(__file__).with_name("runner.py").read_text()


class ToolFailure(Exception):
    def __init__(self, code, message, next_action, **fields):
        self.result = {
            "code": code,
            "message": message,
            "next_action": next_action,
            "retryable": False,
            **fields,
        }


@dataclass
class Session:
    actor: str
    subject: str
    sandbox_id: str
    native_uid: str
    display_name: str
    handle: str
    expires: float
    client_id: str = ""
    started: float = field(default_factory=time.monotonic)
    chunks: deque = field(default_factory=deque)
    cursor: int = 0
    retained: int = 0
    state: str = "starting"
    exit_code: int | None = None
    cancel_requested: bool = False
    error: str = ""
    updated: float = field(default_factory=time.monotonic)
    controls: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=1))
    lock: threading.Lock = field(default_factory=threading.Lock)


class Sessions:
    def __init__(self, settings, policy, store, drain):
        self.policy, self.store, self.drain = policy, store, drain
        self.instance = settings.pod_uid or str(uuid4())
        self.address = (
            str(ipaddress.ip_address(settings.pod_ip)) if settings.pod_ip else ""
        )
        self.signer = URLSafeTimedSerializer(
            settings.session_secret,
            salt="sandbox-mcp-execution-v1",
            signer_kwargs={"digest_method": hashlib.sha256},
        )
        self.pool = ThreadPoolExecutor(
            max_workers=policy.max_sessions, thread_name_prefix="portal-mcp"
        )
        self.sessions = {}
        self.closed = False

    def _prune(self):
        for key, session in list(self.sessions.items()):
            if (
                session.state not in {"starting", "running"}
                and time.monotonic() - session.updated > self.policy.retention_seconds
            ):
                del self.sessions[key]
        completed = [
            key
            for key, s in self.sessions.items()
            if s.state not in {"starting", "running"}
        ]
        for key in completed[
            : max(0, len(self.sessions) - self.policy.max_sessions * 4)
        ]:
            del self.sessions[key]

    def full(self):
        return (
            sum(s.state in {"starting", "running"} for s in self.sessions.values())
            >= self.policy.max_sessions
        )

    def decode(self, handle):
        try:
            record = self.signer.loads(
                handle,
                max_age=self.policy.max_timeout_seconds
                + self.policy.retention_seconds
                + 30,
            )
            if set(record) != {"instance", "address", "key"} or any(
                not isinstance(v, str) for v in record.values()
            ):
                raise ValueError()
            if record["address"]:
                ipaddress.ip_address(record["address"])
            return record
        except (BadData, ValueError, TypeError, KeyError):
            raise ToolFailure(
                "SESSION_UNAVAILABLE",
                "This execution session is invalid or expired.",
                "Check the same sandbox before starting another command; a lost session does not prove the command stopped.",
            ) from None

    async def start(
        self,
        actor,
        subject,
        sandbox_id,
        command,
        cwd,
        stdin,
        timeout_seconds,
        *,
        client_id="",
    ):
        self.drain.require_accepting()
        self._prune()
        if self.closed or self.full():
            raise ToolFailure(
                "CAPACITY_EXCEEDED",
                "MCP session capacity is full; this command did not start.",
                "Wait for another session to finish, then retry.",
                retryable=True,
                retry_after_seconds=2,
                execution_state="not_started",
            )
        sandbox = await asyncio.to_thread(
            self.store.mcp_sandbox, sandbox_id, actor, shell=True
        )
        target = await asyncio.to_thread(
            self.store.execution, sandbox_id, actor, sandbox.owner
        )
        # Reserve before the next await so concurrent calls cannot oversubscribe the pool.
        self._prune()
        if self.closed or self.full():
            raise ToolFailure(
                "CAPACITY_EXCEEDED",
                "MCP session capacity is full; this command did not start.",
                "Retry later.",
                retryable=True,
                execution_state="not_started",
            )
        key = str(uuid4())
        handle = self.signer.dumps(
            {"instance": self.instance, "address": self.address, "key": key}
        )
        session = Session(
            actor,
            subject,
            sandbox_id,
            target.sandbox_uid,
            sandbox.title,
            handle,
            time.monotonic() + timeout_seconds + 10,
            client_id=client_id,
        )
        self.sessions[key] = session
        self.pool.submit(
            self._drive,
            session,
            target,
            {
                "command": command,
                "cwd": cwd,
                "stdin": stdin,
                "timeout_seconds": timeout_seconds,
            },
        )
        return session

    def _append(self, session, stream, text):
        if not text:
            return
        # Split native output so polling never has to skip an oversized chunk.
        for start in range(0, len(text), 1024):
            chunk = text[start : start + 1024]
            size = len(chunk.encode())
            session.cursor += 1
            session.chunks.append((session.cursor, stream, chunk, size))
            session.retained += size
            while session.retained > self.policy.output_bytes:
                session.retained -= session.chunks.popleft()[3]

    def _drive(self, session, target, body):
        connection = None
        audit_id = self.decode(session.handle)["key"]
        event(
            "mcp_execution",
            category="audit",
            actor=session.actor,
            sandbox_id=session.sandbox_id,
            session_id=audit_id,
            outcome="starting",
            client_id=session.client_id,
            action="run_command",
        )
        try:
            connection = connect(
                target,
                ["python3", "-u", "-c", RUNNER],
                stdin=True,
                tty=False,
                timeout=10,
            )
            connection.write_stdin(json.dumps(body, ensure_ascii=False) + "\n")
            with session.lock:
                session.state = "running"
            checked = time.monotonic()
            while connection.is_open():
                if (
                    time.monotonic() >= session.expires
                    or self.closed
                    or self.drain.remaining() == 0
                ):
                    raise OSError("Session attachment ended")
                if time.monotonic() - checked >= 2:
                    sandbox = self.store.mcp_sandbox(
                        session.sandbox_id, session.actor, shell=True
                    )
                    if sandbox.uid != session.native_uid:
                        raise OSError("Native sandbox identity changed")
                    checked = time.monotonic()
                try:
                    message = session.controls.get_nowait()
                    connection.write_stdin(json.dumps(message) + "\n")
                except queue.Empty:
                    pass
                connection.update(timeout=0.2)
                with session.lock:
                    self._append(session, "stdout", connection.read_stdout(timeout=0))
                    self._append(session, "stderr", connection.read_stderr(timeout=0))
            with session.lock:
                self._append(session, "stdout", connection.read_stdout(timeout=0))
                self._append(session, "stderr", connection.read_stderr(timeout=0))
                session.exit_code = connection.returncode
                session.state = (
                    "completed" if session.exit_code is not None else "unknown"
                )
        except Exception:
            with session.lock:
                session.state = "unknown"
                session.error = "The execution attachment was interrupted; completion is unconfirmed."
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            session.updated = time.monotonic()
            event(
                "mcp_execution",
                category="audit",
                actor=session.actor,
                sandbox_id=session.sandbox_id,
                session_id=audit_id,
                outcome=session.state,
                exit_code=session.exit_code,
                client_id=session.client_id,
                action="run_command",
                duration_ms=round((time.monotonic() - session.started) * 1000),
            )

    def local(self, actor, subject, sandbox_id, handle):
        record = self.decode(handle)
        session = self.sessions.get(record["key"])
        if record["instance"] != self.instance or session is None:
            raise ToolFailure(
                "SESSION_LOST",
                "This live session has expired, been evicted or lost its owning portal process.",
                "Inspect the same sandbox before repeating the command; it may have run.",
                execution_state="unknown",
            )
        if (session.actor, session.subject, session.sandbox_id) != (
            actor,
            subject,
            sandbox_id,
        ):
            raise ToolFailure(
                "SESSION_UNAVAILABLE",
                "This session is unavailable to this caller and sandbox.",
                "Use the IDs returned by your own run_command call.",
            )
        self._prune()
        if record["key"] not in self.sessions:
            raise ToolFailure(
                "SESSION_EXPIRED",
                "The completed session's output has expired.",
                "Inspect the sandbox's files; do not automatically rerun commands to recover output.",
            )
        return session

    def snapshot(self, session, cursor=0):
        with session.lock:
            if cursor > session.cursor:
                raise ToolFailure(
                    "INVALID_CURSOR",
                    "Output cursor is ahead of this session.",
                    "Use the next_cursor returned for this sandbox and session.",
                )
            stdout, stderr, size, end = [], [], 0, cursor
            first = session.chunks[0][0] if session.chunks else session.cursor + 1
            end = max(cursor, first - 1)
            for position, stream, text, count in session.chunks:
                if position <= cursor:
                    continue
                if size + count > 65536:
                    break
                (stdout if stream == "stdout" else stderr).append(text)
                size += count
                end = position
            state = session.state
            return {
                "sandbox_id": session.sandbox_id,
                "display_name": session.display_name,
                "session_id": session.handle,
                "state": state,
                "stdout": "".join(stdout),
                "stderr": "".join(stderr),
                "exit_code": session.exit_code,
                "next_cursor": end,
                "has_more": end < session.cursor,
                "truncated": cursor < first - 1,
                "cancel_requested": session.cancel_requested,
                "output_retention_seconds": self.policy.retention_seconds,
                "next_action": "Read this same session with next_cursor; do not rerun the command."
                if state in {"starting", "running"}
                else "Completion is unconfirmed. Inspect this same sandbox before repeating the command."
                if state == "unknown"
                else "The command exited. Use exit_code, stdout and stderr to assess the result.",
            }

    async def read(self, session, cursor, wait_seconds):
        deadline = time.monotonic() + wait_seconds
        while (
            session.state in {"starting", "running"}
            and session.cursor <= cursor
            and time.monotonic() < deadline
        ):
            await asyncio.sleep(0.05)
        return self.snapshot(session, cursor)

    async def foreground(self, session):
        deadline = time.monotonic() + self.policy.foreground_wait_seconds
        while session.state in {"starting", "running"} and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return self.snapshot(session)

    def cancel(self, session):
        with session.lock:
            if (
                session.state in {"starting", "running"}
                and not session.cancel_requested
            ):
                session.controls.put_nowait({"action": "cancel"})
                session.cancel_requested = True
        return self.snapshot(session)

    async def forward(self, record, handle, sandbox_id, action, body, token):
        if not record["address"]:
            raise ToolFailure(
                "SESSION_LOST",
                "This execution belongs to another unavailable portal process.",
                "Inspect the same sandbox before rerunning anything.",
                execution_state="unknown",
            )
        address = ipaddress.ip_address(record["address"])
        host = f"[{address}]" if address.version == 6 else str(address)
        # Only a server-signed handle can choose the peer; callers cannot supply URLs.
        url = f"http://{host}:8000{body.pop('_path')}/api/mcp-session/{action}"
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.post(
                    url,
                    headers={"Authorization": "Bearer " + token},
                    json={"sandbox_id": sandbox_id, "session_id": handle, **body},
                )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError):
            raise ToolFailure(
                "SESSION_UNREACHABLE",
                "The replica holding this live session could not be reached.",
                "Retry reading the same session. Do not launch the command again; its outcome is unconfirmed.",
                retryable=True,
                execution_state="unknown",
            ) from None

    async def close(self):
        for session in self.sessions.values():
            self.cancel(session)
        await asyncio.sleep(0.3)
        self.closed = True
        await asyncio.to_thread(self.pool.shutdown, wait=True, cancel_futures=True)
