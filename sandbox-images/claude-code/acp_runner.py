"""Non-PTY ACP process supervision inside one private coding sandbox.

The authenticated portal supplies the first frame from its approved profile.
No portal, database or caller credentials are needed by this process.
"""

import base64
import ctypes
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_urlsafe
from uuid import uuid4

MAX_FRAME = 1024 * 1024
MAX_BODY = 512 * 1024
MODEL_ENV = {
    "PATH",
    "HOME",
    "LANG",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
}


def protect_supervisor():
    # Same-UID shell tools must not open the runner's framed control pipe via
    # /proc or ptrace it. Killing this process remains an uncertain outcome.
    libc = ctypes.CDLL(None)
    if (
        sys.platform != "linux"
        or libc.prctl(4, 0, 0, 0, 0) != 0
        or libc.prctl(36, 1, 0, 0, 0) != 0
    ):
        raise RuntimeError(
            "ACP supervision requires Linux process protection and subreaping"
        )


class Runner:
    def __init__(self, config, input_stream=None, output_stream=None):
        self.config = config
        self.input = input_stream or sys.stdin.buffer
        self.output = output_stream or sys.stdout.buffer
        self.lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending = {}
        self.cancelled = threading.Event()
        self.process = None
        self.http = None

    def emit(self, message):
        data = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        if len(data) > MAX_FRAME:
            raise ValueError("ACP relay frame exceeds its limit")
        with self.lock:
            self.output.write(data)
            self.output.flush()

    def output_stream(self, stream, kind):
        while chunk := stream.read1(48 * 1024):
            self.emit({"type": kind, "data": base64.b64encode(chunk).decode()})

    def read_input(self):
        try:
            while line := self.input.readline(MAX_FRAME + 1):
                if len(line) > MAX_FRAME:
                    raise ValueError("ACP relay frame exceeds its limit")
                frame = json.loads(line)
                if not isinstance(frame, dict):
                    raise TypeError("ACP input frames must be objects")
                if frame.get("type") == "stdin":
                    data = base64.b64decode(frame["data"], validate=True)
                    if len(data) > MAX_BODY:
                        raise ValueError("ACP input exceeds its limit")
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
                elif frame.get("type") == "mcp_response":
                    with self.pending_lock:
                        item = self.pending.get(frame.get("id"))
                        if item:
                            item[1].append(frame)
                            item[0].set()
                elif frame.get("type") == "cancel":
                    break
                else:
                    raise ValueError("Unknown ACP relay frame")
        except (BrokenPipeError, OSError, ValueError, KeyError, TypeError):
            pass
        finally:
            self.cancelled.set()
            self.signal(signal.SIGTERM)

    def signal(self, sig):
        if self.process is not None:
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                pass

    def mcp_server(self):
        runner = self
        capability = token_urlsafe(32)

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def do_POST(self):
                try:
                    if runner.cancelled.is_set():
                        self.send_error(503)
                        return
                    if (
                        self.headers.get("transfer-encoding")
                        or sum(len(k) + len(v) for k, v in self.headers.items())
                        > 16 * 1024
                    ):
                        self.send_error(400)
                        return
                    length = int(self.headers.get("content-length", "0"))
                    if self.path != "/mcp/" + capability or not 0 < length <= MAX_BODY:
                        self.send_error(400)
                        return
                    content_type = self.headers.get("content-type", "")
                    if (
                        content_type.partition(";")[0].strip().lower()
                        != "application/json"
                    ):
                        self.send_error(415)
                        return
                    body = self.rfile.read(length)
                    if len(body) != length or not isinstance(json.loads(body), dict):
                        self.send_error(400)
                        return
                    request_id = str(uuid4())
                    event, result = threading.Event(), []
                    with runner.pending_lock:
                        if len(runner.pending) >= 8:
                            self.send_error(429)
                            return
                        runner.pending[request_id] = (event, result)
                    try:
                        runner.emit(
                            {
                                "type": "mcp_request",
                                "id": request_id,
                                "method": "POST",
                                "headers": {
                                    key.lower(): self.headers[key]
                                    for key in (
                                        "Content-Type",
                                        "Accept",
                                        "Mcp-Session-Id",
                                        "Mcp-Protocol-Version",
                                        "Authorization",
                                    )
                                    if key in self.headers
                                },
                                "body": base64.b64encode(body).decode(),
                            }
                        )
                        deadline = time.monotonic() + 900
                        while not event.wait(0.2):
                            if (
                                runner.cancelled.is_set()
                                or time.monotonic() >= deadline
                            ):
                                self.send_error(504)
                                return
                        response = result[0]
                        payload = base64.b64decode(response["body"], validate=True)
                        status = response["status"]
                        if (
                            len(payload) > MAX_BODY
                            or type(status) is not int
                            or not 100 <= status <= 599
                        ):
                            self.send_error(502)
                            return
                        self.send_response(status)
                        for key, value in response.get("headers", {}).items():
                            if (
                                key.lower() in {"content-type", "mcp-session-id"}
                                and "\r" not in value
                                and "\n" not in value
                            ):
                                self.send_header(key, value)
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                    finally:
                        with runner.pending_lock:
                            runner.pending.pop(request_id, None)
                except (OSError, ValueError, KeyError, TypeError):
                    self.close_connection = True

            def log_message(self, format, *args):
                # Native stdout is the framed protocol; capabilities are never logged.
                return

        class Server(ThreadingHTTPServer):
            slots = threading.BoundedSemaphore(8)

            def process_request(self, request, client_address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.slots.release()

        self.http = Server(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.http.server_port}/mcp/{capability}"

    def drain(self):
        """Reap adopted descendants, including tools that started a new group."""
        self.signal(signal.SIGTERM)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
            if not children.exists():
                return False
            pids = [int(pid) for pid in children.read_text().split()]
            if not pids:
                return True
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if not pid:
                        break
                except ChildProcessError:
                    break
            time.sleep(0.05)
        return False

    def run(self):
        # Linux subreaping keeps daemonized descendants within this process owner.
        protect_supervisor()
        binding = hashlib.sha256(self.config["binding_id"].encode()).hexdigest()
        root = Path(self.config["workspace_root"]).resolve()
        workspace = root / binding
        workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not workspace.resolve().is_relative_to(root):
            raise ValueError("ACP workspace is outside the admitted root")
        config_dir = workspace / ".claude"
        config_dir.mkdir(mode=0o700, exist_ok=True)
        if not config_dir.resolve().is_relative_to(workspace):
            raise ValueError("ACP native configuration escapes the workspace")
        env = {key: value for key, value in os.environ.items() if key in MODEL_ENV}
        env.update(
            {
                "CLAUDE_CONFIG_DIR": str(config_dir),
                "MCP_TOOL_TIMEOUT": "900000",
                "CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT": "900000",
                "CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS": "0",
            }
        )
        mcp_url = self.mcp_server()
        self.process = subprocess.Popen(
            self.config["command"],
            cwd=workspace,
            env=env,
            start_new_session=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        self.emit(
            {
                "type": "ready",
                "protocol": 1,
                "sandbox_uid": self.config["sandbox_uid"],
                "policy_revision": self.config["policy_revision"],
                "binding_id": self.config["binding_id"],
                "run_id": self.config["run_id"],
                "process_id": self.config["process_token"],
                "owner_subject": self.config["owner_subject"],
                "conversation_id": self.config["conversation_id"],
                "workspace": str(root),
                "cwd": str(workspace),
                "config_dir": str(config_dir),
                "mcp_url": mcp_url,
            }
        )
        outputs = [
            threading.Thread(
                target=self.output_stream, args=(stream, kind), daemon=True
            )
            for stream, kind in (
                (self.process.stdout, "stdout"),
                (self.process.stderr, "stderr"),
            )
        ]
        for thread in outputs:
            thread.start()
        threading.Thread(target=self.read_input, daemon=True).start()
        while self.process.poll() is None:
            if self.cancelled.wait(0.05):
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.signal(signal.SIGKILL)
                break
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            code = None
        self.cancelled.set()
        self.http.shutdown()
        drained = self.drain() if code is not None else False
        for thread in outputs:
            thread.join(timeout=2)
        drained = drained and all(not thread.is_alive() for thread in outputs)
        self.emit(
            {
                "type": "exit",
                "returncode": code,
                "drained": drained,
                "run_id": self.config["run_id"],
                "process_id": self.config["process_token"],
            }
        )
        return 0 if drained else 1


def main():
    protect_supervisor()
    first = sys.stdin.buffer.readline(MAX_FRAME + 1)
    if len(first) > MAX_FRAME:
        raise ValueError("ACP start frame exceeds its limit")
    config = json.loads(first)
    if config.get("type") != "start":
        raise ValueError("Expected approved process configuration")
    return Runner(config).run()


if __name__ == "__main__":
    raise SystemExit(main())
