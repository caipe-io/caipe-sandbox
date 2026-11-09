"""Exercise the real Linux supervisor, not a mocked drain response."""

import base64
import hashlib
import json
import os
import select
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux process boundaries"
)
RUNNER = Path(__file__).resolve().parents[3] / "sandbox-images/claude-code/acp_runner.py"


def read_frame(process):
    assert select.select([process.stdout], [], [], 15)[0], "runner did not respond"
    return json.loads(process.stdout.readline())


def launch(tmp_path, command):
    process = subprocess.Popen(
        [sys.executable, "-I", str(RUNNER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    config = {
        "type": "start",
        "binding_id": "binding",
        "conversation_id": "conversation",
        "owner_subject": "user",
        "workspace_root": str(tmp_path),
        "command": command,
        "sandbox_uid": "sandbox-uid",
        "policy_revision": "sha256:" + "a" * 64,
        "run_id": "run",
        "process_token": "process-token",
    }
    process.stdin.write(json.dumps(config).encode() + b"\n")
    process.stdin.flush()
    ready = read_frame(process)
    assert ready["type"] == "ready"
    assert ready["workspace"] == str(tmp_path)
    assert ready["cwd"] == str(tmp_path / hashlib.sha256(b"binding").hexdigest())
    return process


def test_supervisor_control_pipe_is_not_accessible_to_same_uid_child(tmp_path):
    code = """import os,time
try:
    fd=os.open('/proc/'+str(os.getppid())+'/fd/1',os.O_WRONLY)
except PermissionError:
    print('protected',flush=True)
else:
    print('EXPOSED',flush=True)
time.sleep(60)
"""
    process = launch(tmp_path, [sys.executable, "-u", "-c", code])
    try:
        output = bytearray()
        while b"\n" not in output:
            frame = read_frame(process)
            assert frame["type"] == "stdout"
            output.extend(base64.b64decode(frame["data"]))
        assert bytes(output) == b"protected\n"
        process.stdin.write(b'{"type":"cancel"}\n')
        process.stdin.flush()
        final = read_frame(process)
        assert final["type"] == "exit" and final["drained"] is True
        assert final["run_id"] == "run" and final["process_id"] == "process-token"
        assert process.wait(timeout=15) == 0
    finally:
        process.kill()
        process.wait()


def test_cancel_reaps_a_tool_that_detached_into_another_session(tmp_path):
    code = """import os,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
print(child.pid,flush=True)
time.sleep(60)
"""
    process = launch(tmp_path, [sys.executable, "-u", "-c", code])
    try:
        output = bytearray()
        while b"\n" not in output:
            frame = read_frame(process)
            assert frame["type"] == "stdout"
            output.extend(base64.b64decode(frame["data"]))
        child = int(bytes(output).splitlines()[0])
        process.stdin.write(b'{"type":"cancel"}\n')
        process.stdin.flush()
        while True:
            frame = read_frame(process)
            if frame["type"] == "exit":
                break
            assert frame["type"] in {"stdout", "stderr"}
        assert frame["drained"] is True
        assert frame["run_id"] == "run" and frame["process_id"] == "process-token"
        process.wait(timeout=15)
        with pytest.raises(ProcessLookupError):
            os.kill(child, 0)
    finally:
        process.kill()
        process.wait()
