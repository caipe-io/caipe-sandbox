"""Process lifecycle checks with real Linux signal restrictions and owned children."""

import json
import platform
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from portal.mcp import runner

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux /proc and seccomp"
)

# Additional filter in the child only; the host/container's existing policy remains active.
FILTER = r"""
import ctypes, os, platform, runpy, sys
class Instruction(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Instruction))]
nr = {'x86_64': 62, 'aarch64': 129}[platform.machine()]
items = (Instruction * 6)(
    Instruction(0x20,0,0,0), Instruction(0x15,0,3,nr),
    Instruction(0x20,0,0,16), Instruction(0x45,0,1,1 << 31),
    Instruction(0x06,0,0,0x00050001), Instruction(0x06,0,0,0x7fff0000))
program = Program(len(items), items)
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(38,1,0,0,0) == 0
assert libc.prctl(22,2,ctypes.byref(program),0,0) == 0
runpy.run_path(sys.argv[1], run_name='__main__')
"""


def launch(command, *, restricted, timeout=15):
    if restricted and platform.machine() not in {"x86_64", "aarch64"}:
        pytest.skip("No seccomp test syscall number for this architecture")
    args = [sys.executable, "-u"]
    args += ["-c", FILTER, runner.__file__] if restricted else [runner.__file__]
    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    process.stdin.write(
        json.dumps({"command": command, "timeout_seconds": timeout}) + "\n"
    )
    process.stdin.flush()
    return process


def collect(process):
    try:
        process.wait(timeout=10)
        return process.returncode, process.stdout.read(), process.stderr.read()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def child_pid(path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return int(path.read_text())
        time.sleep(0.02)
    pytest.fail("Command did not publish its child PID")


@pytest.mark.parametrize("restricted", [False, True])
def test_completed_command_keeps_stdout_stderr_and_exit_code(restricted):
    code, out, err = collect(
        launch("printf out; printf err >&2; exit 7", restricted=restricted)
    )
    assert (code, out, err) == (7, "out", "err")


@pytest.mark.parametrize("restricted", [False, True])
def test_cancel_stops_owned_children_and_preserves_unrelated_process(
    tmp_path, restricted
):
    path = tmp_path / "child"
    sibling = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    process = launch(f"sleep 15 & echo $! > '{path}'; wait", restricted=restricted)
    try:
        pid = child_pid(path)
        process.stdin.write('{"action":"cancel"}\n')
        process.stdin.flush()
        code, _, err = collect(process)
        assert code == 143 and not err
        assert runner.process_identity(pid) is None
        assert sibling.poll() is None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        sibling.terminate()
        sibling.wait(timeout=3)


@pytest.mark.parametrize("restricted", [False, True])
def test_deadline_stops_children_and_reports_timeout(tmp_path, restricted):
    path = tmp_path / "child"
    process = launch(
        f"sleep 15 & echo $! > '{path}'; wait", restricted=restricted, timeout=1
    )
    pid = child_pid(path)
    code, _, err = collect(process)
    assert code == 124 and "execution deadline" in err and "Traceback" not in err
    assert runner.process_identity(pid) is None


@pytest.mark.parametrize("restricted", [False, True])
def test_completed_shell_does_not_leave_background_children(tmp_path, restricted):
    path = tmp_path / "child"
    process = launch(f"sleep 15 & echo $! > '{path}'; exit 7", restricted=restricted)
    code, _, err = collect(process)
    assert code == 7 and not err
    assert runner.process_identity(int(path.read_text())) is None


def test_reused_pid_is_not_signalled(monkeypatch):
    monkeypatch.setattr(runner.os, "killpg", Mock(side_effect=PermissionError))
    monkeypatch.setattr(runner, "group_members", lambda group: [(123, "before")])
    monkeypatch.setattr(runner, "process_identity", lambda pid: (123, 123, "after"))
    kill = Mock()
    monkeypatch.setattr(runner.os, "kill", kill)
    assert runner.signal_group(SimpleNamespace(pid=123), signal.SIGTERM)
    kill.assert_not_called()
