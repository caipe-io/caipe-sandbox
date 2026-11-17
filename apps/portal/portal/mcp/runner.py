"""One-shot command wrapper sent through exec; stdin carries control, not a server."""

import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time


def exited(process):
    if sys.platform == "linux":
        # Keep the leader unreaped so its group/session ID cannot be reused during cleanup.
        return (
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            is not None
        )
    return process.poll() is not None


def process_identity(pid):
    try:
        with open(f"/proc/{pid}/stat", errors="replace") as source:
            fields = source.read().rsplit(")", 1)[1].split()
        if fields[0] not in {"Z", "X"}:
            return int(fields[2]), int(fields[3]), fields[19]
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return None


def group_members(group):
    members = []
    for name in os.listdir("/proc"):
        if not name.isdecimal():
            continue
        identity = process_identity(name)
        if identity is not None and identity[:2] == (group, group):
            members.append((int(name), identity[2]))
    return members


def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
        return False
    except ProcessLookupError:
        return False
    except PermissionError:
        if sys.platform != "linux":
            raise
    # Restricted runtimes may permit only positive PID signals. Recheck identity and group.
    for pid, started in group_members(process.pid):
        if process_identity(pid) != (process.pid, process.pid, started):
            continue
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass
    return True


def wait_for_exit(process, timeout):
    deadline = time.monotonic() + timeout
    while not exited(process):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def cleanup(process):
    if signal_group(process, signal.SIGKILL):
        deadline = time.monotonic() + 2
        while group_members(process.pid):
            if time.monotonic() >= deadline:
                raise OSError("Command process group termination is unconfirmed")
            signal_group(process, signal.SIGKILL)
            time.sleep(0.05)


def main():
    pending = bytearray()
    while b"\n" not in pending:
        chunk = os.read(sys.stdin.fileno(), 4096)
        if not chunk or len(pending) + len(chunk) > 131072:
            return 125
        pending.extend(chunk)
    line, _, pending = pending.partition(b"\n")
    body = json.loads(line)
    interrupted = False

    def stop(signum, frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    process = None
    try:
        with tempfile.TemporaryFile() as source:
            source.write(body.get("stdin", "").encode())
            source.seek(0)
            process = subprocess.Popen(
                ["/bin/sh", "-c", body["command"]],
                cwd=body.get("cwd") or None,
                stdin=source,
                start_new_session=True,
            )
            deadline = time.monotonic() + body["timeout_seconds"]
            selector = selectors.DefaultSelector()
            selector.register(sys.stdin, selectors.EVENT_READ)
            while (
                not exited(process) and not interrupted and time.monotonic() < deadline
            ):
                if b"\n" in pending:
                    line, _, pending = pending.partition(b"\n")
                    interrupted = json.loads(line).get("action") == "cancel"
                    continue
                if selector.select(0.1):
                    chunk = os.read(sys.stdin.fileno(), 4096)
                    if not chunk:
                        interrupted = True
                        break
                    pending.extend(chunk)
                    if len(pending) > 8192:
                        interrupted = True
                        break
            timed_out = not exited(process) and not interrupted
            if not exited(process):
                signal_group(process, signal.SIGTERM)
                wait_for_exit(process, 2)
            cleanup(process)
            code = process.wait(timeout=2)
            if timed_out:
                print(
                    "Command exceeded its execution deadline; its process group was stopped.",
                    file=sys.stderr,
                )
            return 124 if timed_out else 128 - code if code < 0 else code
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print(
            "Sandbox command could not start or finish cleanly. Check the working directory, "
            "Python 3 runtime and process permissions. Inspect this command before retrying.",
            file=sys.stderr,
        )
        return 125
    finally:
        if process is not None and process.returncode is None:
            try:
                cleanup(process)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                print(
                    "Command cleanup is unconfirmed; child processes may still be running.",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    sys.exit(main())
