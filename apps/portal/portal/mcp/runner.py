"""One-shot command wrapper sent through exec; stdin carries control, not a server."""

import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time


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
                process.poll() is None
                and not interrupted
                and time.monotonic() < deadline
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
            timed_out = process.poll() is None and not interrupted
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            if timed_out:
                print(
                    "Command exceeded its execution deadline; its process group was stopped.",
                    file=sys.stderr,
                )
            return 124 if timed_out else 128 - code if code < 0 else code
    except (OSError, ValueError, KeyError, TypeError):
        print(
            "Sandbox command could not start. Check the working directory and Python 3 runtime.",
            file=sys.stderr,
        )
        return 125
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    sys.exit(main())
