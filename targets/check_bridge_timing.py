#!/usr/bin/env python3
"""Does the bridge's own environment slow the target down?

A standalone replay of the same input finishes in ~40 ms, yet the bridge times
out on ~31% of executions at a 200 ms budget -- even with a single worker, so
concurrency is ruled out. The remaining difference is the bridge process itself:
the core hands it a stdin/stdout PIPE and it launches the target from inside
that session.

Drive a real ``--serve`` bridge over a pipe and compare its reported outcomes
against the identical requests issued with no bridge involved.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(HERE, "..", "adapters", "python", "bridge.py")
TARGET = os.path.join(HERE, "cfgparser.py")
BUDGET_MS = 200
SAMPLES = 40


def make_input(index: int) -> bytes:
    return (b"[server]\nport = %d\nworkers = 4\ntimeout_ms = 100\ntls = false\n"
            % (1000 + index))


def request(index: int) -> dict:
    return {
        "v": 1, "op": "execute", "target": os.path.abspath(TARGET),
        "input_file": None, "timeout_ms": BUDGET_MS, "seed": index,
        "target_python": sys.executable, "dialect": "ini",
    }


def main() -> int:
    files = []
    for i in range(SAMPLES):
        fd, path = tempfile.mkstemp(suffix=".in")
        with os.fdopen(fd, "wb") as handle:
            handle.write(make_input(i))
        files.append(path)

    # 1. Direct, no bridge: the reference condition.
    direct_hangs = 0
    for path in files:
        try:
            subprocess.run([sys.executable, TARGET, path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=BUDGET_MS / 1000.0)
        except subprocess.TimeoutExpired:
            direct_hangs += 1

    # 2. Through a real serve-mode bridge, exactly as the core drives it.
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(
        [sys.executable, BRIDGE, "--serve"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env,
    )
    bridge_hangs = 0
    bridge_replies = 0
    try:
        for i, path in enumerate(files):
            req = request(i)
            req["input_file"] = path
            proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                break
            bridge_replies += 1
            resp = json.loads(line)
            if resp.get("status") == "TIMEOUT":
                bridge_hangs += 1
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print("budget                : %d ms" % BUDGET_MS)
    print("direct   (%d inputs)  : %d hangs" % (SAMPLES, direct_hangs))
    print("bridge   (%d replies) : %d hangs" % (bridge_replies, bridge_hangs))
    print()

    for path in files:
        try:
            os.unlink(path)
        except OSError:
            pass

    if bridge_hangs > direct_hangs:
        print("VERDICT: the bridge session turns fast inputs into timeouts.")
        print("The defect is in how the bridge launches or waits on the target,")
        print("not in the target's own timing.")
        return 1
    print("VERDICT: bridge and direct observation agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
