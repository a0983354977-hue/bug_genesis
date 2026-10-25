#!/usr/bin/env python3
"""Why does delta reduction fail on the hang family?

The campaign classifies a hang with a 200 ms budget, but reduction probes with
``cfg.reduceMs`` (100 ms here). If the input does *not* hang within the smaller
budget, every reduction probe returns a different signature and the family
keeps its unreduced input -- silently.

This reads the real input from the campaign database rather than guessing at
what the fuzzer must have produced.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import time

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "p3_cfg.db")
TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfgparser.py")
FAMILY = "F_000001M5MXECZDWE689E9B5A6X"


def probe(data: bytes, budget_ms: int) -> str:
    """Return 'HANG' when the target does not finish inside the budget."""
    fd, path = tempfile.mkstemp(suffix=".in")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, TARGET, path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=max(budget_ms, 1) / 1000.0,
            )
            elapsed = int((time.perf_counter() - t0) * 1000)
            return "finish rc=%d in %dms" % (proc.returncode, elapsed)
        except subprocess.TimeoutExpired:
            return "HANG"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main() -> int:
    conn = sqlite3.connect(DB)
    row = list(conn.execute(
        "SELECT content FROM test_cases WHERE family_id=? AND is_repro=0 LIMIT 1",
        (FAMILY,)))
    if not row:
        print("no test case found for %s in %s" % (FAMILY, DB))
        return 2
    data = bytes(row[0][0])

    print("input length : %d bytes" % len(data))
    print("tail         : %r" % data[-40:])
    print("ends with \\  : %s" % data.rstrip(b"\r\n").endswith(b"\\"))
    print()

    for budget in (200, 150, 100, 75, 50):
        print("  budget %3d ms -> %s" % (budget, probe(data, budget)))

    print()
    # A trailing backslash is what the target's continuation bug needs. Strip
    # everything after the last one and check whether the hang survives.
    idx = data.rstrip(b"\r\n").rfind(b"\\")
    if idx >= 0:
        trimmed = data[:idx + 1]
        print("trim to last backslash: %d bytes" % len(trimmed))
        for budget in (200, 100):
            print("  budget %3d ms -> %s" % (budget, probe(trimmed, budget)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
