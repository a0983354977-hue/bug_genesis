#!/usr/bin/env python3
"""Replay *every* stored hang input and count how many still hang.

The engine recorded 1012 observations as ``hang|TIMEOUT|`` with ``raw_exit=0``
and elapsed 188-221 ms, but a single replay of one of them finished in 43 ms.
Either the target genuinely hangs on these inputs, or the timeout fired
spuriously. Replaying all of them at the campaign's own budget is the only way
to tell, and the answer decides whether the knowledge base holds a real family
or a fabricated one.
"""

import os
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "cfgparser.py")
DB = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(
    HERE, "..", "p3_cfg.db")
BUDGET_MS = 200
REPEATS = 3


def replay(data: bytes, budget_ms: int):
    """Return elapsed ms, or None when the budget was blown."""
    fd, path = tempfile.mkstemp(suffix=".in")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, TARGET, path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=max(budget_ms, 1) / 1000.0,
            )
            return (time.perf_counter() - t0) * 1000.0, proc.returncode
        except subprocess.TimeoutExpired:
            return None, None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main() -> int:
    conn = sqlite3.connect(DB)
    rows = list(conn.execute(
        "SELECT id, content FROM test_cases WHERE kind_label='hang'"))
    if not rows:
        print("no hang cases in %s" % DB)
        return 2

    still_hang = 0
    finishes = 0
    elapsed = []
    returncodes = set()
    examples = []

    for fid, blob in rows:
        data = bytes(blob)
        worst = None
        for _ in range(REPEATS):
            ms, rc = replay(data, BUDGET_MS)
            if ms is None:
                worst = None
                break
            returncodes.add(rc)
            worst = ms if worst is None else max(worst, ms)
        if worst is None:
            still_hang += 1
            if len(examples) < 3:
                examples.append((fid, data))
        else:
            finishes += 1
            elapsed.append(worst)

    total = len(rows)
    print("replayed %d stored hang inputs, %d repeats each, budget %d ms"
          % (total, REPEATS, BUDGET_MS))
    print()
    print("  still hang     : %d (%.1f%%)" % (still_hang, 100.0 * still_hang / total))
    print("  finish normally: %d (%.1f%%)" % (finishes, 100.0 * finishes / total))
    if elapsed:
        print("  finish time    : min=%.0f p50=%.0f max=%.0f ms"
              % (min(elapsed), statistics.median(elapsed), max(elapsed)))
    print("  return codes   : %s" % sorted(returncodes))
    print()
    for fid, data in examples:
        print("  %s  %r" % (fid, data[:70]))

    print()
    if finishes > still_hang:
        print("VERDICT: the majority of stored 'hangs' terminate normally.")
        print("The TIMEOUT family is largely a spurious classification, not a")
        print("reproducible target defect -- the knowledge base is asserting a")
        print("bug that cannot be replayed.")
        return 1
    print("VERDICT: stored hangs replay as hangs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
