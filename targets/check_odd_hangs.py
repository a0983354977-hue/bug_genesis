#!/usr/bin/env python3
"""Are the stored hangs that do not end in a backslash still real?

check_hang_backslash explains 97.5% of the stored hangs by the target's
continuation path; the remainder end in some other byte. Replaying them at the
campaign's 200 ms budget proves they were classified consistently, but a budget
that small cannot separate "never terminates" from "terminates slowly on a busy
machine". So re-run those few at a budget five times larger, five times each.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "cfgparser.py")
DB = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(
    HERE, "..", "p3_t9.db")
BUDGET_MS = 1000
REPEATS = 5


def main() -> int:
    conn = sqlite3.connect(DB)
    rows = list(conn.execute(
        "SELECT id, content FROM test_cases WHERE kind_label='hang'"))
    odd = []
    for fid, blob in rows:
        data = bytes(blob)
        if not data.rstrip(b"\r\n").endswith(b"\\"):
            odd.append((fid, data))

    print("stored hangs: %d, of which %d do not end in a backslash"
          % (len(rows), len(odd)))
    if not odd:
        print("nothing unusual to check")
        return 0
    print("re-running each %d times with a %d ms budget" % (REPEATS, BUDGET_MS))
    print()

    still = 0
    finished = []
    for fid, data in odd:
        fd, path = tempfile.mkstemp(suffix=".in")
        hangs = True
        times = []
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            for _ in range(REPEATS):
                t0 = time.perf_counter()
                try:
                    subprocess.run(
                        [sys.executable, TARGET, path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=BUDGET_MS / 1000.0,
                    )
                    times.append((time.perf_counter() - t0) * 1000.0)
                    hangs = False
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        if hangs:
            still += 1
            print("  HANG   %s  %r" % (fid, data[-40:]))
        else:
            finished.append((fid, data, times[0]))

    print()
    print("  still hang at %d ms : %d / %d" % (BUDGET_MS, still, len(odd)))
    for fid, data, ms in finished:
        print("  finished in %.0f ms: %s  %r" % (ms, fid, data[-40:]))

    if still == len(odd):
        print()
        print("VERDICT: every stored hang terminates neither at 200 ms nor at "
              "%d ms." % BUDGET_MS)
        return 0
    print()
    print("VERDICT: %d stored hangs terminate at %d ms; those classifications "
          "are not reproducible." % (len(finished), BUDGET_MS))
    return 1


if __name__ == "__main__":
    sys.exit(main())