#!/usr/bin/env python3
"""Do the stored hangs correspond to inputs the target really hangs on?

The target's only non-terminating path is a continuation line: the last
character before EOF is a backslash, so ``_continuation_advance`` returns 0
and the parse cursor never moves. A stored hang whose bytes do *not* end that
way is therefore a claim the replay cannot support.

This counts them rather than asserting it.
"""

import os
import sqlite3
import sys

DB = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else
      os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "p3_cfg.db"))


def main() -> int:
    conn = sqlite3.connect(DB)
    rows = list(conn.execute("SELECT content FROM test_cases WHERE kind_label='hang'"))
    if not rows:
        print("no hang cases in %s" % DB)
        return 2

    with_backslash = 0
    sizes = {}
    for (blob,) in rows:
        data = bytes(blob)
        stripped = data.rstrip(b"\r\n")
        if stripped.endswith(b"\\"):
            with_backslash += 1
        sizes[len(data)] = sizes.get(len(data), 0) + 1

    total = len(rows)
    without = total - with_backslash

    print("stored hang cases : %d" % total)
    print("  end with backslash (real hang trigger) : %d (%.1f%%)"
          % (with_backslash, 100.0 * with_backslash / total))
    print("  do NOT end with backslash              : %d (%.1f%%)"
          % (without, 100.0 * without / total))
    print()
    print("sizes (top 6):")
    for size, count in sorted(sizes.items(), key=lambda kv: -kv[1])[:6]:
        print("  %5d B  x%d" % (size, count))

    print()
    if without == 0:
        print("VERDICT: every stored hang matches the target's real hang trigger.")
        return 0
    print("VERDICT: %d stored hangs cannot be explained by the target's hang" % without)
    print("path. Either the timeout fired on an input that terminates, or the")
    print("stored bytes no longer match what was executed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
