#!/usr/bin/env python3
"""Verify every planted defect in cfgparser.py is actually reachable.

A defect that cannot be reached is not a defect -- it is dead code that makes
the benchmark look better than it is. This harness drives the target with
exact bytes and asserts the *observed* outcome, never the source.

    python targets/check_cfgparser.py
"""

import os
import subprocess
import sys
import tempfile

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfgparser.py")
TIMEOUT_S = 4.0

#: port truncation collapses to zero at this value: 256 & 0xFF == 0.
TRUNCATED_PORT = 256


def run(data: bytes, timeout: float = TIMEOUT_S):
    """Run the target on ``data`` and return (exit_code, combined_output)."""
    fd, path = tempfile.mkstemp(suffix=".cfg")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        proc = subprocess.run(
            [sys.executable, TARGET, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        out = (proc.stdout or b"") + (proc.stderr or b"")
        return proc.returncode, out.decode("utf-8", "replace")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def check(name, data, want_exit, want_text=None, allow_hang=False):
    """Assert the observed outcome. Returns True when the assertion held."""
    try:
        code, out = run(data)
    except subprocess.TimeoutExpired:
        if allow_hang:
            print("  PASS %-22s -> hung (as designed)" % name)
            return True
        print("  FAIL %-22s -> TIMED OUT, expected exit %s" % (name, want_exit))
        return False

    ok = code == want_exit
    if ok and want_text:
        ok = want_text in out
    if ok:
        print("  PASS %-22s -> exit %d  %s" % (name, code, out.strip().splitlines()[-1] if out.strip() else ""))
        return True
    print("  FAIL %-22s -> exit %d (want %d)  out=%r" % (name, code, want_exit, out[:160]))
    return False


def main() -> int:
    print("cfgparser defect reachability")
    print("-" * 68)
    results = []

    # 1. The happy path must still work, or every other assertion is noise.
    results.append(check(
        "valid config",
        b"[server]\nport = 8080\nworkers = 4\ntimeout_ms = 100\ntls = false\n",
        0, "OK sections="))

    # 2. The intern-cache defect: >= 16 consecutive 'A' inside a value.
    #    Interning runs BEFORE coercion, so this reaches the null write rather
    #    than dying on TypeMismatch first.
    #
    #    Honest expectation: exit **1**, not an NTSTATUS crash. CPython installs
    #    its own SEH handler on Windows and converts the access violation into a
    #    catchable OSError, so the Python target can never produce a CRASH_*
    #    family. Faking that code with RtlExitUserProcess would be fabricating
    #    an observation, so we assert what actually happens and say so.
    run_av = b"[server]\nport = 1" + b"A" * 16 + b"\n"
    results.append(check("intern null write", run_av, 1, "OSError"))

    # 3. Unbounded nesting -> RecursionError (NEST_LIMIT is declared, never used).
    deep = b"[" + b"server][" * 200 + b"server]\n"
    results.append(check("unbounded nesting", deep, 1, "RecursionError"))

    # 4. Trailing backslash at EOF -> cursor never advances -> hang.
    results.append(check("continuation hang", b"[server]\nport = 1 \\\n",
                         None, None, allow_hang=True))

    # 5. 8-bit truncation collapsing to zero -> division by the truncated value.
    results.append(check("port truncation",
                         b"[server]\nport = %d\nworkers = 2\n" % TRUNCATED_PORT,
                         1, "ScaledPortCollapse"))

    # 6. Semantic rules -- the point of a *config* target.
    results.append(check("tls without cert", b"[server]\nport = 1\ntls = true\n",
                         1, "MissingRequired"))
    results.append(check("unknown section", b"[nope]\nport = 1\n", 1, "UnknownSection"))
    results.append(check("duplicate key",
                         b"[server]\nport = 1\nport = 2\n", 1, "DuplicateKey"))
    results.append(check("mutex violation",
                         b"[server]\nport = 1\nbind_addr = a\nbind_iface = b\n",
                         1, "MutuallyExclusive"))
    results.append(check("non-positive",
                         b"[server]\nport = 0\n", 1, "NotPositive"))

    print("-" * 68)
    good = sum(1 for r in results if r)
    print("%d/%d reachable" % (good, len(results)))
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
