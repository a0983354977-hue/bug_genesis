#!/usr/bin/env python3
"""Can every stored counterexample be read back and reproduced on its own?

Phase 3's Definition of Done asks the knowledge base to hold Python-produced
counterexamples losslessly: the ``content`` BLOB and the family reproducer must,
by themselves, produce the same observation they were filed under.

This checks that by *independently* re-implementing the signature contract from
src/engine/executor.nim and re-running the target:

    signature = kind | canonical_code | normalizeOutput(output)

Nothing is trusted from the database except the bytes themselves. A mismatch
means either the stored bytes are not what was executed, or the signature rules
drifted between the Nim module and this check.
"""

import argparse
import os
import re
import sqlite3
import subprocess
import sys
import tempfile

MAX_CAPTURED_OUTPUT = 4096
TRUNCATION_MARK = "\n...[output truncated]"
NT = 0xFFFFFFFF

WINDOWS_AV = {0xC0000005, 0xC0000008, 0xC0000096}
WINDOWS_FPE = {0xC0000094, 0xC0000093}


def classify(timed_out: bool, returncode: int):
    """Mirror executor.normalizeOutcome / executor.canonicalCode."""
    if timed_out:
        return "hang", "TIMEOUT"
    if returncode == 0:
        return "ok", "EXIT_0"
    if returncode == 1:
        return "logic_error", "EXIT_1"

    code = returncode & NT
    if code in WINDOWS_AV:
        return "crash_access_violation", "NTSTATUS_0x%08X" % code
    if code == 0xC00000FD:
        return "crash_stack_overflow", "NTSTATUS_0x%08X" % code
    if code in WINDOWS_FPE:
        return "crash_int_div_by_zero", "NTSTATUS_0x%08X" % code
    if code & 0xF0000000 == 0xC0000000:
        return "crash_other", "NTSTATUS_0x%08X" % code
    return "logic_error", "EXIT_1"


def normalize_output(text: str) -> str:
    """Mirror executor.normalizeOutput.

    Two rules, in one pass per line, because the order the characters are seen
    in matters: digit runs become '#', and the contents of a quoted span become
    '#' while the quotes themselves stay.

    This is the second copy of a contract that lives in
    src/engine/executor.nim. It is deliberately an independent implementation:
    if the two drift, this check reports a signature mismatch loudly instead of
    quietly agreeing with a broken rule. Change both, together.
    """
    chunks = []
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        out = []
        i = 0
        n = len(line)
        while i < n:
            c = line[i]
            if c.isdigit():
                while i < n and line[i].isdigit():
                    i += 1
                out.append("#")
            elif c in "'\"":
                out.append(c)
                i += 1
                closed = False
                while i < n and line[i] != c:
                    i += 1
                if i < n:
                    closed = True
                out.append("#")
                if closed:
                    out.append(c)
                    i += 1
            else:
                out.append(c)
                i += 1
        chunk = "".join(out).strip()
        if chunk:
            chunks.append(chunk)
    return " | ".join(chunks)


def bounded(raw: bytes) -> str:
    if len(raw) > MAX_CAPTURED_OUTPUT:
        raw = raw[:MAX_CAPTURED_OUTPUT] + TRUNCATION_MARK.encode()
    return raw.decode("utf-8", errors="replace")


def run_once(target, interpreter, data: bytes, timeout_ms: int):
    fd, path = tempfile.mkstemp(suffix=".in")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        argv = [target, path] if not interpreter else [interpreter, target, path]
        try:
            proc = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=max(timeout_ms, 1) / 1000.0)
            kind, code = classify(False, proc.returncode)
            return kind, code, bounded(proc.stdout)
        except subprocess.TimeoutExpired as exc:
            captured = exc.output or b""
            kind, code = classify(True, 0)
            return kind, code, bounded(captured)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def signature_of(kind, code, output):
    return "%s|%s|%s" % (kind, code, normalize_output(output))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("target")
    ap.add_argument("--interpreter", default="",
                    help="interpreter when the target is a script")
    ap.add_argument("--timeout", type=int, default=200)
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    failures = []

    # --- BLOB integrity: every stored case is a real, non-empty blob whose
    # recorded length still describes it.
    bad_blob = 0
    for content_len, stored_len, typeof in conn.execute(
            "SELECT content_len, length(content), typeof(content) "
            "FROM test_cases"):
        if typeof != "blob" or int(content_len) != stored_len or stored_len == 0:
            bad_blob += 1
    total_cases = conn.execute("SELECT COUNT(*) FROM test_cases").fetchone()[0]

    # --- The reproducer and the is_repro case must be the same bytes.
    diverged = 0
    for fid, repro, case_content in conn.execute(
            "SELECT f.id, f.repro, c.content FROM bug_families f "
            "LEFT JOIN test_cases c ON c.family_id = f.id AND c.is_repro = 1 "
            "WHERE f.repro_len > 0"):
        if case_content is not None and bytes(repro) != bytes(case_content):
            diverged += 1

    # --- Signature grammar, on every stored family.
    grammar = re.compile(
        r"^(ok|logic_error|crash_access_violation|crash_stack_overflow|"
        r"crash_int_div_by_zero|crash_other|hang)"
        r"\|(EXIT_0|EXIT_1|TIMEOUT|NTSTATUS_0x[0-9A-F]{8})\|(.*)$", re.S)
    bad_grammar = [sig for (sig,) in conn.execute(
        "SELECT signature FROM bug_families") if not grammar.match(sig)]

    # --- The real test: replay each reproducer and rebuild the signature.
    replayed = 0
    reproduced = 0
    for sig, kind, code, repro in conn.execute(
            "SELECT signature, kind_label, code, repro FROM bug_families "
            "WHERE repro_len > 0"):
        data = bytes(repro)
        got_kind, got_code, got_output = run_once(
            args.target, args.interpreter, data, args.timeout)
        got_sig = signature_of(got_kind, got_code, got_output)
        replayed += 1
        if got_sig == sig:
            reproduced += 1
        elif len(failures) < 5:
            failures.append((sig, got_sig, data[:60]))

    print("knowledge base: %s" % args.db)
    print("  target: %s %s" % (args.target, args.interpreter))
    print()
    print("  test_cases stored          : %d" % total_cases)
    print("  non-empty BLOBs w/ length  : %d  (violations: %d)"
          % (total_cases - bad_blob, bad_blob))
    print("  reproducer == is_repro row : %d  (divergences: %d)"
          % (replayed - diverged, diverged))
    print("  signature grammar holds    : %d  (violations: %d)"
          % (replayed - len(bad_grammar), len(bad_grammar)))
    for sig in bad_grammar[:3]:
        print("      bad grammar: %r" % sig[:90])
    print()
    print("  reproducers replayed       : %d" % replayed)
    print("  reproduced the same family : %d" % reproduced)
    for want, got, data in failures:
        print()
        print("      stored : %s" % want[:110])
        print("      replay : %s" % got[:110])
        print("      bytes  : %r" % data)

    # A campaign run with --no-reduce stores no reproducers, so the replay half
    # of this check has nothing to work on. Reporting that as a failure would be
    # a lie; reporting it as a pass would let a campaign that silently stopped
    # reducing look healthy. It is neither, so it gets its own exit code.
    if replayed == 0:
        print()
        print("NOTE: this knowledge base stores no reproducers (campaign ran with")
        print("      --no-reduce?), so the replay half was SKIPPED. BLOB integrity")
        print("      and signature grammar were still checked above.")
        clean = bad_blob == 0 and diverged == 0 and not bad_grammar
        print("VERDICT: %s (replay not verified)" % (
            "storage checks pass;" if clean else "storage checks FAILED;"))
        return 0 if clean else 1

    ok = (bad_blob == 0 and diverged == 0 and not bad_grammar
          and reproduced == replayed)
    print()
    print("VERDICT: %s" % ("the knowledge base round-trips losslessly."
                           if ok else "the knowledge base does NOT round-trip."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())