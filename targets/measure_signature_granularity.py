#!/usr/bin/env python3
"""How many families does each candidate normalisation rule actually merge?

The stored signatures are already the output of the current rule (digit runs -> '#').
Applying further candidate rules to the *stored* output part measures the merge
rate without re-running anything.

Nothing is asserted here: it prints the counts so the rule that ships is the one
the data supports, not the one that sounded plausible.
"""

import collections
import os
import re
import sqlite3
import sys

DB = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "p3_t12.db")


def rule_quoted(text: str) -> str:
    """Abstract the contents of quoted spans -> '#', keeping the quotes."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            out.append(c)
            i += 1
            close = text.find(c, i)
            out.append("#")
            if close == -1:
                i = n
            else:
                out.append(c)
                i = close + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


IDENT = re.compile(r"[A-Za-z0-9_]")


def rule_runs(text: str, minimum: int = 3) -> str:
    """Collapse runs of the same non-identifier character of length >= minimum."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        j = i + 1
        while j < n and text[j] == c:
            j += 1
        run = j - i
        if run >= minimum and not IDENT.match(c):
            out.append(c)
            out.append("#")
        else:
            out.append(text[i:j])
        i = j
    return "".join(out)


def rule_unquoted_values(text: str) -> str:
    """Aggressive: also abstract `key=value` payload after known-safe keys.

    Only applied to values whose key is a *data* key (name/value/part/body),
    never to keys that name a code path (key/section/expected/reason).
    """
    def sub(m):
        return "%s='#'" % m.group(1)

    return re.sub(
        r"\b(name|value|part|body|raw)=('[^']*'|\"[^\"]*\")", sub, text)


def main() -> int:
    conn = sqlite3.connect(DB)
    sigs = [s for (s,) in conn.execute("SELECT signature FROM bug_families")]
    if not sigs:
        print("no families in %s" % DB)
        return 2

    def out_part(sig):
        return sig.split("|", 2)[2] if sig.count("|") >= 2 else sig

    def full(sig, new_out):
        parts = sig.split("|", 2)
        return "%s|%s|%s" % (parts[0], parts[1], new_out)

    print("knowledge base: %s" % DB)
    print("stored families                : %d" % len(sigs))
    print()

    variants = [
        ("baseline (as stored)", lambda s: s),
        ("+ quote contents -> '#'", lambda s: full(s, rule_quoted(out_part(s)))),
        ("+ same-char run >=3", lambda s: full(
            s, rule_runs(rule_quoted(out_part(s))))),
        ("+ data-key values -> '#'", lambda s: full(
            s, rule_unquoted_values(rule_runs(rule_quoted(out_part(s)))))),
    ]

    previous = None
    for name, fn in variants:
        merged = collections.Counter(fn(s) for s in sigs)
        distinct = len(merged)
        line = "  %-28s distinct families: %5d" % (name, distinct)
        if previous is not None and previous > 0:
            line += "   (merges %d, %.0f%%)" % (
                previous - distinct, 100.0 * (previous - distinct) / previous)
        print(line)
        previous = distinct

    print()
    print("=== after the strongest rule: the families that remain ===")
    final = collections.Counter(variants[-1][1](s) for s in sigs)
    for sig, hits in sorted(final.items(), key=lambda kv: -kv[1])[:25]:
        print("  hits=%-5d %s" % (hits, sig[:96]))

    print()
    print("=== what the merge WOULD combine (sample: 3 groups) ===")
    groups = collections.defaultdict(list)
    for s in sigs:
        groups[variants[-1][1](s)].append(s)
    shown = 0
    for key, members in groups.items():
        if len(members) < 2:
            continue
        print()
        print("  -> one family, %d stored copies:" % len(members))
        for m in members[:3]:
            print("       %s" % m[:100])
        shown += 1
        if shown >= 3:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())