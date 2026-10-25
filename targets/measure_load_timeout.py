#!/usr/bin/env python3
"""Is the ``hang|TIMEOUT|`` family real, or an artefact of load?

The campaign stored 1012 inputs classified as hangs, but only 138 of them end
in a backslash -- the target's one real non-terminating path. The rest have the
exact byte lengths of the four seed files and replay in ~43 ms with exit 0.

That pattern says the timeout fired on inputs that complete normally, which
would mean the knowledge base holds a *fabricated* defect family. Before
changing anything, measure it: replay the seeds under the same worker count the
campaign used and record the completion-time distribution against the budget.
"""

import concurrent.futures
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "cfgparser.py")
SEED_DIR = os.path.join(HERE, "..", "seeds_cfg")
BUDGET_MS = 200
WORKERS = 4
ROUNDS = 120


def one_run(path: str):
    """Run the target once; return elapsed ms, or None when it exceeded budget."""
    fd, work = tempfile.mkstemp(suffix=".in")
    try:
        with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
            dst.write(src.read())
        t0 = time.perf_counter()
        try:
            subprocess.run(
                [sys.executable, TARGET, work],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=BUDGET_MS / 1000.0,
            )
            return (time.perf_counter() - t0) * 1000.0
        except subprocess.TimeoutExpired:
            return None
    finally:
        try:
            os.unlink(work)
        except OSError:
            pass


def main() -> int:
    seeds = [os.path.join(SEED_DIR, n) for n in sorted(os.listdir(SEED_DIR))]
    seeds = [s for s in seeds if os.path.isfile(s)]
    if not seeds:
        print("no seeds in %s" % SEED_DIR)
        return 2

    jobs = [seeds[i % len(seeds)] for i in range(ROUNDS)]

    # Serial baseline: what the target costs with the machine to itself.
    serial = [one_run(s) for s in seeds * 3]

    # Same work at the campaign's worker count: the condition that produced the
    # stored observations.
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        parallel = list(pool.map(one_run, jobs))

    def report(label, values):
        real = [v for v in values if v is not None]
        blown = len(values) - len(real)
        print("  %-10s n=%-4d over-budget=%-4d (%.1f%%)"
              % (label, len(values), blown, 100.0 * blown / max(len(values), 1)))
        if real:
            print("             ms min=%.0f p50=%.0f p95=%.0f max=%.0f mean=%.0f"
                  % (min(real), statistics.median(real),
                     sorted(real)[int(len(real) * 0.95) - 1], max(real),
                     statistics.mean(real)))
        return blown

    print("target        : %s" % TARGET)
    print("budget        : %d ms   workers: %d" % (BUDGET_MS, WORKERS))
    print()
    b_serial = report("serial", serial)
    b_par = report("parallel", parallel)

    print()
    if b_par > b_serial:
        print("VERDICT: the budget is blown under load but not at rest.")
        print("The timeout fired on inputs that terminate normally, so the")
        print("stored hang family is a scheduling artefact, not a target defect.")
        return 1
    print("VERDICT: no false timeouts at either load level.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
