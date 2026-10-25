#!/usr/bin/env python3
"""BUG GENESIS — Python target adapter (Hypothesis).

Speaks the protocol in ``docs/adapter-protocol.md``. The Nim core drives this
process over stdin/stdout as one JSON object per line; this file is the only
place Python-specific knowledge lives.

Design notes that are *not* obvious from the protocol document, and were
settled by measurement on this project:

1. **Serve mode is mandatory, not an optimisation.** ``import hypothesis``
   costs ~477 ms, versus ~7 ms for one native target execution. A
   spawn-per-request bridge would spend 98.5% of its wall clock importing and
   would have to batch requests, which couples batch size to worker count and
   destabilises the core loop's accounting.

2. **stderr is discarded in serve mode.** The core does not drain the bridge's
   stderr pipe while the session is alive, so anything written there
   accumulates until the ~4 KB buffer fills and *both* sides deadlock: the
   bridge blocks on a write, the core blocks on a response that never comes.
   Standalone modes keep stderr for humans.

3. **Variety comes from seed-derived constraints, not from sampling more
   examples.** With ``max_examples=1`` Hypothesis returns the simplest value
   its search can reach -- measured as ``{}`` for every one of six identical
   runs regardless of ``derandomize``. Raising ``max_examples`` costs ~30 ms
   per request for negligible extra diversity at this scale. So the request's
   ``seed`` parameterises the *strategy* (depth bands, run lengths, numeric
   bounds), and Hypothesis draws the structure beneath those bounds. Same seed
   -> same input, different seed -> different shape.

4. **Recursive structure is drawn, never composed.** Nesting built as
   ``st.builds(f, st.builds(f, ...))`` stops satisfying Hypothesis's own
   generator at depth ~100 (``Unsatisfiable``). A single ``@st.composite``
   that recurses through ``draw()`` reached depth 250 in 3 ms.

Reproduce a single request without the core::

    python adapters/python/bridge.py --once \
      '{"v":1,"op":"generate","target":"...","input_file":"...",
        "timeout_ms":150,"seed":123,"generator":"hypothesis_nested_json"}'
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import threading
import time
import traceback
import warnings

PROTOCOL_VERSION = 1

GENERATORS = (
    "hypothesis_nested_json",
    "hypothesis_extreme_num",
    "hypothesis_string_run",
    "hypothesis_malformed",
)

#: Generator families, keyed by input dialect.
#:
#: Phase 3 adds a second *target* (targets/cfgparser.py) whose input is INI, not
#: JSON. Pointing the JSON generators at it would only ever produce
#: ``UnknownSection`` -- one family, found on the first execution, after which
#: the campaign has nothing left to learn. A generator has to speak the
#: target's language or it is not testing the target's *semantics*.
#:
#: The dialect is derived from the target's file extension, so the core needs
#: no new request field and the choice stays in one place.
GENERATOR_FAMILIES = {
    "json": GENERATORS,
    "ini": (
        "hypothesis_cfg_semantic",
        "hypothesis_cfg_nesting",
        "hypothesis_cfg_port",
        "hypothesis_cfg_continuation",
        "hypothesis_cfg_token",
    ),
    # Phase 4.1: 任意二進位。
    #
    # 沒有任何結構假設的產生器家族。給一個格式未知的目標硬套 JSON 產生器，
    # 輸入會在第一個位元組就被拒絕，於是整場 campaign 只量到「格式嗅探」
    # 而從未進入解析邏輯 —— 看起來有覆蓋，實際上零。
    "raw": (
        "raw_bytes",
        "raw_text",
        "raw_magic",
    ),
}

#: Extension -> dialect. Unknown extensions fall back to ``json``.
DIALECT_BY_EXT = {
    ".py": "ini",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".toml": "ini",
}


def dialect_for(target: str, override: str = "") -> str:
    """Pick the generator family that matches the target's input format.

    ``override`` wins when the core states a dialect explicitly. The extension
    table is only a *heuristic* and a target named ``cfgparser`` (no suffix) or
    ``parser.bin`` would otherwise silently receive JSON generators -- producing
    nothing but ``UnknownSection`` while looking like a productive campaign.
    Silent degradation is the failure this project treats as worst, so the core
    states the dialect and the extension table is the fallback.
    """
    if override:
        return override if override in GENERATOR_FAMILIES else "json"
    _, ext = os.path.splitext(target)
    return DIALECT_BY_EXT.get(ext.lower(), "json")

#: Protocol ceiling on a single message (adapter-protocol.md §2.3).
MAX_MESSAGE_BYTES = 4096
#: Cap on ``error_message`` (§3.3).
ERROR_CAP = 2048
#: Defensive cap on a generated input. Strategies are size-bounded by
#: construction (depth <= 250 -> ~1.5 KB), so this should never engage.
MAX_INPUT_BYTES = 65536
#: Slack before the per-request watchdog fires, beyond ``timeout_ms``.
#: The first ``generate`` also pays the one-off Hypothesis import.
WARM_SLACK_MS = 6000
COLD_SLACK_MS = 2000

WINDOWS = sys.platform.startswith("win")

# NTSTATUS table mirrored from executor.nim's normalizeOutcome. If these two
# ever disagree, the core's cross-check reports it (protocol §4).
_NT = {
    0xC0000005: "CRASH_AV",
    0xC0000008: "CRASH_AV",
    0xC0000096: "CRASH_AV",
    0xC00000FD: "CRASH_STACK",
    0xC0000094: "CRASH_FPE",
    0xC0000093: "CRASH_FPE",
}
#: POSIX: 128 + signal. SIGSEGV covers both AV and stack overflow; the OS
#: cannot distinguish them, so both sides map 139 to CRASH_AV (§3.5).
_POSIX = {139: "CRASH_AV", 136: "CRASH_FPE", 134: "CRASH_OTHER",
          132: "CRASH_OTHER", 135: "CRASH_OTHER"}


# ---------------------------------------------------------------------------
# Exit code normalisation (§3.5 -- the place where cross-language drift happens)
# ---------------------------------------------------------------------------

def wire_exit_code(rc: int) -> int:
    """Reduce a runtime-native exit code to the protocol's unsigned form.

    Python on Windows already gives the NTSTATUS as an unsigned int
    (3221225477 == 0xC0000005); Nim stores the same pattern as a signed
    ``int32`` (-1073741819). Python on POSIX gives ``-signal`` while Nim gives
    ``128 + signal``. This is the single normalisation both sides agree on.
    """
    if rc < 0:
        return 128 + (-rc)
    return rc & 0xFFFFFFFF


def classify(w: int, timed_out: bool) -> str:
    if timed_out:
        return "TIMEOUT"
    if w == 0:
        return "OK"
    if w == 1:
        return "LOGIC_ERROR"
    if WINDOWS:
        if w in _NT:
            return _NT[w]
        return "CRASH_OTHER" if (w & 0xF0000000) == 0xC0000000 else "LOGIC_ERROR"
    return _POSIX.get(w, "LOGIC_ERROR")


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

def _size_of(path: str) -> int:
    """Size of the input file, or -1 when unreadable. Trace context only."""
    try:
        return os.path.getsize(path)
    except OSError:
        return -1


def _trace(event: str, **fields) -> None:
    """Append one diagnostic line when ``BUG_GENESIS_BRIDGE_TRACE`` names a file.

    Off by default: the protocol forbids using stdout/stderr for anything but the
    protocol (§2.1/§2.2), so diagnostics must go somewhere else or nowhere.
    """
    path = os.environ.get("BUG_GENESIS_BRIDGE_TRACE")
    if not path:
        return
    try:
        payload = {"pid": os.getpid(), "event": event}
        payload.update(fields)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
    except Exception:                                              # pragma: no cover
        pass


def _run_once(argv, timeout_ms: int, note: str = ""):
    """Launch the target once and classify what happened.

    Returns ``(status, exit_code, message, elapsed_ms)``. Split out of
    :func:`observe` so the timeout confirmation below can retry the *same*
    launch path -- two copies of the argv/timeout logic would drift, and the
    symptom of that drift is a hang that reproduces only intermittently.
    """
    t0 = time.perf_counter()
    try:
        # `timeout=` is implemented by subprocess against `time.monotonic`,
        # i.e. the 15.6 ms clock above, so this threshold has that same
        # granularity: the effective budget here is [timeout, timeout+15.6ms]
        # where the Nim executor's QueryPerformanceCounter budget is exact.
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(timeout_ms, 1) / 1000.0,
        )
    except subprocess.TimeoutExpired:
        _trace("timeout", budget_ms=timeout_ms, note=note,
               ms=round((time.perf_counter() - t0) * 1000, 1))
        return None
    except OSError as exc:
        return ("ERROR", -1, "bridge: cannot launch target: %s" % exc,
                int((time.perf_counter() - t0) * 1000))
    except Exception as exc:                                    # pragma: no cover
        return ("ERROR", -1, "bridge: " + repr(exc),
                int((time.perf_counter() - t0) * 1000))

    elapsed = int((time.perf_counter() - t0) * 1000)
    # Combined, unmodified: the core normalises this into a signature (§3.3),
    # so reformatting here would split one defect into two families.
    raw = (proc.stdout or b"") + (proc.stderr or b"")
    msg = raw.decode("utf-8", "replace")[:ERROR_CAP]
    w = wire_exit_code(proc.returncode)
    _trace("finished", budget_ms=timeout_ms, note=note,
           ms=round((time.perf_counter() - t0) * 1000, 1),
           rc=w, status=classify(w, timed_out=False))
    return (classify(w, timed_out=False), w, msg, elapsed)


def build_argv(target: str, input_file: str, target_python: str,
                target_args: str = "") -> list[str]:
    """How to launch the target -- the bridge's copy of the rule.

    Must stay in lockstep with ``buildTargetArgv`` in
    src/engine/executor.nim. Two copies exist because the bridge launches the
    target itself rather than asking the core to do it, and a drift between them
    shows up as "reduction no longer reproduces": the reproducer is verified on
    one launch path and re-run on another. Whitespace-split, no shell quoting,
    ``{input}`` marks the input path (default: appended at the end).
    """
    argv: list[str] = [target_python, target] if target_python else [target]
    if target_args:
        parts = [p for p in target_args.split() if p]
        if "{input}" in target_args:
            for part in parts:
                argv.append(input_file if part == "{input}"
                            else part.replace("{input}", input_file))
        else:
            argv.extend(parts)
            argv.append(input_file)
    else:
        argv.append(input_file)
    return argv


def observe(target: str, input_file: str, timeout_ms: int,
             target_python: str = "", op: str = "execute",
             target_args: str = "") -> dict:
    """Run the target and return a trustworthy observation.

    ``target_python`` names an interpreter: when it is non-empty the target is a
    *script*, not a binary, and is launched as ``[target_python, target,
    input_file]``. Leaving it empty keeps the original behaviour of launching the
    target directly, so an executable target costs nothing.

    **A timeout is not a defect claim.** It only says the target did not finish
    inside the budget, and on a loaded machine that happens to inputs which
    terminate perfectly well. Phase 3 measured exactly this: of 1012
    observations recorded as ``TIMEOUT`` against the Python target, only 141
    still hung on replay -- 86% finished normally in 38-57 ms, with the input
    unchanged. A single timeout would therefore have written a fabricated
    ``hang|TIMEOUT|`` family into the knowledge base.

    So every timeout is re-run once. Two timeouts means a reproducible hang and
    a genuine observation; one normal finish means the first timeout was an
    artefact of machine state, and the second run's real outcome is used
    instead. This is the same rule the executor applies on the native path
    (executor.nim ``execute``), so both paths agree.

    Durations use :func:`time.perf_counter`, **not** :func:`time.monotonic`.
    On this build ``time.monotonic()`` is ``GetTickCount64`` with a
    0.015625 s resolution -- measured, not assumed -- so every sub-tick
    measurement truncates to 0 and durations come out as 14, 0, 0, 16, 0, 0.
    ``perf_counter`` is QPC and has the resolution this needs.
    """
    t0 = time.perf_counter()
    argv = build_argv(target, input_file, target_python, target_args)

    first = _run_once(argv, timeout_ms, note="%s %dB" % (op, _size_of(input_file)))
    if first is None:
        # Timed out once -- confirm before calling it a hang.
        second = _run_once(argv, timeout_ms, note="%s %dB" % (op, _size_of(input_file)))
        if second is not None:
            # The target finished on the retry, so the input does not hang.
            # The first timeout was machine state, not a defect; report what
            # actually happened instead of fabricating a TIMEOUT family.
            status, code, msg, _ = second
            return {"status": status, "exit_code": code, "error_message": msg,
                    "_elapsed_ms": int((time.perf_counter() - t0) * 1000)}
        # Hung twice: reproducible, and a genuine observation.
        return {"status": "TIMEOUT", "exit_code": 0, "error_message": "",
                "_elapsed_ms": int((time.perf_counter() - t0) * 1000)}

    status, code, msg, _ = first
    return {"status": status, "exit_code": code, "error_message": msg,
            "_elapsed_ms": int((time.perf_counter() - t0) * 1000)}


# ---------------------------------------------------------------------------
# Hypothesis generation (lazy: pays the 477 ms import only if actually used)
# ---------------------------------------------------------------------------

_hypothesis = None


def _hp():
    global _hypothesis
    if _hypothesis is None:
        warnings.filterwarnings("ignore")
        import hypothesis as h
        import hypothesis.strategies as st
        from hypothesis import given, settings, HealthCheck, errors
        _hypothesis = {"h": h, "st": st, "given": given,
                       "settings": settings, "HealthCheck": HealthCheck,
                       "errors": errors}
    return _hypothesis


def _draw_one(strategy) -> object:
    """Ask Hypothesis for exactly one example of ``strategy``.

    See module docstring point 3 for why one example and why variety is
    pushed into the strategy's constraints instead.
    """
    hp = _hp()
    out = []

    @hp["given"](strategy)
    @hp["settings"](derandomize=False, database=None, deadline=None,
                    max_examples=1, print_blob=False,
                    suppress_health_check=list(hp["HealthCheck"]),
                    report_multiple_bugs=False)
    def _capture(x):
        out.append(x)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _capture()
    except hp["errors"].StopTest:
        pass
    if not out:
        raise RuntimeError("hypothesis produced no example")
    return out[0]


def build_strategy(gen: str, params: random.Random):
    """Seed-derived constraints under which Hypothesis draws the structure."""
    hp = _hp()
    st = hp["st"]

    if gen == "hypothesis_nested_json":
        # Depth band is chosen by the seed, not drawn from a wide range:
        # with max_examples=1 the depth drawn is always the band's floor, so
        # the floor *is* the knob. Bands at or above ~110 reach the target's
        # stack-overflow path; lower bands reach structural errors.
        lo = params.choice([1, 8, 40, 70, 110, 140, 180, 220])
        hi = lo + params.randint(0, 40)
        leaf = (st.none() | st.booleans()
                | st.integers(-999999, 999999) | st.text(max_size=4))

        @st.composite
        def _nested(draw):
            depth = draw(st.integers(min_value=lo, max_value=hi))

            def make(d: int):
                if d <= 0:
                    return draw(leaf)
                if draw(st.booleans()):
                    return [make(d - 1)]
                return {"k": make(d - 1)}

            return make(depth)

        return _nested()

    if gen == "hypothesis_extreme_num":
        lo, hi = params.choice([
            (65536, 65536), (32768, 32768), (65535, 65536),
            (2147483647, 2147483647), (-2147483648, -2147483648),
            (65536, 10 ** 19), (-10 ** 19, -1),
        ])
        n_items = params.randint(1, 3)

        @st.composite
        def _extreme(draw):
            return {
                "v": draw(st.integers(min_value=lo, max_value=hi)),
                "arr": draw(st.lists(st.integers(min_value=lo, max_value=hi),
                                     min_size=n_items, max_size=n_items + 2)),
            }

        return _extreme()

    if gen == "hypothesis_string_run":
        # The target's access violation needs >= 16 consecutive 'A' inside one
        # string token, so the run length has a hard floor, not a wide range.
        run = params.choice([16, 24, 32, 48, 64])
        prefix = params.choice(["", "pre", '"', "{"])
        alphabet = params.choice(["A", "AB", "Axyz", "Aa1_"])

        @st.composite
        def _run(draw):
            body = draw(st.text(alphabet=alphabet, min_size=run, max_size=run + 8))
            return {"k": prefix + body}

        return _run()

    if gen == "hypothesis_malformed":
        mode = params.choice(["truncate", "dangling", "drop_close", "bad_esc"])

        @st.composite
        def _malformed(draw):
            text = draw(st.text(min_size=1, max_size=16))
            n = draw(st.integers(min_value=0, max_value=12))
            if mode == "dangling":
                # Unterminated string ending in a lone backslash: the target's
                # skipEscape returns 0 and the scanner stops advancing.
                return '{"k": "' + text + "\\" * max(n, 1)
            doc = json.dumps({"k": text, "n": n})
            if mode == "truncate":
                cut = params.randint(1, max(1, len(doc) - 1))
                return doc[:cut]
            if mode == "drop_close":
                return doc[:-1]
            return doc.replace('"k"', '"k\\q"')

        return _malformed()

    # ------------------------------------------------------------------
    # Phase 3: INI dialect, for targets/cfgparser.py
    #
    # Each generator below aims at one *specific* planted defect. Firing the
    # JSON generators at an INI target would only ever produce UnknownSection --
    # a single family that the campaign discovers on its first execution and
    # then has nothing left to learn. The point of a structured generator is to
    # reach the target's semantic checks, not merely its syntax error path.
    # ------------------------------------------------------------------

    if gen == "hypothesis_cfg_semantic":
        # Aim at the cross-field rules in cfgparser._validate. The seed picks
        # *which* rule to violate so that one campaign seed walks all of them;
        # Hypothesis draws the values inside that rule.
        mode = params.choice([
            "tls_no_cert",      # tls=true with no cert -> MissingRequired
            "mutex",            # bind_addr + bind_iface -> MutuallyExclusive
            "duplicate",        # same key twice        -> DuplicateKey
            "unknown_section",  # [nope]                -> UnknownSection
            "non_positive",     # port=0                -> NotPositive
            "type_mismatch",    # port=abc              -> TypeMismatch
            "valid",            # a legal document: exercises the OK path
        ])
        n_kv = params.randint(1, 4)

        @st.composite
        def _semantic(draw):
            if mode == "tls_no_cert":
                lines = ["[server]", "tls = true"]
                if n_kv > 1:
                    lines.append("port = %d" % draw(st.integers(1, 65535)))
                return "\n".join(lines) + "\n"

            if mode == "mutex":
                return ("[server]\nport = 80\n"
                        "bind_addr = %s\nbind_iface = %s\n"
                        % (draw(st.sampled_from(["127.0.0.1", "0.0.0.0"])),
                           draw(st.sampled_from(["eth0", "lo"]))))

            if mode == "duplicate":
                value = draw(st.integers(1, 65535))
                return "[server]\nport = %d\nport = %d\n" % (value, value)

            if mode == "unknown_section":
                name = draw(st.sampled_from(["nope", "Server", "", "  server",
                                             "se_rver", "server "]))
                return "[%s]\nport = 80\n" % name

            if mode == "non_positive":
                value = draw(st.integers(-65535, 0))
                return "[server]\nport = %d\n" % value

            if mode == "type_mismatch":
                value = draw(st.sampled_from(["abc", "", "1.5", "true", "0x",
                                              "--", "0b2"]))
                return "[server]\nport = %s\n" % value

            # A document that should parse cleanly. Without this branch the
            # engine would never see the OK path, and a target that always
            # fails looks the same as one that always crashes.
            tls = draw(st.sampled_from(["true", "false"]))
            return ("[server]\n"
                    "port = %d\n"
                    "workers = %d\n"
                    "timeout_ms = %d\n"
                    "tls = %s\n"
                    "cert = server.crt\n"
                    % (draw(st.integers(1, 65535)),
                       draw(st.integers(1, 16)),
                       draw(st.integers(1, 30000)), tls))

        return _semantic()

    if gen == "hypothesis_cfg_nesting":
        # cfgparser._check_nesting recurses NEST_COST frames per level and never
        # consults NEST_LIMIT, so a deep section path reaches RecursionError.
        # Depth is a seed-chosen band (max_examples=1 would otherwise always draw
        # the floor of a wide range); Hypothesis picks which section name repeats.
        levels = params.choice([1, 4, 16, 64, 128, 200, 300])

        @st.composite
        def _nesting(draw):
            part = draw(st.sampled_from(["server", "tls", "logging", "client"]))
            return "[" + ("][".join([part] * levels)) + "]\nport = 80\n"

        return _nesting()

    if gen == "hypothesis_cfg_port":
        # _scale_port truncates to 8 bits and divides by the result, so any
        # multiple of 256 collapses the divisor to zero -> ScaledPortCollapse.
        # The value has to survive the range check first, so the multiplier is
        # capped at 127 (127 * 256 = 32512 < the 32767 envelope).
        hi = params.choice([3, 15, 127])

        @st.composite
        def _port(draw):
            port = draw(st.integers(1, hi)) * 256
            workers = draw(st.integers(1, 8))
            lines = ["[server]", "port = %d" % port, "workers = %d" % workers]
            if draw(st.booleans()):
                lines.append("timeout_ms = %d" % draw(st.integers(1, 30000)))
            return "\n".join(lines) + "\n"

        return _port()

    if gen == "hypothesis_cfg_continuation":
        # A trailing backslash at EOF leaves _continuation_advance returning 0,
        # so the parse cursor never moves and the target hangs. This is the only
        # defect in the target that yields TIMEOUT rather than an exception.
        tails = params.choice(["\\", "\\\\", " \\", "x\\"])

        @st.composite
        def _cont(draw):
            lead = "[server]\nport = %d\n" % draw(st.integers(1, 65535))
            if draw(st.booleans()):
                lead += "workers = 1 "
            return lead + tails + "\n"

        return _cont()

    if gen == "hypothesis_cfg_token":
        # _maybe_intern writes through an unallocated cache once a value holds
        # >= 16 consecutive 'A'. Interning runs before coercion, so the run can
        # sit in any value -- including one that is not a number at all.
        run = params.choice([16, 20, 32, 64])

        @st.composite
        def _token(draw):
            key = draw(st.sampled_from(["port", "workers", "timeout_ms", "cert",
                                        "bind_addr"]))
            prefix = draw(st.sampled_from(["", "1", "AAAA", "-1"]))
            # The run is emitted whole: a Hypothesis-drawn text would frequently
            # break it up with other characters and miss the trigger entirely.
            pad = draw(st.text(alphabet="Aa1_", min_size=0, max_size=4))
            return "[server]\n%s = %sAAAA%s\n" % (key, prefix, "A" * (run - 4) + pad)

        return _token()

    # ------------------------------------------------------------------
    # Phase 4.1: raw dialect — arbitrary binary, no structural assumption
    #
    # The dialect is chosen from the seed bytes' magic number (engine-side,
    # src/engine/profile.nim). When nothing recognises them the answer is
    # still "raw" — never "json", for the reason in GENERATOR_FAMILIES.
    # ------------------------------------------------------------------

    if gen == "raw_bytes":
        # Uniform bytes. This is the baseline: no shape at all, so whatever
        # the target does with arbitrary input is what gets measured.
        size = params.choice([0, 1, 16, 64, 256, 512, 1024, 4096])

        @st.composite
        def _raw_bytes(draw):
            return draw(st.binary(min_size=size, max_size=size))

        return _raw_bytes()

    if gen == "raw_text":
        # Printable text. Uniform bytes die in the format sniffing step for
        # almost every real-world parser, so the strings that parsers spend
        # most of their time on would otherwise go untested.
        alphabet = params.choice([
            # plausible identifiers and paths
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-",
            # whitespace and structural punctuation
            " \t\r\n[]{}<>():,;=\"'",
            # the characters format sniffers key on
            "%#$*+\\|~^&@!?",
            # surrogates and NUL: the Windows CP950 / UTF-8 boundary this
            # project has been bitten by before (adapter-protocol.md §2.2)
            "\x00\xff\ud800\udfffabc",
        ])
        size = params.choice([0, 8, 64, 512, 2048])

        @st.composite
        def _raw_text(draw):
            return draw(st.text(alphabet=alphabet, min_size=size, max_size=size))

        return _raw_text()

    if gen == "raw_magic":
        # A *recognised* header followed by a corrupt payload.
        #
        # Without this the vast majority of draws are rejected at byte 0 and
        # the campaign measures only the magic-number check, never the parser
        # behind it. Keeping the prefix valid is what lets the target reach
        # its length fields, offsets and checksums — the parts a fuzzer is
        # actually trying to break.
        magic = params.choice([
            b"MZ",                       # PE/COFF
            b"\x7fELF",                  # ELF
            b"%PDF-",                    # PDF
            b"PK\x03\x04",               # ZIP (also OOXML/EPUB)
            b"\x1f\x8b\x08",             # gzip
            b"BZh9",                     # bzip2
            b"\xfd7zXZ\x00",             # xz
            b"7z\xbc\xaf\x27\x1c",       # 7z
            b"Rar!\x1a\x07\x00",         # RAR
            b"\x89PNG\r\n\x1a\n",        # PNG
            b"\xff\xd8\xff",             # JPEG
            b"GIF89a",                   # GIF
            b"MSCF",                     # CAB
            b"ustar",                    # POSIX tar (offset 257)
        ])
        tail = params.choice([0, 16, 64, 512, 1024])

        @st.composite
        def _raw_magic(draw):
            # The tail is uniform bytes: past the header, anything goes.
            return magic + draw(st.binary(min_size=tail, max_size=tail))

        return _raw_magic()

    raise ValueError("unknown generator: %r" % (gen,))


def generate(gen: str, seed: int) -> bytes:
    params = random.Random(seed)
    value = _draw_one(build_strategy(gen, params))
    if isinstance(value, (bytes, bytearray)):
        # raw 產生器直接吐位元組。把它們過 JSON 編碼會加上引號與 \uXXXX
        # 转义，于是「任意二进位」实际上变成了一段 ASCII 文本 —— 与想要
        # 测的东西完全不是一回事。
        raw = bytes(value)
    else:
        data = (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
        raw = data.encode("utf-8", "replace")
    if len(raw) > MAX_INPUT_BYTES:
        raw = raw[:MAX_INPUT_BYTES]
    return raw


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

def handle(req: dict) -> dict:
    op = req.get("op")
    target = req.get("target") or ""
    input_file = req.get("input_file") or ""
    timeout_ms = int(req.get("timeout_ms") or 150)
    # 目標旗標：必须与执行器送给我们的完全一致（见 build_argv）。
    target_args = req.get("target_args") or ""
    seed = int(req.get("seed") or 0)
    # Phase 3: an interpreted target is launched with this interpreter. Empty
    # means "the target is a binary", which keeps P1/P2 behaviour untouched.
    target_python = req.get("target_python") or ""
    dialect = req.get("dialect") or ""
    generator = ""

    if op not in ("execute", "generate"):
        return _resp("ERROR", -1, "bridge: unknown op %r" % (op,), input_file, 0, "")
    if not target or not input_file:
        return _resp("ERROR", -1, "bridge: missing target/input_file",
                     input_file, 0, "")

    # The generator family follows the target's input dialect, so pointing the
    # engine at a .py target automatically switches to INI-shaped strategies.
    family = GENERATOR_FAMILIES[dialect_for(target, dialect)]

    t0 = time.perf_counter()
    try:
        if op == "generate":
            generator = req.get("generator") or family[seed % len(family)]
            if generator not in family:
                return _resp("ERROR", -1,
                             "bridge: generator %r not in dialect %r"
                             % (generator, dialect_for(target, dialect)),
                             input_file, 0, "")
            payload = generate(generator, seed)
            os.makedirs(os.path.dirname(input_file) or ".", exist_ok=True)
            with open(input_file, "wb") as fh:
                fh.write(payload)
            # Fall through: always execute what we just wrote, so the
            # observation describes bytes that exist on disk (§3.2).
        obs = observe(target, input_file, timeout_ms, target_python, op,
                      target_args)
    except Exception as exc:
        return _resp("ERROR", -1,
                     "bridge internal error: %s" % exc,
                     input_file, 0, generator)

    if obs.get("status") == "ERROR":
        return _resp("ERROR", -1, obs.get("error_message") or "bridge: no observation",
                     input_file, 0, generator)

    # .get's default is evaluated eagerly, but a hit here is the normal case
    # and this only runs once per request.
    elapsed = obs.get("_elapsed_ms", int((time.perf_counter() - t0) * 1000))
    return _resp(obs["status"], obs["exit_code"], obs.get("error_message", ""),
                 input_file, elapsed, generator)


def _resp(status, exit_code, message, input_file, elapsed_ms, generator) -> dict:
    return {
        "v": PROTOCOL_VERSION,
        "op": "",
        "status": status,
        "exit_code": int(exit_code),
        "error_message": (message or "")[:ERROR_CAP],
        "coverage_signature": None,   # reserved; never fabricated (§3.6)
        "elapsed_ms": int(elapsed_ms),
        "input_file": input_file,
        "generator": generator or "",
    }


def dump(resp: dict) -> str:
    """Serialise, keeping the line under the protocol's message ceiling."""
    line = json.dumps(resp, ensure_ascii=True, separators=(",", ":"))
    if len(line.encode("utf-8")) > MAX_MESSAGE_BYTES:
        resp = dict(resp)
        resp["error_message"] = resp["error_message"][:512] + "…[truncated]"
        line = json.dumps(resp, ensure_ascii=True, separators=(",", ":"))
    return line


# ---------------------------------------------------------------------------
# Serve mode
# ---------------------------------------------------------------------------

_watchdog = None
_watchdog_lock = threading.Lock()


def _arm_watchdog(resp: dict, deadline_s: float) -> None:
    """Guarantee a response, or die trying.

    A bridge that never answers would hang the worker thread that is blocked
    reading it, and the core's own timeout cannot help: it only reaps
    processes it spawned for a single job. So the deadline lives here.

    The callback reports ``ERROR``, never ``TIMEOUT``. At this point we do not
    know whether the *target* hung -- our own ``subprocess.run(timeout=)``
    above is what reports a real hang. Reporting a target hang we cannot
    confirm would inject a fabricated defect into the knowledge base, which
    this project does not do (§3.6). After responding, the process exits so
    the core respawns a fresh one.
    """
    global _watchdog

    def fire():
        resp["status"] = "ERROR"
        resp["exit_code"] = -1
        resp["error_message"] = "bridge watchdog: request exceeded %.0fms" % (
            deadline_s * 1000)
        try:
            with _watchdog_lock:
                sys.stdout.write(dump(resp) + "\n")
                sys.stdout.flush()
        finally:
            os._exit(3)

    with _watchdog_lock:
        if _watchdog is not None:
            _watchdog.cancel()
        _watchdog = threading.Timer(deadline_s, fire)
        _watchdog.daemon = True
        _watchdog.start()


def _serve_one(line: str) -> None:
    try:
        req = json.loads(line)
    except ValueError as exc:
        _serve_refuse("", "bridge: malformed request: %s" % exc)
        return

    # §8: refuse a version we do not claim to speak. Silently interpreting a
    # newer/older request in our own field semantics is how two implementations
    # quietly diverge on the same field name.
    if req.get("v") != PROTOCOL_VERSION:
        _serve_refuse(req.get("op", ""),
                      "bridge: unsupported protocol version %r (bridge speaks %d)"
                      % (req.get("v"), PROTOCOL_VERSION))
        return

    timeout_ms = int(req.get("timeout_ms") or 150)
    # 第一次 generate 要额外付那笔一次性 import，看门狗的宽限不能一样算。
    warm = "hypothesis" in sys.modules or req.get("op") != "generate"
    slack = COLD_SLACK_MS if warm else WARM_SLACK_MS
    _arm_watchdog(_resp("ERROR", -1, "", req.get("input_file") or "", 0, ""),
                  (timeout_ms + slack) / 1000.0)
    try:
        out = handle(req)
    except BaseException:
        out = _resp("ERROR", -1,
                    "bridge internal error: " + traceback.format_exc(limit=4),
                    req.get("input_file") or "", 0, "")
    out["op"] = req.get("op", "")
    _flush(out)


def _serve_refuse(op: str, message: str) -> None:
    """Reply with a well-formed ERROR rather than raising.

    A refusal is still a response (§6): the core must be able to read *why*
    instead of seeing only end-of-stream.
    """
    out = _resp("ERROR", -1, message, "", 0, "")
    out["op"] = op
    _flush(out)


def _flush(resp: dict) -> None:
    global _watchdog
    with _watchdog_lock:
        if _watchdog is not None:
            _watchdog.cancel()
            _watchdog = None
        sys.stdout.write(dump(resp) + "\n")
        sys.stdout.flush()


def _configure_stdio() -> None:
    """Pin stdin/stdout to UTF-8 regardless of the host locale.

    Windows gives a pipe the **console codepage** (cp950 on this machine),
    while Nim writes UTF-8 raw bytes: ``std/json`` escapes control characters
    and quotes but leaves non-ASCII text as-is. The result was that the
    ``target`` path ``...新增資料夾...`` decoded into lone surrogates and
    arrived as ``C:\\...\\udce6\\udc96...ug_genesis`` -- ``[WinError 123]``,
    i.e. the bridge could not find the binary to fuzz.

    The protocol document states UTF-8 (§2.3); this is where it is enforced.
    """
    for stream, err in ((sys.stdin, "replace"), (sys.stdout, "backslashreplace")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue        # Py<3.7: no public API; leave the host default
        try:
            reconfigure(encoding="utf-8", errors=err)
        except (ValueError, OSError):
            pass


def serve() -> int:
    """持久会话主循环。

    ``global _watchdog`` 不是可选的：``_flush`` 对 ``_watchdog`` 有赋值，
    而 Python 是按**整个函数**判定局部/全域的 —— 没有这行声明，函数内对
    ``_watchdog`` 的读取一律是局部读取，会在第一次赋值之前就抛
    ``UnboundLocalError``，于是 bridge 在写出任何响应之前就死掉。
    这正是本行注释存在的原因。
    """
    global _watchdog
    _configure_stdio()

    # 丢弃 stderr（§2.2）：核心在会话存活期间不会汲取这条管道，任何写入
    # 累积到约 4 KB 就会双向卡死。逃逸开关供人工排障使用。
    if os.environ.get("BUG_GENESIS_BRIDGE_STDERR") != "1":
        try:
            sys.stderr = open(os.devnull, "w")
        except OSError:
            pass

    try:
        for line in sys.stdin:
            line = line.strip()
            if line:
                _serve_one(line)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        # stderr 已被丢弃，而核心只认 stdout 的一行。若不吐出去，桥接只会
        # 凭空消失、核心只看见 EOF，而「为什么」永远查不到。这里把它作为
        # 协议允许的 ERROR 响应交回去（§3.3）。
        msg = "bridge fatal: " + traceback.format_exc(limit=4)
        try:
            _flush(_resp("ERROR", -1, msg, "", 0, ""))
        except Exception:
            pass
        return 1
    return 0


def once(req_json: str) -> int:
    req = json.loads(req_json)
    resp = handle(req)
    resp["op"] = req.get("op", "")
    sys.stdout.write(dump(resp) + "\n")
    return 0


def main(argv: list[str]) -> int:
    # Standalone modes keep stderr (they are for humans) but still speak
    # UTF-8 on stdin/stdout, so a request containing a non-ASCII path works
    # identically to one sent over --serve.
    _configure_stdio()
    if len(argv) >= 2 and argv[1] == "--serve":
        return serve()
    if len(argv) >= 3 and argv[1] == "--once":
        return once(argv[2])
    if len(argv) >= 3 and argv[1] == "--generate":
        # Debug helper: print the bytes a generator produces, no target run.
        req = json.loads(argv[2])
        data = generate(req.get("generator") or GENERATORS[0],
                        int(req.get("seed") or 0))
        sys.stdout.buffer.write(data)
        return 0
    sys.stderr.write(__doc__ or "")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
