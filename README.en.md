# BUG GENESIS

[繁體中文](README.md) | English

BUG GENESIS is a local, failure-feedback evolutionary fuzzing research tool. It derives inputs from seed files, launches a specified local target, classifies reproducible failures, minimizes counterexamples, and stores cases and statistics in SQLite. The repository includes intentionally defective JSON and configuration parsers for testing the engine locally.

This is not a coverage-guided fuzzer: it does not collect code coverage. It adjusts mutation strategy weights using outcomes such as passes, failures, new bug families, and environmental noise.

## Defensive purpose and dual-use notice

The intended use is **defensive software testing, quality assurance, security research, and education**. Test only software you own, are commissioned to test, or have explicit written authorization to assess, and use an isolated, recoverable test environment. Unauthorized testing may violate laws, contracts, or terms of service; users are responsible for confirming applicable rules and obtaining authorization.

The engine repeatedly launches a local target, supplies mutated inputs, and may terminate timed-out child processes. The included `vuln_parser` and `cfgparser.py` are **intentionally vulnerable test targets**, not production parsers. Do not point this tool at unknown or production software; start with a low execution count, short timeouts, and a separate database. The engine is not a network scanner and does not discover remote targets; behavior of an external target program is outside this project’s control.

The software and examples are provided “as is,” without warranties of fitness, uninterrupted operation, or completeness of results. To the extent permitted by law, the authors disclaim liability for damages or legal consequences arising from use or misuse. This notice does not authorize testing another party’s systems and does not override applicable law, contracts, or formal authorization.

**License status:** `bug_genesis.nimble` declares MIT in package metadata, but there is currently no root `LICENSE` file. This README disclaimer is not an open-source license. Before publishing or redistributing, confirm the rights holder and license text and add the formal license file. Third-party packages remain subject to their own licenses.

## Features

- Native mutation strategies: bit flips, byte overrides, boundary values, structural corruption, run insertion, nesting growth, block duplication, and token injection.
- Optional Python/Hypothesis generators for JSON, INI, and raw input dialects. The dialect can be specified explicitly or profiled from seed content.
- Failure-directed feedback: raise weights for strategies yielding new families and lower weights for misses/noise while preserving exploration.
- Reproducibility gate: replay observations and compare signatures instead of treating a one-off environmental timeout as a confirmed defect.
- Bug-family deduplication, counterexample minimization, fault-offset tracking, and taint-biased follow-up mutations.
- SQLite storage for raw test bytes, families, reproducers, strategy statistics, and run records.
- Read-only browser console with a 3D graph, timeline, and details. It can download reproducers but never executes targets in the browser.
- Local checks for reproducibility, input profiling, bridge timing, database round trips, and process cleanup.

The bridge selects generators by dialect: JSON uses `hypothesis_nested_json`, `hypothesis_extreme_num`, `hypothesis_string_run`, and `hypothesis_malformed`; INI uses `hypothesis_cfg_semantic`, `hypothesis_cfg_nesting`, `hypothesis_cfg_port`, `hypothesis_cfg_continuation`, and `hypothesis_cfg_token`; raw uses `raw_bytes`, `raw_text`, and `raw_magic`.

## Requirements

- Nim 2.0+ and Nimble; examples use PowerShell on Windows. The `db_connector` SQLite driver is declared in `bug_genesis.nimble`.
- Python (Python 3.9+ recommended) for Python targets and the bridge. Hypothesis is optional; install it to use the generator adapter: `python -m pip install hypothesis`.
- Node.js/npm only for the browser console.

## Build and run

Open PowerShell in the project root:

```powershell
nimble buildAll
```

This builds `build\genesis_core.exe` and the intentionally vulnerable `build\vuln_parser.exe`. For a short run against the default JSON parser, use a separate database to avoid overwriting the existing root `bugs.db`:

```powershell
.\build\genesis_core.exe --target=.\build\vuln_parser.exe --seed-dir=.\seeds --iters=500 --workers=2 --timeout=150 --seed=42 --db=.\build\demo.db
```

The campaign ends when its execution budget is consumed. A nonzero `--seed` makes the engine’s random selection sequence reproducible; external factors such as target behavior and OS scheduling may still change results. When testing the Python configuration target, explicitly set `--target-kind=interpreted` (the default is `executable`):

```powershell
python -m pip install hypothesis
.\build\genesis_core.exe --target=.\targets\cfgparser.py --target-kind=interpreted --dialect=ini --seed-dir=.\seeds_cfg --python=python --iters=500 --workers=2 --timeout=300 --seed=42 --db=.\build\cfg-demo.db
```

Add `--no-hypothesis` to disable the adapter and use only native mutation strategies. `--target-args` splits arguments on whitespace and does not parse shell quoting. If `{input}` is present, the input path is substituted there; otherwise it is appended to the arguments.

### CLI options

| Option | Default / purpose |
|---|---|
| `--help` | Show command help. |
| `--target=PATH` | Target path; if omitted, looks for `vuln_parser` next to the engine executable. |
| `--target-kind=KIND` | `executable` or `interpreted`; default is `executable`. Explicitly use `interpreted` for Python scripts. |
| `--dialect=NAME` | `json`, `ini`, or `raw`; profiled from seed content when omitted. |
| `--target-args=ARGS` | Extra target arguments; supports the `{input}` placeholder. |
| `--seed-dir=PATH` | Seed directory; defaults to `.\seeds`. Only direct files from 1–4096 bytes are loaded. |
| `--db=PATH` | SQLite knowledge base; defaults to `bugs.db`. |
| `--iters=N` | Number of executions; defaults to 5000. |
| `--timeout=MS` | Per-target timeout; defaults to 150 ms and is raised to 10 ms if lower. |
| `--workers=N` | Worker count; defaults to up to 16 or the CPU count. Capped at 6 when using Hypothesis. |
| `--seed=N` | Engine RNG seed; omitted or zero uses the current time. |
| `--report-every=N` | Progress reporting interval; defaults to 1000. |
| `--max-reduce=N` | Maximum target executions for reducing each new family; defaults to 400. |
| `--no-reduce` | Disable counterexample reduction. |
| `--python=PATH` | Python interpreter; defaults to `python`, for the bridge and Python targets. |
| `--python-bridge=PATH` | Hypothesis bridge path; defaults to `adapters\python\bridge.py`. |
| `--no-hypothesis` | Disable Python/Hypothesis generators and use native strategies only. |
| `--quiet` | Suppress per-failure output without disabling database recording. |

## All `.exe` files: purpose and operation

The current `build\` directory contains six executables. They are build artifacts; if they are absent, run `nimble buildAll` for the engine and JSON target, then use the Nim commands below to build the four check programs.

| Executable | Purpose | How to run |
|---|---|---|
| `genesis_core.exe` | Main fuzzing engine: generates/mutates cases, executes the target, classifies and confirms failures, reduces reproducers, and writes SQLite. | `.\build\genesis_core.exe --help` for options; then follow “Build and run.” |
| `vuln_parser.exe` | Intentionally defective JSON parser test target, not the engine. Takes an input file path. | `.\build\vuln_parser.exe .\seeds\01_object.json`. Standalone, it only reports how that input was parsed. |
| `noise_check.exe` | Checks that the reproducibility gate requires the same signature and that environmental noise lowers strategy weight without counting as a confirmed failure. | `.\build\noise_check.exe`; requires `build\vuln_parser.exe`. Rebuild/run: `nim c -r --hints:off targets\noise_check.nim`. |
| `profile_check.exe` | Checks seed profiling, magic bytes, JSON/INI/raw dialect selection, and conservative handling of mixed seeds. | `.\build\profile_check.exe`; rebuild/run: `nim c -r --hints:off targets\profile_check.nim`. |
| `reaper_check.exe` | Windows process-reaper check: confirms that only processes whose command line points into the test temp directory are removed, and that the engine does not reap itself. The Job Object check is skipped on non-Windows. | `.\build\reaper_check.exe`; creates and cleans up test processes. Rebuild/run: `nim c -r --hints:off targets\reaper_check.nim`. |
| `taint_check.exe` | Checks fault-offset extraction, taint sanitization, and mutation bias around tracked offsets. | `.\build\taint_check.exe`; rebuild/run: `nim c -r --hints:off targets\taint_check.nim`. |

The four `*_check.exe` programs are local assertions, accept no CLI options, and do not replace the main engine. Do not run binaries from an untrusted source.

## Project file guide

This guide covers project-owned source, data, and tools. `build\`, `console\node_modules\`, `console\dist\`, `__pycache__\`, and `.hypothesis\` are build, package, or runtime artifacts rather than source code.

### Root and build configuration

| Path | Purpose |
|---|---|
| `bug_genesis.nimble` | Nimble package metadata and tasks: `buildTarget`, `buildEngine`, `buildAll`, and `testAll`. `testAll` builds and runs a 1,500-execution campaign with four workers using the default database path. |
| `config.nims` | Shared Nim settings: ORC memory management, threads, optimization, `src` import path, and `build` output directory. |
| `launch_console.bat` | Windows console launcher: changes to `console`, opens `http://localhost:5178`, and runs the Vite dev server. |
| `bugs.db` | Default engine SQLite knowledge base; may contain prior test inputs and results. Use a new `--db` path for new runs. |
| `p3_*.db` | Existing Phase 3 experiment/campaign database snapshots, including `p3_bench.db`, `p3_bin.db`, `p3_bin_hp.db`, `p3_cfg.db`, `p3_final.db`, `p3_g1.db`, `p3_g2.db`, `p3_g3.db`, `p3_native.db`, `p3_orphan.db`, `p3_reap.db`, `p3_t2.db`–`p3_t12.db`, `p3_trace.db`, and `p3_w.db`. Filenames alone do not fully describe each run; inspect them in the console or query their SQLite `run_log`. |
| `bench.log`, `campaign.log`, `p3_cfg.log` | Existing test/campaign text output, not source code or required runtime configuration. |
| `p3_orphan.db-wal`, `p3_orphan.db-shm` | SQLite WAL/shared-memory sidecars. If a campaign is interrupted, the main `.db` may not include the newest WAL records. Do not copy only a live database file. |

### Engine and targets

| Path | Purpose |
|---|---|
| `src\genesis_core.nim` | CLI and configuration parsing, target/seed setup, worker scheduling, strategy feedback, database writes, and campaign summary. |
| `src\engine\mutator.nim` | Native mutation strategies, strategy selection and weight updates, input size limits, and taint-guided sampling. |
| `src\engine\executor.nim` | Target launch/termination, timeout confirmation, output normalization and signatures, replay, and native/Python adapter lifecycle. |
| `src\engine\classifier.nim` | Failure-signature classification, reproducibility gate, offset extraction, and delta-debugging reduction. |
| `src\engine\profile.nim` | Profiles seed formats using magic bytes and text structure, selects the Hypothesis dialect, and falls back to raw for mixed formats. |
| `src\engine\reaper.nim` | Windows Job Object child-process lifecycle management and startup orphan cleanup; non-Windows does not provide equivalent immediate Job Object cleanup. |
| `src\storage\db.nim` | SQLite schema, CRUD for cases/families/reproducers/strategy stats/runs/noise/tainted offsets, and summary reporting. |
| `src\target\vuln_parser.nim` | Source for the intentionally defective JSON parser benchmark target compiled as `vuln_parser.exe`. Use only for controlled local testing. |

### Python adapter and protocol

| Path | Purpose |
|---|---|
| `adapters\python\bridge.py` | Persistent Python child process. Accepts JSON Lines requests, generates Hypothesis inputs, and executes Python or binary targets. `--serve` is the engine session mode; `--generate` is an internal generator interface, not a general interactive CLI. |
| `docs\adapter-protocol.md` | Adapter Protocol v1: message formats, input/output, status, timeout, signature, adapter errors, and process-management contract. |

### Python targets and checks

| Path | Purpose |
|---|---|
| `targets\cfgparser.py` | Second intentionally defective target: parses and semantically validates INI-style settings. Select it with `--target-kind=interpreted`. |
| `targets\flaky_env.py` | Nondeterministic environmental-noise negative-control target, used to check whether intermittent failures are incorrectly recorded as stable defects. |
| `targets\check_cfgparser.py` | Checks that the expected input paths in `cfgparser.py` are reachable and that observed statuses/messages match expectations. |
| `targets\check_bridge_timing.py` | Compares direct execution with execution through the bridge to look for bridge-induced timeouts. |
| `targets\check_hang_backslash.py` | Counts whether database cases classified as hangs match the target’s trailing-backslash condition. Accepts a database path; defaults to `p3_cfg.db`. |
| `targets\check_hang_reduce.py` | Reads a hang case from the database, replays it with different budgets, and checks whether reduction probes preserve the result. |
| `targets\check_hang_replay.py` | Replays stored hang cases and summarizes reproduction; it executes the test target. |
| `targets\check_odd_hangs.py` | Replays atypical hangs repeatedly with a larger budget to distinguish stable hangs from slow/intermittent execution. |
| `targets\check_kb_roundtrip.py` | Checks knowledge-base byte BLOBs, reproducers, and signatures, and can replay families. Run `python targets\check_kb_roundtrip.py --help` for its arguments. |
| `targets\measure_load_timeout.py` | Replays configuration seeds under concurrent load and measures runtime distributions and timeout risk. |
| `targets\measure_signature_granularity.py` | Applies candidate normalization rules to stored signatures and compares family-merge counts; it measures but does not rewrite the database signatures. |
| `targets\noise_check.nim` | Source for `noise_check.exe`. |
| `targets\profile_check.nim` | Source for `profile_check.exe`. |
| `targets\reaper_check.nim` | Source for `reaper_check.exe`. |
| `targets\taint_check.nim` | Source for `taint_check.exe`. |

Some check scripts execute a target or read a database. Confirm their target/database paths and copy data when needed. The included `p3_*.db` files are experiment snapshots, not recommended destinations for new campaigns.

### Seed data

- `seeds\01_object.json`–`15_config.json`: 15 JSON/text seed inputs with varied JSON structures.
- `seeds_cfg\boundary_port.cfg`, `full.cfg`, `minimal.cfg`, and `nested.cfg`: INI-style configuration seeds.
- `seeds_bin\archive.tar`, `blob.bin`, `header.zip`, `notes.txt`, `real.tar`, and `sample.gz`: binary/text samples for format profiling and raw generation.

The engine reads direct files only (not recursively); empty inputs and files larger than 4096 bytes are not loaded.

### Knowledge-base console

| Path | Purpose |
|---|---|
| `console\index.html` | HTML shell: database picker, timeline slider, replay control, canvases, and information panels. |
| `console\src\main.ts` | Loads the database and renders summaries/timeline/family details; supports reproducer download and discovery replay. |
| `console\src\kb.ts` | Uses sql.js/WASM in the browser to read SQLite tables and shape family, case, strategy, and run data. |
| `console\src\graph.ts` | Renders the 3D family graph with Three.js. Axes represent discovery time, defect class, and leading strategy. |
| `console\src\style.css` | Console styles. |
| `console\package.json`, `console\package-lock.json` | npm scripts and locked frontend dependency versions. |
| `console\tsconfig.json`, `console\vite.config.ts` | TypeScript and Vite configuration; dev server uses `localhost:5178` and may read the parent directory. |
| `console\public\sql-wasm.wasm` | WebAssembly module required by sql.js to query SQLite. |
| `console\public\kb.db` | Optional local database snapshot (not tracked by Git); auto-loaded when present and not updated automatically by engine runs. |
| `console\README.md` | Standalone console documentation and known limitations. |

Start the console:

```powershell
cd console
npm install
npm run dev
```

Open `http://localhost:5178`. Alternatively, run `.\launch_console.bat` from the project root (npm dependencies must already be installed). To avoid publishing local test data, database files are not tracked by Git. The console auto-loads `console\public\kb.db` if present; otherwise use **Open .db** in the upper-left to select a database. To create or refresh a local snapshot, wait for the campaign to finish normally, then copy from the project root:

```powershell
Copy-Item .\build\demo.db .\console\public\kb.db -Force
```

The console is read-only: it cannot start/stop campaigns or execute reproducers in the browser. Do not update its snapshot from a live database or copy only the main `.db` while WAL/SHM sidecars may contain uncheckpointed data.

## Data and limitations

- `test_cases.content` and family `repro` store raw bytes; databases may contain test inputs, so review them before sharing.
- Counterexample reduction costs additional target executions. `--max-reduce` bounds per-family work; `--no-reduce` disables it.
- Timeouts are retried before classification, but system load still affects runtime. Crash-code classification varies by OS; POSIX signals cannot always distinguish hardware fault types.
- Target output capture is capped at 4096 bytes. Targets with large output may block on pipes and be classified as timed out.
- Windows uses a Job Object to manage child processes. Other platforms do not have the same immediate orphan cleanup.
- The frontend reads at most 200,000 cases and 500 run records. Its timeline and strategy graph visualize stored data; they are not live monitoring.

## Validation and frontend build

```powershell
nimble buildAll
python targets\check_cfgparser.py
python targets\check_bridge_timing.py
cd console
npm run build
```

`nimble testAll` runs a 1,500-execution short campaign using the default `bugs.db`. To avoid modifying existing data, use the engine command above with an explicit `--db` path.
