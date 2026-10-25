## genesis_core — 主程式入口與排程中樞。
##
## 整個引擎的大腦，負責指揮閉環運作：
##
##   種子 → 變異(Mutator) → 執行(Executor) → 分類(Classifier)
##        → 落地(DB) → 回饋調整權重(Failure-Directed) → 下一輪
##
## 設計上的幾條硬規則：
##
##   * SQLite 只在主執行緒接觸。工作者執行緒純粹只做「跑一個案例」，
##     因此不需要連線池、不需要鎖，也不會有交易交錯的問題。
##   * 每個工作者寫自己的暫存檔。共用一個檔會讓並行案例互相覆寫，
##     靜默產出大量「輸入與結果對不上」的假資料 —— 這是模糊測試器最典型的
##     自欺方式。
##   * 逾時判定完全交給 executor，主迴圈不看退出碼（見 executor 的文件）。
##   * 反例縮減在主執行緒執行，會短暫停住整池工作者；但每個新族群一生只
##     縮減一次，而且這正是最值得花執行預算的地方。縮減的執行次數有硬上限。
##   * 縮減用較短的逾時。掛死族群的簽章只含 `hang|TIMEOUT|` 與空輸出，而目標
##     程式所有非無窮迴圈路徑都在十毫秒內結束，所以 100ms 與全額逾時對「是否
##     仍重現」給出相同的答案，卻快一個數量級。

import std/[os, parseopt, strutils, monotimes, times, tables, algorithm,
            cpuinfo]
import db_connector/db_sqlite
import engine/[mutator, executor, classifier, profile, reaper]
import storage/db

type
  Config = object
    target:      string
    dbPath:      string
    seedDir:     string
    iters:       int
    timeoutMs:   int
    reduceMs:    int
    workers:     int
    rngSeed:     int64
    reportEvery: int
    doReduce:    bool
    quiet:       bool
    maxAttempts: int
    ## Python/Hypothesis 适配器：bridge.py 位置、直译器、是否启用。
    ## 启用与否会在 campaign 起始定案（找不到桥接就自动降级为纯原生），
    ## 因为「能不能用」是宿主环境的事实，不该由排程在半路猜。
    pythonBridge: string
    pythonCmd:    string
    hypothesis:   bool
    ## 目標是**腳本**而非二進位（Phase 3 的 targets/*.py）。
    ## 執行器會用 `pythonCmd` 啟動它；不開啟就是 P1/P2 的二進位行為。
    targetInterpreted: bool
    ## 目標的輸入方言（`json` / `ini`），決定 bridge 挑哪組 Hypothesis 產生器。
    ## 預設空字串 = 讓 bridge 依副檔名猜；見 AdapterSpec.dialect 的說明。
    dialect: string
    ## 傳給目標的額外旗標（如 `-tf`）。空字串 = 只傳輸入路徑，即原行為。
    ## 見 AdapterSpec.targetArgs 的完整語意。
    targetArgs: string

  Job = object
    payload:  string
    strategy: MutationStrategy
    ## msHypothesis 专用：传给 bridge 作为产生器种子。原生作业固定为 0。
    seed:     int64
    quit:     bool          ## 毒丸：通知工作者收工

  JobResult = object
    payload:  string
    strategy: MutationStrategy
    res:      ExecResult

  WorkerArgs = object
    spec:     AdapterSpec
    workFile: string
    timeoutMs: int
    ## 反例縮減需要**自己**執行目標，而它不經過 TargetAdapter（縮減是在主執行緒
    ## 同步跑的，沒有常駐會話）。因此 targetKind 必須一併帶進去，否則對 Python
    ## 目標的縮減會直接 exec 一個 .py、永遠無法重現，於是每個族群都靜默保留
    ## 未縮減的大輸入 —— 知識庫會悄悄變差，而且沒有任何一行會報錯。
    interpreter: string

# 工作者透過這兩個全域通道與主執行緒溝通。Channel 內部是 C 層的鎖，
# 與 ORC 的引用計數無關，因此跨執行緒傳遞 string 是安全的。
var gJobs:    Channel[Job]
var gResults: Channel[JobResult]

proc workerProc(a: WorkerArgs) {.thread.} =
  ## 每个工作者**独占**自己的适配器。
  ##
  ## 独占而非共享的理由：TargetAdapter 持有一条活的管道与一个 Process，
  ## 共享意味着两个线程同时读写同一条流，而那会产生「输入与结果对不上」
  ## 这种不会崩潰的捾錯 —— 最难查的一类。
  var adapter = initAdapter(a.spec)
  try:
    while true:
      let job = gJobs.recv()
      if job.quit: break
      let wantGen = a.spec.generator == gkHypothesis and
                    job.strategy == msHypothesis
      var r = runJob(adapter, a.workFile, job.payload, a.timeoutMs,
                     job.seed, wantGen)
      if r.invalid and a.spec.generator == gkHypothesis:
        # 协议 §6：死亡的桥接重生后，**该作业再试一次**。
        # 第一次失败已经消耗了 ensureAlive 的额度，第二次若也失败就一定
        # 是重试额度耗尽或桥接反复死亡 —— 那时它会立刻回 invalid 不再起
        # 进程，因此这条路径是有界的，不会变成无限重建。
        r = runJob(adapter, a.workFile, job.payload, a.timeoutMs,
                   job.seed, wantGen)
      gResults.send(JobResult(payload: r.input, strategy: job.strategy, res: r))
  finally:
    # 不回收就会在 campaign 结束后留下 N 个 python 进程。
    closeAdapter(adapter)

const
  ## python 适配器的工作者上限。每个 worker 各持一个常驻直译器（数十 MB），
  ## 而单次目标执行只有几毫秒、桥接开销又被会话摊平 —— 减 worker 不会
  ## 等比例损吞吐，内存却会等比例上升。这是内存预算，不是 CPU 预算。
  MaxPythonWorkers = 6

const Usage = """
BUG GENESIS — failure-directed evolutionary fuzzing engine (Phase 1)

usage: genesis_core [options]

  --target=PATH        instrumented target binary
                       (default: vuln_parser next to this executable)
  --target-kind=KIND   executable | interpreted (default: executable)
                       interpreted: target is a script, launched with --python
  --dialect=NAME       generator dialect: json | ini | raw (default: by content)
                       states the target's input format instead of guessing
  --target-args=ARGS   extra flags for the target, e.g. -tf
                       {input} marks where the input path goes (default: appended)
  --seed-dir=PATH      directory of seed inputs (default: ./seeds)
  --db=PATH            SQLite knowledge base (default: bugs.db)
  --iters=N            number of executions (default: 5000)
  --timeout=MS         per-execution timeout (default: 150)
  --workers=N          worker processes (default: min(cpus, 16))
  --seed=N             RNG seed; defaults to the wall clock
  --report-every=N     progress line interval (default: 1000)
  --max-reduce=N       execution budget per counterexample reduction (400)
  --no-reduce          skip delta reduction
  --python=PATH        interpreter for the Hypothesis adapter (default: python)
  --python-bridge=PATH adapter script (default: adapters/python/bridge.py)
  --no-hypothesis      disable the Python adapter, run native strategies only
  --quiet              suppress per-failure output
  --help               show this message
"""

proc parseCli(): Config =
  result.dbPath      = "bugs.db"
  result.seedDir     = ""
  result.iters       = 5000
  result.timeoutMs   = 150
  result.reduceMs    = 100
  result.workers     = 0
  result.rngSeed     = 0
  result.reportEvery = 1000
  result.doReduce    = true
  result.quiet       = false
  result.maxAttempts = 400
  result.pythonBridge = ""
  result.pythonCmd    = "python"
  result.hypothesis   = true
  result.targetInterpreted = false
  result.dialect    = ""
  result.targetArgs = ""

  var p = initOptParser(commandLineParams())
  for kind, key, val in p.getopt():
    case kind
    of cmdArgument:
      if result.target.len == 0: result.target = key
    of cmdLongOption, cmdShortOption:
      case key
      of "target":       result.target = val
      of "db":           result.dbPath = val
      of "seed-dir":     result.seedDir = val
      of "iters":        result.iters = parseInt(val)
      of "timeout":      result.timeoutMs = parseInt(val)
      of "workers":      result.workers = parseInt(val)
      of "seed":         result.rngSeed = parseBiggestInt(val)
      of "report-every": result.reportEvery = parseInt(val)
      of "max-reduce":   result.maxAttempts = parseInt(val)
      of "python":        result.pythonCmd = val
      of "python-bridge": result.pythonBridge = val
      of "no-hypothesis": result.hypothesis = false
      # Phase 3：目標是腳本時必須明確指定；預設仍是 executable。
      # 否則引擎會直接嘗試啟動 .py，產生啟動失敗而非有效觀測。
      of "target-kind":
        case val
        of "interpreted", "script": result.targetInterpreted = true
        of "executable",  "binary": result.targetInterpreted = false
        else:
          stderr.writeLine("unknown --target-kind: " & val)
          stderr.writeLine("  use: interpreted | executable")
          quit(2)
      of "dialect":       result.dialect = val
      of "target-args":   result.targetArgs = val
      of "no-reduce":     result.doReduce = false
      of "quiet":        result.quiet = true
      of "help", "h":
        echo Usage
        quit(0)
      else:
        stderr.writeLine("unknown option: --" & key)
        stderr.writeLine(Usage)
        quit(2)
    of cmdEnd:
      discard

proc die(msg: string): int =
  stderr.writeLine("genesis_core: " & msg)
  1

proc resolveTarget(cfg: var Config): bool =
  if cfg.target.len == 0:
    ## 不直接用 ExeExt 拼字串：這個常數是不帶點的 "exe"，而且各平臺定義不一致。
    ## 逐一探測可執行副檔名更穩，也自然涵蓋 POSIX 上無副檔名的二進位。
    let base = getAppDir()
    for ext in ExeExts:
      let candidate = if ext.len > 0: base / ("vuln_parser." & ext)
                      else:           base / "vuln_parser"
      if fileExists(candidate):
        cfg.target = candidate
        break
    if cfg.target.len == 0:
      cfg.target = base / "vuln_parser"
  if not fileExists(cfg.target):
    stderr.writeLine("genesis_core: target binary not found: " & cfg.target)
    stderr.writeLine("  build it first with: nimble buildTarget")
    return false
  result = true

proc resolvePython(cfg: var Config): bool =
  ## 探测并确认 Hypothesis 适配器可用；不可用就降级为纯原生，而不是退出。
  ##
  ## 降级而非硬性要求：Phase 1 的八种原生策略已经能独立完成任务，Pytho
  ## 适配器是新增的搜索能力而非硬依赖。但「降级」必须发生在**最开始**
  ## 并明说出来 —— 半路悄悄换掉会把两类案例混进同一份统计。
  if not cfg.hypothesis: return true

  if cfg.pythonBridge.len == 0:
    for candidate in [getAppDir() / "adapters" / "python" / "bridge.py",
                      getCurrentDir() / "adapters" / "python" / "bridge.py"]:
      if fileExists(candidate):
        cfg.pythonBridge = candidate
        break
  if cfg.pythonBridge.len == 0 or not fileExists(cfg.pythonBridge):
    echo "  [适配器] 找不到 bridge.py，本轮关闭 Hypothesis 产生器"
    cfg.hypothesis = false
    return true

  let why = probeInterpreter(cfg.pythonCmd)
  if why.len > 0:
    echo "  [适配器] 直译器 '", cfg.pythonCmd, "' 不可用: ", why,
         "\n           本轮关闭 Hypothesis 产生器（可用 --python=PATH 指定）"
    cfg.hypothesis = false
  result = true

proc resolveSeedDir(cfg: var Config): bool =
  if cfg.seedDir.len == 0:
    for candidate in [getAppDir() / "seeds", getCurrentDir() / "seeds"]:
      if dirExists(candidate):
        cfg.seedDir = candidate
        break
  result = cfg.seedDir.len > 0 and dirExists(cfg.seedDir)

proc loadSeeds(dir: string): seq[string] =
  ## 依大小排序，讓「同一個 seed → 同一條變異序列」在跨機器時仍成立。
  for kind, path in walkDir(dir):
    if kind != pcFile: continue
    try:
      let content = readFile(path)
      if content.len in 1 .. MaxInputLen:
        result.add content
    except CatchableError:
      continue
  result.sort(proc (a, b: string): int = cmp(a.len, b.len))

proc banner(cfg: Config, seedCount: int, detected: Profile) =
  echo repeat('=', 78)
  echo "BUG GENESIS // Phase 2 // 跨語言合約 + 動態適配器"
  echo repeat('=', 78)
  echo "目標        : ", cfg.target
  echo "目標形態    : ", (if cfg.targetInterpreted:
      "interpreted (" & cfg.pythonCmd & ")" else: "executable")
  if detected.kind == "explicit":
    echo "輸入方言    : ", cfg.dialect, " (explicit)"
  else:
    # 說明**為什麼**是這個方言，而不是只印結果。操作者需要能一眼看出
    # 引擎是靠什么猜的 —— 靠副檔名还是靠实际内容 —— 否則「生成器选错了」
    # 与「目标真的只有这个缺陷」在日志上长得一模一样。
    echo "輸入方言    : ", cfg.dialect, " (profile: ", detected.kind,
         ", via ", detected.via, ")"
  echo "知識庫      : ", cfg.dbPath
  if cfg.hypothesis:
    echo "產生器      : python + Hypothesis (", cfg.pythonCmd, ")"
    echo "              bridge = ", cfg.pythonBridge
  else:
    echo "產生器      : native mutation only"
  echo "種子庫      : ", cfg.seedDir, " (", seedCount, " 個有效種子)"
  echo "執行預算    : ", cfg.iters, " 次  x  ", cfg.timeoutMs, "ms 逾時"
  echo "工作者      : ", cfg.workers, " 條執行緒"
  echo "RNG seed    : ", cfg.rngSeed
  echo "反例縮減    : ", (if cfg.doReduce:
      "啟用 (budget " & $cfg.maxAttempts & "/family, " &
      $cfg.reduceMs & "ms probe)" else: "停用")
  echo repeat('=', 78)
  echo ""

proc main(): int =
  var cfg = parseCli()
  if not resolveTarget(cfg):  return die("bad target")
  if not resolveSeedDir(cfg): return die("bad seed directory")
  discard resolvePython(cfg)

  let seeds = loadSeeds(cfg.seedDir)
  if seeds.len == 0:
    return die("seed directory contains no usable input: " & cfg.seedDir)

  # Phase 4.1 — 看种子实际是什么，而不是靠副档名猜。
  #
  # 副档名是使用者随手取的：`parser.bin`、`dump`、`a.dat` 都会让 bridge
  # fallback 到 JSON 产生器，于是一整场 campaign 只会得到格式嗅探的拒绝，
  # 看起来在跑，实际上从未进入解析逻辑。种子字节本身是权威。
  var detected = dominantProfile(seeds)
  if cfg.dialect.len > 0:
    # 使用者明说了就照办 —— 他可能比种子更知道目标要什么（例如种子是
    # 混合的而目标只吃其中一种）。
    detected = Profile(kind: "explicit", dialect: cfg.dialect,
                       via: "command line")
  else:
    cfg.dialect = detected.dialect

  if cfg.workers <= 0:
    # 工作者數決定的是「同時有幾個程序在跑」。目標是每次執行都啟動一個程序，
    # 因此這是 I/O 密集而非 CPU 密集：上限取 16 而不是核心數，避免在大機器上
    # 過度訂購，同時讓主執行緒仍有餘裕處理收割與寫入。
    cfg.workers = max(1, min(countProcessors(), 16))
  if cfg.timeoutMs < 10: cfg.timeoutMs = 10
  # 縮減的探測逾時：夠確認無窮迴圈，但不讓每一次刪除嘗試都等滿全額預算。
  cfg.reduceMs = max(25, min(cfg.timeoutMs, 100))
  if cfg.rngSeed == 0:
    cfg.rngSeed = int64(epochTime() * 1_000_000)

  if cfg.hypothesis and cfg.workers > MaxPythonWorkers:
    echo "  [適配器] 工作者數由 ", cfg.workers, " 降為 ", MaxPythonWorkers,
         "（每个 python worker 各占一个常驻直译器）"
    cfg.workers = MaxPythonWorkers

  banner(cfg, seeds.len, detected)

  let tempRoot = getTempDir() / "bug_genesis"
  createDir(tempRoot)

  # Phase 4.2 — 先收前一次没收拾干净的，再把这次的管起来。
  #
  # 实测：4 个 worker 跑着有真实无限回圈的目标时，只杀引擎 PID（不加 /T）
  # 会留下 1 个 python.exe，两分钟后仍在跑，且永远不会自己退出。sweep 处理
  # 已经发生的孤儿（含本功能上线前的），initReaper 让这一次不再产生孤儿。
  let swept = sweep(tempRoot)
  if swept > 0:
    echo "  [reaper] 清除上次遗留的孤儿程序: ", swept, " 个"
  if not initReaper():
    echo "  [reaper] job object 不可用，本次不提供即时孤儿回收",
         "（行为与 Phase 3 相同，不影响观测）"

  var database: DbConn
  try:
    database = openDb(cfg.dbPath)
    initSchema(database)
  except CatchableError as e:
    return die("cannot open knowledge base " & cfg.dbPath & ": " & e.msg)

  # 承接前一輪的知識：策略戰績直接續用，不必從零重新學習。
  var mut = initMutator(cfg.rngSeed)
  mut.stats = loadStats(database)
  # 只有真启用 python 适配器时才让 msHypothesis 参与抽样。
  # 启用集而非把权重设 0，见 mutator.pickStrategy 的理由。
  if not cfg.hypothesis:
    mut.enabled.excl msHypothesis

  var familyCache = initTable[string, string]()
  for f in database.getFailureHistory(1_000_000):
    familyCache[f.signature] = f.id

  # 模組 4 — 承接知識庫裡既有的感染點。這就是「已知漏洞作為跳板」的持久化
  # 形態：上一輪標記的偏移量，這一輪開始就直接是高優先級，不必重新發現。
  mut.setTainted(database.loadTainted())

  let runId = database.startRun(cfg.target, cfg.workers, cfg.timeoutMs,
                                toHex($cfg.rngSeed))

  let spec =
    AdapterSpec(generator: (if cfg.hypothesis: gkHypothesis else: gkNative),
                targetKind: (if cfg.targetInterpreted: tkInterpreted
                             else: tkExecutable),
                target: cfg.target,
                bridge: cfg.pythonBridge,
                python: cfg.pythonCmd,
                targetPython: (if cfg.targetInterpreted: cfg.pythonCmd else: ""),
                dialect: cfg.dialect,
                targetArgs: cfg.targetArgs)
  ## 縮減用的直譯器：與執行器看到的完全同一個，避免「執行時用 A、縮減時用 B」
  ## 這種會讓反例對不上原始簽章的分裂。
  let reduceInterpreter = spec.targetPython

  gJobs.open()
  gResults.open()

  var threads = newSeq[Thread[WorkerArgs]](cfg.workers)
  for i in 0 ..< cfg.workers:
    let args = WorkerArgs(spec: spec,
                          workFile: tempRoot / ("worker_" & $i & ".in"),
                          timeoutMs: cfg.timeoutMs,
                          interpreter: spec.targetPython)
    createThread(threads[i], workerProc, args)

  let reduceFile = tempRoot / "reducer.in"
  let t0 = getMonoTime()

  var execDone = 0
  var failures = 0
  var newFamilies = 0
  var lastReport = 0
  ## 没有可信观测的次数（适配器起不来、桥接死亡、响应破規）。它们占掉
  ## 执行预算却什么都不证明，必须单独计数并在结束时被看见。
  var adapterErrors = 0
  ## 模組 3 — 被重現閘門擋在缺陷族群之外的觀測次數。
  ## 與 adapterErrors 同樣必須被看見：一个“沒有發現任何問題”的活動，若
  ## 其实是把三十次偶发故障全当杂讯丢掉，報表必须说出这件事。
  var noiseFiltered = 0
  ## 同一簽章連續被擋下的次數。只在本次活動內記憶（可重現性是當前環境的
  ## 性質，見 classifier.MaxNoiseStrikes）。
  var noiseStrikes = initTable[string, int]()
  # 縮減是每個族群一次性成本，必須與轟炸耗時分开计量，否則會把一輪幾十秒
  # 誤報成「引擎只有 30 exec/s」。
  var reduceMsSpent = 0'i64
  # 模組 3 的重現探測是額外執行，不屬於轟炸吞吐，必須與縮減成本一樣分開計量：
  # 混進去會把「引擎跑得慢」誤報成「引擎在驗證」。
  var probeMsSpent = 0'i64
  var probeExecs = 0
  # Phase 4.2 — 中斷失憶的解法。
  #
  # 实测：被 timeout 砍掉的 campaign，run_log 是 execs=0 / families=0，
  # strategy_stats 是 0 列，而 test_cases 里躺着 181~581 笔真实观测。
  # 控制台于是显示「0 次执行」——比没有记录更糟，因为它是一个看似
  # 完整的错误事实。finishRun 只在正常收尾时写，于是任何中断都必然丢。
  #
  # 两个写入点都是幂等的（UPDATE 与 ON CONFLICT DO UPDATE），所以
  # 周期性重写与收尾写入互不干扰。
  const CheckpointMs = 2000
  var lastCheckpoint = getMonoTime()
  var reduceExecs   = 0'i64
  let batchSize = max(cfg.workers, cfg.workers * 16)

  while execDone < cfg.iters:
    let n = min(batchSize, cfg.iters - execDone)

    # --- 派工 ---
    for _ in 0 ..< n:
      let strategy = mut.pickStrategy()
      mut.recordTry(strategy)
      if strategy == msHypothesis:
        # 输入不在这里变样：由 bridge 的 Hypothesis 产生器按 seed 生成。
        # payload 留空，工作者据 strategy 判定这是 generate 而非 execute。
        gJobs.send(Job(payload: "", strategy: strategy,
                       seed: mut.nextSeed()))
      else:
        let payload = mut.mutate(mut.pickSeed(seeds), strategy)
        gJobs.send(Job(payload: payload, strategy: strategy, seed: 0))

    # --- 收割與知識累積（只有主執行緒碰 DB） ---
    for _ in 0 ..< n:
      let job = gResults.recv()
      inc execDone
      let r = job.res

      # 放在迴圈頂部，不是尾端：本迴圈有多處 `continue`（無可信觀測、
      # 空內容），放尾端會讓每一次最需要落盤的失敗路徑反而跳過 checkpoint。
      if (getMonoTime() - lastCheckpoint).inMilliseconds >= CheckpointMs:
        database.finishRun(runId, int64(execDone), int64(newFamilies))
        database.saveStats(mut.stats)
        lastCheckpoint = getMonoTime()

      if r.invalid:
        # 没有可信观测：既不入库也不回馈。记成「通过」会把适配器故障
        # 变成「这里没问题」的证据，而它们什么都没证明。
        inc adapterErrors
        if not cfg.quiet:
          echo "  [adapter error] ", r.output
        continue

      # 采用**实际执行**的字节：原生作业两者相同；python generate 时
      # bridge 已经把它写到磁盘，这里读回的是同一次执行用的那批位元组。
      let payload = r.input
      if payload.len == 0:
        # content 是 NOT NULL BLOB，空值会抛不可处理的 ValueError；
        # 不该让它在主迴圈炸掉，计入 adapterErrors。
        inc adapterErrors
        continue
      # 测试案例记产生器（便于回溯），策略战绩仍记 MutationStrategy。
      let shown = if r.generator.len > 0: r.generator else: job.strategy.label

      if not r.kind.isFailure:
        discard database.savePassingCase(payload, r, job.strategy.label)
        mut.reward(job.strategy, failed = false, isNewFamily = false)
        continue

      inc failures
      let (sig, kindLabel, code) = classify(r)

      # --- 模組 3：重現閘門 -------------------------------------------------
      #
      # 只有「立刻重跑仍然是同一個簽章」的故障才配成為缺陷族群。系統資源不足
      # 引發的假性逾時、第三方函式庫的偶發例外，都在這裡被擋下：記錄、排除、
      # 降權（見 mutator.recordNoise）。
      #
      # 已登記的族群不再探測 —— 它們在首次入庫時就已通過閘門，重測只會白白
      # 燒掉執行預算；而未登記的簽章每次都要重新取证，因此环境变了就能翻身。
      if database.familyIdBySig(sig).len == 0:
        let strikes = noiseStrikes.getOrDefault(sig, 0)
        var confirmed = 0
        if strikes < MaxNoiseStrikes:
          let pt0 = getMonoTime()
          confirmed = confirmSignature(cfg.target, reduceFile, payload,
                                       cfg.reduceMs, sig, ReproProbes,
                                       reduceInterpreter, cfg.targetArgs)
          probeMsSpent += (getMonoTime() - pt0).inMilliseconds
          probeExecs += ReproProbes
        if confirmed < ReproProbes:
          inc noiseFiltered
          noiseStrikes[sig] = strikes + 1
          database.saveNoise(sig, kindLabel, code, shown, r.output,
                             confirmed, ReproProbes)
          mut.recordNoise(job.strategy)
          if not cfg.quiet:
            echo "  [noise] 未通過重現閘門 ", confirmed, "/", ReproProbes,
                 " — 已排除出缺陷族群: ", signatureSample(sig, 56)
          continue

      let (familyId, isNew) = database.upsertFamily(sig, kindLabel, code)
      discard database.saveTestCase(payload, r, sig, familyId,
                                    shown, false)
      mut.reward(job.strategy, failed = true, isNewFamily = isNew)

      if not cfg.quiet:
        echo "[", kindLabel, " ", code, "] exec#", execDone, " strategy=",
             shown, " bytes=", payload.len

      # --- 模組 4：感染點升格 -----------------------------------------------
      #
      # 知識庫一旦標記某個偏移量引發過異常，它就升格為高優先級感染點：
      # mutator.pickPos 會把字元級手法集中到它周圍的窗口，邊界值策略則只在
      # 與它相交的長度/索引欄位上開火（聯合爆破相依指標）。
      #
      # 能走到這裡就代表已經通過重現閘門 —— 雜訊在上面就被 continue 掉了，
      # 否則偶發故障會把偏移量標成感染點，與模組 3 的目的正好相反。
      let off = extractOffset(r.output)
      if off >= 0:
        let hits = database.upsertTainted(off, sig)
        # 只在越過門檻的那一刻升格並廣播：反覆出現才是證據，偶爾一次不是。
        # 之後命中數還會繼續累積，但活躍集只由 loadTainted 依命中度取前 8。
        if hits == TaintHits:
          mut.setTainted(database.loadTainted())
          if not cfg.quiet:
            echo "  *** TAINTED OFFSET @", off, " ***  第 ", hits,
                 " 次引發異常 → 相依的長度/索引欄位進入優先轟炸"

      if isNew:
        inc newFamilies
        familyCache[sig] = familyId
        echo "  *** NEW FAMILY #", familyId, " ***"

        if cfg.doReduce:
          let rt0 = getMonoTime()
          let (repro, attempts) = reduce(cfg.target, reduceFile, payload,
                                         cfg.reduceMs, sig, cfg.maxAttempts,
                                         reduceInterpreter, cfg.targetArgs)
          reduceMsSpent += (getMonoTime() - rt0).inMilliseconds
          reduceExecs += attempts
          # 縮減的每一次刪減都驗證過簽章，但最後一次嘗試只證明「再也刪不掉」，
          # 不等於當下這個字串仍然重現原簽章；而縮減也可能一無所獲（回傳原
          # 輸入）。兩種結果都必須能落庫 —— 「刪不掉」本身就是這個族群的最小
          # 反例，是真實發現而不是沒做事 —— 因此一律在存檔前重新驗證一次，
          # 讓 `bug_families.repro` 恆為「剛剛才被證明過」的東西。
          let vr = execute(cfg.target, reduceFile, repro, cfg.reduceMs,
                           reduceInterpreter, cfg.targetArgs)
          reduceExecs += 1
          if vr.kind.isFailure and vr.signature == sig:
            database.saveRepro(familyId, repro)
            discard database.saveTestCase(repro, vr, sig, familyId,
                                          shown, true)
            if repro.len < payload.len:
              echo "      reduced ", payload.len, "B -> ", repro.len,
                   "B  (", attempts, " executions)"
            else:
              echo "      already minimal (", attempts, " executions)"
            echo "      minimal reproducer: ", preview(repro)
          else:
            echo "      reduction no longer reproduces the signature; ",
                 "keeping the unreduced input"

    if cfg.reportEvery > 0 and execDone >= lastReport + cfg.reportEvery:
      lastReport = execDone
      let execMs = (getMonoTime() - t0).inMilliseconds - reduceMsSpent -
                   probeMsSpent
      let rate = if execMs > 0:
        formatFloat(execDone.float * 1000.0 / execMs.float, ffDecimal, 1)
      else:
        "0.0"
      echo "  ... ", execDone, "/", cfg.iters, " execs | ", failures,
           " failures | ", familyCache.len, " families | ", rate, " exec/s"

  let elapsed = (getMonoTime() - t0).inMilliseconds
  let execMs  = max(0'i64, elapsed - reduceMsSpent - probeMsSpent)

  # 關閉工作者：一人一枚毒丸，收完再 join。
  for _ in 0 ..< cfg.workers:
    gJobs.send(Job(quit: true))
  for t in threads.mitems:
    joinThread(t)
  gJobs.close()
  gResults.close()

  let execRate = if execMs > 0:
    formatFloat(execDone.float * 1000.0 / execMs.float, ffDecimal, 1)
  else:
    "0.0"

  echo ""
  echo "本輪統計      : ", execDone, " 次執行 | ", failures, " 次失敗 | ",
       newFamilies, " 個新族群"
  echo "轟炸耗時      : ", execMs, " ms  (", execRate,
       " exec/s，不含反例縮減)"
  echo "反例縮減      : ", reduceMsSpent, " ms / ", reduceExecs,
       " 次執行 (每族群一次性成本)"
  if probeExecs > 0:
    echo "重現閘門      : ", probeMsSpent, " ms / ", probeExecs,
         " 次探測 (只對未登記簽章)"
  if noiseFiltered > 0:
    echo "環境雜訊      : ", noiseFiltered,
         " 次觀測未通過重現閘門，已排除出缺陷族群 (詳見 noise_log)"
  let taintN = database.taintedCount()
  if taintN > 0:
    echo "感染點        : ", taintN, " 個偏移量反覆引發異常，其中前 ",
         min(taintN, int64(MaxTainted)), " 個正在被優先轟炸"
  if adapterErrors > 0:
    echo "適配器失敗    : ", adapterErrors, " 次沒有可信觀測的執行"
    if adapterErrors == execDone:
      return die("every observation came from a failing adapter")
  echo "總耗時        : ", elapsed, " ms"

  database.saveStats(mut.stats)
  database.finishRun(runId, int64(execDone), int64(newFamilies))
  echo database.renderReport()
  database.close()

  # 纳管成败必须可见。rejected > 0 意味着有子程序没能进 job（嵌套 job 政策、
  # 权限），那正是「引擎退出后仍可能残留」的唯一来源；reaper.nim 的文件承诺
  # 会回报一次，这里就是那一次。全部成功时也给一行，否则这个功能存在与否
  # 在输出上完全无法区分——一个永远不报错的回收器和没有回收器是一样的。
  let (adopted, rejected) = reaperStats()
  if adopted > 0 or rejected > 0:
    echo "孤儿回收        : ", adopted, " 个子程序已纳入 job object"
    if rejected > 0:
      echo "                : ", rejected,
           " 个纳管失败（这些子程序在引擎退出后可能残留）"

  # 关闭 job = 释放它管辖的任何仍在跑的程序。正常收尾时应该已经没有了，
  # 这一行是「campaign 结束后不留任何东西」的最后保证。
  closeReaper()
  0

when isMainModule:
  quit(main())
