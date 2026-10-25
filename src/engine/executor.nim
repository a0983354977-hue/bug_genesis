## executor — 變異案例的執行與沙箱管理。
##
## 這個模組唯一的責任，是把「一個位元組串」轉成「一份可信賴的觀測結果」。
## 所有容易出錯的細節都集中在這裡，因為它決定了上層的分類是否建立在事實
## 之上：
##
##   1. 逾時偵測不能靠退出碼。Windows 的 `waitForExit` 在逾時後會呼叫
##      `TerminateProcess(handle, 0)`，因此掛死的程序回報的退出碼是 **0**，
##      與正常結束完全無法區分 —— 無窮迴圈會被記成「成功」。所以這裡以
##      單調時鐘的經過時間判定逾時，而不是退出碼。
##   2. 崩潰必須是真實的作業系統故障。Nim 預設安裝 SIGSEGV 處理器並以
##      `rawQuit(1)` 結束，把空指標存取偽裝成 exit 1。目標程式必須以
##      `-d:noSignalHandler` 編譯，崩潰碼才會是真實的 NTSTATUS
##      （0xC0000005 / 0xC00000FD / 0xC0000094）。
##   3. 輸出必須在程序完全結束（或被強殺）之後才讀，否則會與其餘額競爭。
##
## 已知侷限（刻意保留而非假裝解決）：輸出走管線，若目標在單次執行中寫出
## 超過管線緩衝區（Windows 約 4KB）的資料，它會在寫入處阻塞並被判定為
## 逾時。本專案的目標只輸出單行診斷，因此不構成風險；換成真正會大量輸出
## 的標的時，這裡應改為把 stdout/stderr 重導至檔案。

import std/[osproc, streams, monotimes, times, strutils, json]
import engine/reaper

type
  OutcomeKind* = enum
    ok           = "ok"
    logicError   = "logic_error"
    crashAV      = "crash_access_violation"
    crashStack   = "crash_stack_overflow"
    crashFPE     = "crash_int_div_by_zero"
    crashOther   = "crash_other"
    hang         = "hang"

  ExecResult* = object
    input*:    string
    kind*:     OutcomeKind
    rawExit*:  int32
    timedOut*: bool
    elapsedMs*: int64
    output*:   string
    ## python 產生器的名稱（`hypothesis_*`）。原生案例為空。
    generator*: string
    ## true 表示**沒有可信的觀測**（適配器失效、協定破損、通道 EOF）。
    ## 它既不是通過也不是缺陷，因此不得進入知識庫、不得參與回饋。
    ## 與 `kind == ok` 的差別是本質的：後者是「跑過了且沒事」，前者是
    ## 「根本不知道跑成什麼樣」。
    invalid*:  bool

const
  ## 單次執行擷取輸出的上限，防止異常輸出把記憶體與資料庫撐爆。
  MaxCapturedOutput* = 4096
  ## 殺程序後等待其退出的寬限期。
  KillGraceMs = 750

proc isCrash*(k: OutcomeKind): bool =
  k in {crashAV, crashStack, crashFPE, crashOther}

proc isFailure*(k: OutcomeKind): bool =
  k != ok

proc label*(k: OutcomeKind): string =
  ## 穩定的機器可讀名稱（跨執行、跨平台固定），供簽章與資料庫使用。
  ## 不依賴 `$` 或 `repr` 對枚舉的處理，避免編譯器版本差異改動簽章。
  case k
  of ok:           "ok"
  of logicError:   "logic_error"
  of crashAV:      "crash_access_violation"
  of crashStack:   "crash_stack_overflow"
  of crashFPE:     "crash_int_div_by_zero"
  of crashOther:   "crash_other"
  of hang:         "hang"

proc normalizeOutcome*(rawExit: int32, timedOut: bool): OutcomeKind =
  ## 把各平台差異極大的原始退出碼，正規化成單一的失敗語意。
  if timedOut:
    return hang
  if rawExit == 0:
    return ok
  if rawExit == 1:
    return logicError

  when defined(windows):
    # Windows 回報的是 NTSTATUS，高位元 0xC 表示「嚴重錯誤」。
    let code = cast[uint32](rawExit)
    case code
    of 0xC0000005'u32, 0xC0000008'u32, 0xC0000096'u32: crashAV
    of 0xC00000FD'u32:                                  crashStack
    of 0xC0000094'u32, 0xC0000093'u32:                  crashFPE
    else:
      if (code and 0xF0000000'u32) == 0xC0000000'u32: crashOther
      else:                                           logicError
  else:
    # POSIX 由 osproc 以 128 + signal 回報。
    case rawExit
    of 139: crashAV     # SIGSEGV —— 與堆疊溢位同碼，見下方說明
    of 136: crashFPE    # SIGFPE
    of 134: crashOther  # SIGABRT
    of 132: crashOther  # SIGILL
    of 135: crashOther  # SIGBUS
    else:   logicError

proc canonicalCode*(r: ExecResult): string =
  ## 跨平台穩定的故障代碼字串，作為簽章的一部分。
  ## 注意：POSIX 上空指標存取與堆疊溢位都是 139（SIGSEGV），單靠退出碼無法
  ## 區分；Windows 的 NTSTATUS 則能分辨（0xC0000005 vs 0xC00000FD）。若目標
  ## 要在 POSIX 上被分辨，需要 minidump/coredump 的額外證據。
  if r.kind == hang:      return "TIMEOUT"
  if r.kind == ok:        return "EXIT_0"
  if r.kind == logicError: return "EXIT_1"
  when defined(windows):
    "NTSTATUS_0x" & toUpperAscii(toHex(cast[uint32](r.rawExit), 8))
  else:
    "SIGNAL_" & $r.rawExit

proc boundedRead(s: Stream, cap: int): string =
  if s == nil: return ""
  result = s.readAll()
  if result.len > cap:
    result = result[0 ..< cap] & "\n...[output truncated]"

proc runOnce(exe: string, argv: seq[string], timeoutMs: int): tuple[
    timedOut: bool, rawExit: int32, output: string, elapsedMs: int64] =
  ## 執行**一次**並回傳原始觀測。這是唯一會起程序的地方。
  ##
  ## 拆出來是為了讓逾時確認（見 `execute`）能重跑同一段邏輯而不重寫 ——
  ## 兩份啟動程式碼會各自漂移，而漂移的症狀是「有時候」重現。
  let t0 = getMonoTime()
  var p: Process
  try:
    p = startProcess(exe, args = argv,
                     options = {poUsePath, poStdErrToStdOut})
  except OSError as e:
    return (false, -1'i32, "executor: failed to start target: " & e.msg,
            (getMonoTime() - t0).inMilliseconds)

  # 放进 job：引擎一旦不在了，OS 会替我们把挂死的目标收掉。
  # 必须紧跟 startProcess —— 中间任何一次失败都会留下没被看管的程序。
  adopt(p.processID)

  try:
    let code = waitForExit(p, timeoutMs)
    let elapsed = (getMonoTime() - t0).inMilliseconds

    # 逾時判定：只有當等待時間撐滿整個預算，才可能是逾時。正常結束必定遠
    # 早於預算，所以這個判準對所有非退化情況都是精確的。退出碼一律不採信，
    # 因為 Windows 會把被強殺的程序回報成 0。
    var timedOut = elapsed >= timeoutMs or code == -1
    if timedOut:
      # waitForExit 已嘗試過 terminate；它若沒死，這裡升級為 kill 並回收。
      if running(p):
        kill(p)
        discard waitForExit(p, KillGraceMs)

    result = (timedOut, int32(peekExitCode(p)),
              boundedRead(p.outputStream, MaxCapturedOutput),
              (getMonoTime() - t0).inMilliseconds)
  except CatchableError as e:
    result = (false, -1'i32, "executor: " & e.msg,
              (getMonoTime() - t0).inMilliseconds)
  finally:
    try:
      close(p)
    except CatchableError:
      discard

proc buildTargetArgv*(binPath, workFile, interpreter, extraArgs: string):
    tuple[exe: string, argv: seq[string]] =
  ## 「目標怎麼啟動」的**唯一**定義點。
  ##
  ## 原生路徑、直譯器路徑、縮減、重放全走這裡。多一處副本就多一份可能
  ## 漂移的啟動邏輯，而漂移的症狀是「縮減時能重現、執行時不能」這類只在
  ## 特定路徑出現的故障。
  ##
  ## `argv` 是 **`exe` 之後**的參數（osproc 的 `args`），所以二進位目標
  ## 不含 binPath，直譯器目標才把腳本路徑放在最前。
  var argv: seq[string] = @[]
  if interpreter.len > 0:
    argv.add(binPath)

  let hasPlaceHolder = "{input}" in extraArgs
  if extraArgs.len > 0:
    for part in extraArgs.split(Whitespace):
      if part.len == 0: continue
      if hasPlaceHolder and part == "{input}":
        argv.add(workFile)
      else:
        argv.add(part.replace("{input}", workFile))
    if not hasPlaceHolder:
      argv.add(workFile)
  else:
    argv.add(workFile)

  result.exe  = if interpreter.len > 0: interpreter else: binPath
  result.argv = argv

proc execute*(binPath, workFile: string, input: string, timeoutMs: int,
              interpreter = "", extraArgs = ""): ExecResult =
  ## 執行單一變異案例，回傳不可變的觀測結果。
  ## 這個程序不拋出例外：任何啟動失敗都會被轉成明確的結果，讓模糊測試迴圈
  ## 不會因為一次啟動失敗而中斷。
  ##
  ## `interpreter` 非空時，目標是**腳本**而非二進位：以該直譯器啟動
  ## （`python <target> <input>`）。這是 Phase 3 的 Python 目標走原生變異
  ## 策略時的路徑 —— 它不需要 bridge，因為輸入在 Nim 端就已經產生好了。
  result.input = input
  writeFile(workFile, input)

  let (exe, argv) = buildTargetArgv(binPath, workFile, interpreter, extraArgs)

  var first = runOnce(exe, argv, timeoutMs)

  # 逾時**不是**缺陷斷言，而是一個「沒能在預算內跑完」的觀測。把前者當成
  # 後者會在知識庫裡編造出無法重現的缺陷。
  #
  # 這不是假設：Phase 3 對 Python 目標的 5209 次轟炸中，引擎記下 1012 筆
  # `hang|TIMEOUT|`（全是 raw_exit=0）。逐一重放後只有 141 筆真的掛住，
  # 其餘 871 筆在 38-57ms 內正常結束 —— 86% 是偽造的族群。當時與重放的
  # 差別只在於機器當時的狀態，輸入一個位元組都沒變。
  #
  # 因此超時一律重跑一次。兩次都超時才算掛死；只要有一次正常結束，就採用
  # 那一次的真實結果 —— 那才是這批位元組真正做了什麼。
  if first.timedOut:
    let second = runOnce(exe, argv, timeoutMs)
    if not second.timedOut:
      # 第二次跑完了：輸入並不會掛死。第一次的超時是環境造成的，不可信。
      result.kind     = normalizeOutcome(second.rawExit, false)
      result.rawExit  = second.rawExit
      result.output   = second.output
      result.elapsedMs = second.elapsedMs
      result.timedOut = false
      return
    # 兩次都掛住 —— 這是可重現的掛死，才是缺陷。
    first = second

  result.kind     = normalizeOutcome(first.rawExit, first.timedOut)
  result.rawExit  = first.rawExit
  result.output   = first.output
  result.elapsedMs = first.elapsedMs
  result.timedOut = first.timedOut

proc normalizeOutput*(s: string): string =
  ## 抹除會讓同一個缺陷產生不同簽章的易變部分。
  ##
  ## 兩條規則，依序套用：
  ##
  ##   1. 數字連 run → `#`。行號、位址、數值。
  ##   2. 引號內的文字 → `#`，引號本身保留。
  ##
  ## 第 2 條是量測之後才加的，不是憑直覺。Phase 4 對 Python 目標的
  ## 6000 次轟炸產生 1549 個族群，其中 1548 個是 logic_error；逐一檢視後
  ## 發現它們其實只有 4 種真實缺陷 —— 目標把**出錯的輸入原文**用 `%r`
  ## 迴印進訊息（`MalformedLine '<原文>'`、`UnknownSection name='<原文>'`），
  ## 所以每一個不同輸入都是一個新族群。套用這條規則後是 46 個族群，
  ## 合併 97%（1549 → 46，實測於 targets/measure_signature_granularity.py）。
  ##
  ## 缺陷的身分在**訊息模板**，不在它迴印的資料，而模板完整保留：
  ## `MalformedLine` 與 `UnknownSection` 仍是兩個族群，只是同一個
  ## `UnknownSection` 不再被幾百個不同段名拆成幾百個。
  ##
  ## 曾评估「同字元连 run ≥3」与「data-key 数值」两条规则，前者合併 0 個
  ##（重複內容都在引號內，已被前一條吃掉），後者只多合併 1 個 —— 都不值得
  ## 加进签名逻辑。规则以量测为准，不以直觉为准。
  ##
  ## 代价（诚实记录，因为这里有一个真实的取舍）：若两个缺陷的**唯一**差异
  ## 在于引号内的字面值，这条规则会把它们合并。实测两个目标都没有这种
  ## 讯息 —— 原生目标的讯息完全不含引号，Python 目标的差异键
  ##（`key=` / `section=` / `expected=`）都在引号外。这是刻意的取舍：
  ## 把输入资料放进签名造成的碎片化（34 倍）比这个罕见的过度合并严重得多，
  ## 而且碎片化的症状更隐蔽 —— 知识库看起来「找到一千五百个 bug」，
  ## 实际上只有四种。
  var chunks: seq[string]
  for line in s.splitLines():
    let t = line.strip()
    if t.len == 0: continue
    var norm = newStringOfCap(t.len)
    var i = 0
    while i < t.len:
      let c = t[i]
      if c in Digits:
        while i < t.len and t[i] in Digits: inc i
        norm.add('#')
      elif c == '\'' or c == '"':
        # 引号内容 → 单一 #；引号本身留下，让 `value='#'` 与未加引号的
        # 参数（`key=tls`）仍可分辨。未闭合的引号（模糊测试极常见）
        # 扫到行尾为止，不抛异常也不把后半行漏掉。
        norm.add(c)
        inc i
        var closed = false
        while i < t.len and t[i] != c:
          inc i
        if i < t.len: closed = true
        norm.add('#')
        if closed:
          norm.add(c)
          inc i
      else:
        norm.add(c)
        inc i
    chunks.add(norm.strip())
  chunks.join(" | ")

proc signature*(r: ExecResult): string =
  ## 缺陷簽章：結果類型 + 跨平台故障代碼 + 正規化後的輸出。
  ## 這是去重與分類的唯一依據 —— 兩個執行只有在簽章完全相等時才算同一缺陷，
  ## 因此 exit 1 的 JsonError 與 exit 1 的 ValueError 會被分到不同族群。
  r.kind.label & "|" & r.canonicalCode & "|" & r.output.normalizeOutput

proc reproduces*(binPath, workFile, input: string, timeoutMs: int,
                 wantSig: string, interpreter = "", extraArgs = ""): bool =
  ## 供反例縮減使用：判斷某個候選輸入是否仍重現同一個缺陷。
  ## 簽章完全相符才算重現，避免縮減過程把缺陷換成另一個缺陷。
  ##
  ## 這裡**不經過 bridge**，因為 bridge 是**產生器**的會話；重放要回答的是
  ## 「這批位元組本身是否仍然重現」，那與誰產生它無關。這也順便成為跨語言
  ## 合約的持續驗證 —— bridge 若把崩潰標錯，重放就會拿到不同簽章，縮減會回報
  ## 「no longer reproduces」而不是寫進知識庫。
  ##
  ## `interpreter` 必須與執行器當時用的相同（Phase 3 腳本目標）：用錯直譯器
  ## 去重放會一律得到「啟動失敗」，簽章必然不符，於是所有反例都靜默縮不掉。
  let r = execute(binPath, workFile, input, timeoutMs, interpreter, extraArgs)
  r.kind.isFailure and r.signature == wantSig

# ---------------------------------------------------------------------------
# TargetAdapter — 動態適配器
#
# 本模組對外只暴露兩種執行入口，主迴圈根據 AdapterSpec 決定用哪一条：
#
#   * 原生：`execute` 直接起目標程序（Phase 1 行為，完全未改）。
#   * Python：常駐 `bridge.py` 的 JSON-line 會話（docs/adapter-protocol.md）。
#
# 为什么不把两者统一成一个 `execute`：原生路径的重活是「启进程」，而 python
# 路径的重活是「保持会话」，生命周期不同 —— 后者会跨成百次任务存活，必须由
# 拥有它的那个 worker 独占并负责回收。用同一个入口会隐藏这个所有权问题。
#
# ---------------------------------------------------------------------------
# Phase 3：兩個獨立的軸，而不是一個 enum
#
# P2 的 `AdapterKind` 把「輸入由誰產生」與「目標由誰執行」綁在同一个值上，
# 於是只有兩種組合存在：原生目標+原生變異、原生目標+Hypothesis。Phase 3 要的
# **Python 目標**（targets/cfgparser.py）在那個型別裡根本表達不出來 —— 那不是
# 少寫一支程式，是型別拒絕承載這個概念。
#
# 拆開後兩個軸各自獨立，四種組合都有意義：
#
#   generator=native     target=executable   P1/P2 原生路徑（未改）
#   generator=hypothesis target=executable   P2 跨語言路徑（未改）
#   generator=native     target=interpreted  P3：原生變異打 Python 目標
#   generator=hypothesis target=interpreted  P3：Hypothesis 打 Python 目標
#
# 之後要加「Rust 目標 + Hypothesis 產生器」只需各加一個值，不需要第三個 enum。
# ---------------------------------------------------------------------------

const
  ## docs/adapter-protocol.md §2.1。两侧不一致就必须拒绝会话。
  BridgeProtocolVersion* = 1
  ## 连续几次起不起桥接就判定适配器不可用。
  MaxRestarts = 3
  ## 直译器探测（`python --version`）的上限。
  ProbeTimeoutMs = 10_000

type
  GeneratorKind* = enum
    ## 輸入由誰產生。
    gkNative    = "native"      ## Nim 端的位元級變異（P1 的八種策略）
    gkHypothesis = "hypothesis"  ## bridge 端的 Hypothesis 產生器

  TargetKind* = enum
    ## 目標由誰執行。
    tkExecutable  = "executable"   ## 可直接啟動的二進位（P1/P2）
    tkInterpreted = "interpreted"  ## 需解譯器的腳本（P3 的 Python 目標）

  AdapterSpec* = object
    generator*: GeneratorKind
    targetKind*: TargetKind
    ## 真正被测的二进位 —— 两种适配器都需要，python 路径只是把它转交给 bridge。
    target*: string
    ## bridge.py 的绝对路径。`generator == gkHypothesis` 时必填。
    bridge*: string
    ## 启动 bridge 的直译器。
    python*: string
    ## `targetKind == tkInterpreted` 时启动目標用的直译器；为空则由
    ## bridge 用自己所在的直译器（`sys.executable`）。原生目标恆为空。
    targetPython*: string
    ## 目標的**輸入方言**（`json` / `ini`），決定 bridge 挑哪一組 Hypothesis
    ## 產生器。空字串表示「讓 bridge 依副檔名猜」。
    ##
    ## 為什麼不只靠副檔名：那只是啟發式。目標若叫 `parser` 或 `parser.bin`，
    ## bridge 會靜默給它 JSON 產生器，於是一整場 campaign 只會挖到
    ## `UnknownSection` 一個族群，看起來很 productive 實則毫無覆蓋 —— 這種
    ## 靜默降級正是本專案最不能接受的失敗模式。
    dialect*: string

    ## 傳給目標的**額外旗標**（例如 `tar -tf {input}` 中的 `-tf`）。
    ##
    ## 為什麼需要：執行器原本只把輸入檔路徑當作**唯一**的參數。這對直接讀
    ## 檔的目標夠用，但真實世界的二進位幾乎都要求旗標 —— 沒有 `-tf`，
    ## `tar` 會把輸入檔名當成子命令，回覆 Usage 而非解析檔案，於是一整場
    ## campaign 都在測參數解析器而非目標格式。
    ##
    ## 語意（兩種都支援，見 `buildTargetArgv`）：
    ##   * 含 `{input}` —— 在該位置插入輸入檔路徑；
    ##   * 不含 —— 在末尾追加輸入檔路徑。
    ## 空字串維持原行為。
    ##
    ## 以**空白切開，不做 shell 引號解析**（`"a b"` 會被拆開）。目標旗標
    ## 需要空白的場景目前不存在，而引入引號解析就多一套與 shell 不同的
    ## 語意可供使用者踩。
    targetArgs*: string

  TargetAdapter* = object
    ## 每个 worker 独占一个。`Process` 不是线程安全的，跨线程共享会让一边读、
    ## 一边写同一条管道，而这种损坏的病症是「输入与结果对不上」而不是崩溃。
    spec*:      AdapterSpec
    child*:     Process
    toChild*:   Stream
    fromChild*: Stream
    alive*:     bool
    restarts*:  int

proc startBridge*(a: var TargetAdapter): bool =
  ## 建立常驻会话。失败不抛异常 —— 起不来的桥接应该让该 worker 交回
  ## 「无观测」，而不是炸掉整个campaign。
  a.alive = false
  if a.spec.generator != gkHypothesis: return false
  try:
    # 故意**不含** poStdErrToStdOut：协议住在 stdout 上，把 stderr 合进
    # 来就会让 bridge 印到 stderr 的任何一行污染协议流。
    # poDaemon 让 Windows 不闪出控制台窗口；bridge 自己再把 stderr 丢到
    # devnull，否则这个无人汲取的管道撑到 4KB 就会双向卡死。
    a.child = startProcess(a.spec.python,
                           args = [a.spec.bridge, "--serve"],
                           options = {poUsePath, poDaemon})
    a.toChild   = a.child.inputStream
    a.fromChild = a.child.outputStream
    a.alive = true
    # bridge 是长驻的，同样受 job 管辖：它靠 stdin 关闭自行退出，但那条
    # 退路只在父进程**优雅**死亡时成立。
    adopt(a.child.processID)
  except CatchableError:
    a.child = nil
    a.alive = false
  result = a.alive

proc closeAdapter*(a: var TargetAdapter) =
  ## 会话正常收尾。不这么做的话 campaign 结束后会留下 N 个 python 进程。
  if a.child != nil:
    try:
      if a.toChild != nil: a.toChild.close()
    except CatchableError:
      discard
    # 关掉 stdin 让 bridge 的 stdin 循环自然结束，优先走优雅退出而非强杀。
    try:
      if running(a.child): discard waitForExit(a.child, 1500)
    except CatchableError:
      discard
    try:
      if running(a.child):
        kill(a.child)
        discard waitForExit(a.child, 500)
    except CatchableError:
      discard
    try:
      close(a.child)
    except CatchableError:
      discard
  a.child = nil
  a.toChild = nil
  a.fromChild = nil
  a.alive = false

proc initAdapter*(spec: AdapterSpec): TargetAdapter =
  result.spec = spec
  result.alive = false
  if spec.generator == gkHypothesis:
    discard startBridge(result)

proc ensureAlive(a: var TargetAdapter): bool =
  ## 会话活着就直接用；需要重开时消耗一次额度。
  ##
  ## **不在这里归零**：只有「真的拿到一次完整响应」才算成功（见
  ## pythonRequest）。若在 `alive` 分支重置，每次重启都立刻归零，
  ## MaxRestarts 永远到不了 2，一个反复死亡的桥接就会被无限制重建。
  if a.alive:
    return true
  if a.restarts >= MaxRestarts:
    return false
  inc a.restarts
  startBridge(a)

proc bridgeRequest(a: var TargetAdapter, req: JsonNode): JsonNode =
  ## 送一行、收一行。回传 nil 表示通道失效（EOF、bridge 非零退出、协定破损）。
  ## 这里**不设超时** —— bridge 的看门狗（协议 §2.2）保证在
  ## `timeout_ms + slack` 内必然写下一行后自行退出，而 osproc 的 Stream
  ## 没有可轮询的等待接口，所以是「看门狗保证」而非「本地计时器保证」。
  ## bridge 若真的原生卡死，readLine 会返回 false 并把会话标为死亡。
  if not a.alive: return nil
  try:
    a.toChild.write($req & "\n")
    a.toChild.flush()
    var line = ""
    if not a.fromChild.readLine(line):
      a.alive = false
      return nil
    result = parseJson(line)
  except CatchableError:
    a.alive = false
    result = nil

proc kindOfStatus*(s: string; known: var bool): OutcomeKind =
  ## 协议 §3.5 的 status → 本模组的 OutcomeKind。
  ## 未知值不算可用观测 —— 静默映射成 ok 会让适配器的 bug 变成「一切正常」。
  known = true
  case s
  of "OK":            ok
  of "LOGIC_ERROR":   logicError
  of "CRASH_AV":      crashAV
  of "CRASH_STACK":   crashStack
  of "CRASH_FPE":     crashFPE
  of "CRASH_OTHER":   crashOther
  of "TIMEOUT":       hang
  else:
    known = false
    ok

proc jstr(n: JsonNode, key: string, dflt: string = ""): string =
  ## 取物件栏位的字串值；缺失、型别不符都回 default，不抛异常。
  ##
  ## 直接用 `n.getStr(...)` 会有两个坑：它要的 default 在第一位，而
  ## 标准库的三参数形式在本版不可用；更重要的是它不接受 key，得用 `n{key}`，
  ## 而 `{}` 对**非物件**节点也会回 nil —— 协定破损时那里正好是 JArray。
  if n != nil and n.kind == JObject and n.hasKey(key):
    result = n[key].getStr(dflt)
  else:
    result = dflt

proc jint(n: JsonNode, key: string, dflt: int64): int64 =
  if n != nil and n.kind == JObject and n.hasKey(key):
    result = n[key].getBiggestInt(dflt)
  else:
    result = dflt

proc pythonRequest*(a: var TargetAdapter, op, workFile, input: string,
                    timeoutMs, seed: int64): ExecResult =
  ## 走 JSON 合约的单次「请求 → 观测」。
  ##
  ## 适配器报的状态与本模组由 `exit_code` 独立推导出的状态必须一致；不一致
  ## 就是两侧合约表漂移，记入 stderr（协议 §4）。这里采信 bridge 的状态，
  ## 因为只有它真的握有该次执行的退出码 —— 但漂移必须被看见。
  result.input = input

  # 先把要跑的位元组**写进档案**，再开口要观测。
  #
  # 这不是防御性程式设计，是 Phase 3 实测出来的资料完整性漏洞：协定只传
  # `input_file`，不传 input，因此 execute 走 bridge 时没有任何人写档案 ——
  # 目标跑的是 workFile 里**上一次 generate 残留的位元组**，而知识库存的却是
  # Nim 端这次的变异。两侧说的根本不是同一批字节。
  #
  # 后果被量到了：5200 次轰炸里 1088 笔 `hang|TIMEOUT|` 是 205/255/603B 的
  # 变异（Nim 端的内容），而同一时期的桥接 trace 显示超时**只**发生在 20-21B
  # 的档案上 —— 正是残留的那个续行挂死输入。逐一重放后 86% 的存档挂死在
  # 44ms 内正常结束，因为跑过的从来就不是存下来的那批字节。
  #
  # generate 不写：位元组由 bridge 产生并写档，下面回读的才是真跑过的那批。
  if op == "execute" and input.len > 0:
    try:
      writeFile(workFile, input)
    except CatchableError as e:
      result.invalid = true
      result.output  = "executor: cannot stage input for bridge: " & e.msg
      return

  if not ensureAlive(a):
    result.invalid = true
    result.output  = "executor: python adapter unavailable (bridge could not be started)"
    return

  var req = newJObject()
  req["v"]          = newJInt(BridgeProtocolVersion)
  req["op"]         = newJString(op)
  req["target"]     = newJString(a.spec.target)
  # Phase 3：目標是腳本時，告訴 bridge 用哪個直譯器啟動它。
  # 空字串表示「bridge 自己的直譯器」（`sys.executable`），這是原生目標
  # 與「同環境腳本」兩種情況都能接受的預設。
  req["target_python"] = newJString(a.spec.targetPython)
  req["dialect"]       = newJString(a.spec.dialect)
  # 目標旗標（Phase 4.1）：bridge 必须用与执行器**完全相同**的参数启动目标，
  # 否则「跑过的」与「缩过的」会是两条不同的启动路径，而症状是缩减
  # 永远报 no longer reproduces —— 又一次只会出现在特定路径上的故障。
  req["target_args"]   = newJString(a.spec.targetArgs)
  req["input_file"] = newJString(workFile)
  req["timeout_ms"] = newJInt(timeoutMs)
  req["seed"]       = newJInt(seed)

  let resp = bridgeRequest(a, req)
  # §8 —— 版本不符就是适配器失效，而不是“试着解读看看”。
  # 没有这道检查，未来任一侧改了字段语义都会被当成同一件事读进去，
  # 于是分歧安静地沉淀进知识库 —— 本项目最怕的就是那种错误。
  if resp != nil and resp.kind == JObject and
     jint(resp, "v", -1) != BridgeProtocolVersion:
    result.invalid = true
    result.output  = "executor: protocol version mismatch: requested " &
                     $BridgeProtocolVersion & ", bridge answered " &
                     $jint(resp, "v", -1)
    return

  if resp == nil or resp.kind != JObject:
    result.invalid = true
    result.output  = "executor: bridge session lost (EOF or malformed response)"
    # 不在这里立即重开：`ensureAlive` 是唯一握有重试额度的入口。
    # 早期版本在这里 inc + startBridge，而 startBridge 又会把 restarts
    # 归零 —— 两个重置点互相抵消，死亡的桥接会被无限制重建（每个作业
    # 都重起一个进程）。重试额度只能由“成功拿到一次响应”重置。
    return

  # 先把**桥接自己说的原因**读进 result.output，再做任何判定。
  # 早期版本在 unknown status 上先返回并把 output 写成一句固定模板，
  # 于是 bridge 报的真实原因被丢在下游 —— 查障时看到的只有
  # “returned unknown status: ERROR”。诊断信息不能被诊断模板盖掉。
  result.generator = jstr(resp, "generator")
  result.elapsedMs = jint(resp, "elapsed_ms", 0)
  result.output    = jstr(resp, "error_message")
  let wireExit     = jint(resp, "exit_code", -1)
  # `cast`, never a checked conversion: an NTSTATUS like 0xC0000005
  # (3221225477) is outside int32's *value* range and `-d:rangeChecks`
  # remains on in `-d:release` (only `-d:danger` clears it), so `int32(x)`
  # raises RangeDefect -- a Defect that kills the engine thread instead of
  # recording the crash the response just described. `canonicalCode` casts
  # back to uint32, so this is a lossless round trip.
  result.rawExit   = cast[int32](uint32(cast[uint64](wireExit) and 0xFFFFFFFF'u64))

  # ERROR 是**合法状态**（§3.3/§6），含义是「适配器没有观测」—— 不是未知状态。
  # 必须先于 kindOfStatus 分派：若落入 unknown 分支，bridge 亲手写下的
  # 原因就会被固定模板替换。
  if jstr(resp, "status") == "ERROR":
    result.invalid = true
    if result.output.len == 0:
      result.output = "bridge reported ERROR with no message"
    return

  # 负的 exit_code 只为 ERROR 保留。出现于其他状态就是响应破损 —— 放行
  # 的话 -1 在 Windows 会被 normalizeOutcome 归成 logic_error，凭空造出
  # 一个家族。契约层宁可丢掉这条，也不能编造一条。
  if wireExit < 0:
    let br = result.output
    result.invalid = true
    result.output  = "executor: exit_code " & $wireExit & " with status " &
                     jstr(resp, "status") & (if br.len > 0: ": " & br else: "")
    return

  var known = true
  let reported = kindOfStatus(jstr(resp, "status"), known)
  if not known:
    let br = result.output
    result.invalid = true
    result.output  = "executor: bridge returned unknown status: " &
                     jstr(resp, "status") &
                     (if br.len > 0: " (" & br & ")" else: "")
    return

  result.kind     = reported
  result.timedOut = reported == hang

  # 拿到一次完整且可辨识的响应 —— 这是重试额度的唯一重置点。
  a.restarts = 0

  # 合约交叉检查（§4）。
  let derived = normalizeOutcome(result.rawExit, result.timedOut)
  if derived != reported:
    stderr.writeLine("executor: BRIDGE STATUS DRIFT — bridge said " & reported.label &
                     ", exit_code " & toHex(cast[uint32](result.rawExit), 8) &
                     " derives " & derived.label &
                     " (protocol table in docs/adapter-protocol.md §4)")

  if op == "generate":
    # 回读实际执行的字节，而不是 bridge 收到的种子或我们发过去的 input。
    # 知识库要存的是「跑过的那些位元组」，否则内容与结果会对不上。
    try:
      result.input = readFile(workFile)
    except CatchableError as e:
      result.invalid = true
      result.output  = "executor: cannot read generated input: " & e.msg
      return

proc runJob*(a: var TargetAdapter, workFile, input: string, timeoutMs: int,
             seed: int64, generate: bool): ExecResult =
  ## 单一工作者任务的统一入口。
  ##
  ## 分派看的是**两个独立的轴**，不是单一 kind：
  ##
  ##   * 要 Hypothesis 产生输入 -> 走 bridge（它同时负责生成与观测，
  ##     因为「实际执行的字节」必须是 bridge 写进档案的那一批）。
  ##   * 否则 -> 走原生 `execute`，它自己会按 targetKind 决定是否加解譯器前綴。
  if a.spec.generator == gkHypothesis:
    pythonRequest(a, (if generate: "generate" else: "execute"),
                  workFile, input, timeoutMs, seed)
  else:
    execute(a.spec.target, workFile, input, timeoutMs, a.spec.targetPython,
            a.spec.targetArgs)

proc probeInterpreter*(python: string): string =
  ## 回传空字符串表示可用，否则回传不可用的原因。
  ## 放在 campaign 起始：与其让每个 worker 各自默默产出「无观测」，
  ## 不如在第一时间给出一条人看得懂的错误。
  var p: Process
  try:
    p = startProcess(python, args = ["--version"],
                     options = {poUsePath, poStdErrToStdOut})
  except CatchableError as e:
    return e.msg
  try:
    let code = waitForExit(p, ProbeTimeoutMs)
    if code != 0:
      return "exited with code " & $code
  except CatchableError as e:
    return e.msg
  finally:
    try:
      if running(p): kill(p)
      close(p)
    except CatchableError:
      discard
  result = ""
