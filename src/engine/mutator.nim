## mutator — 變異引擎。
##
## 職責：把一個合法的測試案例，變成具有破壞性的下一代案例。
##
## 設計要點是「策略」與「權重」分離：
##
##   * 策略（MutationStrategy）是彼此獨立的破壞手法，每一種對應目標程式裡
##     一條明確的缺陷路徑。
##   * 權重由 Failure-Directed 迴饋調整 —— 引擎不去猜哪個策略好，而是看哪
##     個策略**真的挖出了新族群**，就把下一轮的機會往那邊傾斜。沒挖到東西
##     的策略會被缓慢降權，但永不歸零，以免引擎把自己鎖死在單一手法上。
##
## 權重以乘法方式更新並夾在上下界之間：這樣既是爬坡法，又保留了探索性，
## 不會因為早期一次運氣好就把其餘策略餓死。

import std/[random, strutils]

type
  MutationStrategy* = enum
    msBitFlip
    msByteOverride
    msBoundaryValue
    msStructural
    msRunInsert
    msNestGrow
    msBlockDuplicate
    msTokenInject
    msHypothesis      ## 跨語言：輸入由 Python/Hypothesis 產生器生成，不在這裡變異

  StrategyStats* = object
    tries*:       array[MutationStrategy, int64]
    failures*:    array[MutationStrategy, int64]
    newFamilies*: array[MutationStrategy, int64]

  Mutator* = object
    rng:     Rand
    weights: array[MutationStrategy, float]
    stats*:  StrategyStats
    ## 参与抽选的策略集合。用集合而不是把权重设 0，是因为 `pickStrategy` 的
    ## 票值循环在上一个策略刚好扣成 0.0 时会命中紧接着的**权重为 0** 的策略
    ## —— 那会绕过开关，把没启用的适配器当成已启用。
    enabled*: set[MutationStrategy]
    ## 高優先級感染點（byte offset）：由知識庫回填，見 setTainted。
    ## 空序列 = 沒有偏移量證據，所有位置抽樣退回全域均勻 —— 此時 pickPos
    ## 舊版行為完全一致（連 RNG 消耗都相同），變異鏈不受影響。
    taints: seq[int]

const
  MinWeight = 0.15
  MaxWeight = 12.0
  BoostNewFamily = 1.35   ## 挖出新族群
  BoostFailure   = 1.06   ## 挖出已知失敗（仍值得靠近）
  DecayMiss      = 0.985  ## 完全沒有回饋
  DecayNoise     = 0.92   ## 未通過重現閘門：比 DecayMiss 更強的降權

  TaintChance* = 55       ## 感染點抽中率（百分比）
  TaintWindow* = 64       ## 以感染點為中心的聯合爆破窗口（位元組）
  MaxTainted*  = 8        ## 最多同時追蹤的感染點數

  ## 任意變異案例的位元組上限，避免結構性生長把輸入無限撐大。
  MaxInputLen* = 4096

  ## 邊界值集合：涵蓋零、負數、16/32 位元邊界，以及超出 int 範圍的值。
  BoundaryValues = [
    "0", "-1", "1", "127", "128", "255", "256",
    "32767", "32768", "65535", "65536",
    "2147483647", "-2147483648",
    "999999999999999999999"
  ]

  ## 拼接到輸入中的 JSON 語意片段。
  Tokens = [
    "null", "true", "false", "NaN", "Infinity", "-0", "1e308", "0x10",
    "65536", "32768", ":", ",", "{", "}", "[", "]", "\"\\u0000\"", "\\"
  ]

  ## 插入的重複位元組。'A' 打空指標路徑， '[' 打堆疊路徑。
  RunChars = ['A', 'A', 'A', 'A', '[', '[', '"', '\x00', '9', '\\']

proc initMutator*(seed: int64): Mutator =
  ## 權重一律等分起始 —— 不預先假設哪個策略比較好，讓失敗回饋自己去發現。
  result.rng = initRand(seed)
  for s in MutationStrategy:
    result.weights[s] = 1.0
    result.stats.tries[s] = 0
    result.enabled.incl s

proc label*(s: MutationStrategy): string =
  ## 穩定的標籤，用於資料庫與終端機；跨執行、跨版本不變。
  ## 不採用 `$`，因為列舉識別字會隨重構而改，簽章與歷史資料卻必須持續可比對。
  case s
  of msBitFlip:        "bit_flip"
  of msByteOverride:   "byte_override"
  of msBoundaryValue:  "boundary_value"
  of msStructural:     "structural_corruption"
  of msRunInsert:      "run_insert"
  of msNestGrow:       "nest_grow"
  of msBlockDuplicate: "block_duplicate"
  of msTokenInject:    "token_inject"
  of msHypothesis:     "hypothesis"

proc parseStrategy*(name: string): MutationStrategy =
  ## 由標籤還原策略。找不到就拋錯，不靜默退回預設值 ——
  ## 靜默降級會讓歷史統計悄悄歸零，而這份統計正是回饋的依據。
  for s in MutationStrategy:
    if s.label == name: return s
  raise newException(ValueError, "unknown mutation strategy: " & name)

proc strategyCount*: int = ord(high(MutationStrategy)) + 1

proc pickSeed*(m: var Mutator, seeds: openArray[string]): string =
  ## 從種子集挑一個作為變異起點。
  ## 種子選擇與變異選擇共用同一個 RNG：整條隨機鏈因此完全由單一 seed 決定，
  ## 任何一次失敗都可以用同一個 seed 精确重跑。
  if seeds.len == 0:
    raise newException(ValueError, "seed corpus is empty")
  seeds[m.rng.rand(seeds.high)]

proc pickStrategy*(m: var Mutator): MutationStrategy =
  ## 從啟用的策略中抽樣。
  ##
  ## 兩段迴圈都是必要的：第一段累積權重總和，第二段扣票；最後再補一段
  ## 兜底回傳，避免 `total` 為 0（例如只啟用了一個權重被衰減到 0 的策略）
  ## 時從未初始化的 `result` 回傳。
  var total = 0.0
  for s in MutationStrategy:
    if s in m.enabled: total += m.weights[s]
  var ticket = m.rng.rand(1.0) * total
  for s in MutationStrategy:
    if s notin m.enabled: continue
    ticket -= m.weights[s]
    if ticket <= 0.0:
      return s
  for s in MutationStrategy:
    if s in m.enabled: return s
  raise newException(ValueError, "no mutation strategy is enabled")

proc recordTry*(m: var Mutator, s: MutationStrategy) =
  ## 每派發一個案例就記一次，與「輸入由誰產生」無關。
  ##
  ## 這不能從 `mutate` 內部做：msHypothesis 沒有位元級變異，core 根本不會
  ## 呼叫 mutate，放在那裡會讓 Hypothesis 的戰績永遠停在 0，而統計正是
  ## 回饋的依據。
  inc m.stats.tries[s]

proc nextSeed*(m: var Mutator): int64 =
  ## 給跨語言產生器的種子。
  ##
  ## 與策略抽選共用同一個 RNG —— 整條隨機鏈（選哪個策略、變異成什麼、
  ## 產生器長什麼形狀）才能由單一個 campaign seed 精确重跑。
  ##
  ## 最高位元強制清零：協定要求 seed 是**非負**整數（adapter-protocol
  ## §3.1），而 `cast[int64]` 會把 uint64 高半區間直接變負數。
  ## `hi` 只取 31 個位元再左移 32：位元 63 恆為 0，位元 32..62 是高位、
  ## 0..31 是低位，兩段不重疊。
  let hi = uint64(m.rng.rand(high(int)) and 0x7FFFFFFF)
  let lo = uint64(m.rng.rand(high(int)) and 0xFFFFFFFF)
  result = int64(hi shl 32 or lo)

proc reward*(m: var Mutator, s: MutationStrategy, failed, isNewFamily: bool) =
  ## Failure-Directed 的核心：依回饋強度調整下一輪的變異機率。
  if isNewFamily:
    m.weights[s] = min(m.weights[s] * BoostNewFamily + 0.05, MaxWeight)
    inc m.stats.newFamilies[s]
  elif failed:
    m.weights[s] = min(m.weights[s] * BoostFailure, MaxWeight)
  else:
    m.weights[s] = max(m.weights[s] * DecayMiss, MinWeight)
  if failed: inc m.stats.failures[s]

proc weightOf*(m: Mutator, s: MutationStrategy): float = m.weights[s]

proc recordNoise*(m: var Mutator, s: MutationStrategy) =
  ## 環境雜訊的回饋：降權，但不歸零。
  ##
  ## 與 `reward` 互斥 —— 被重現閘門擋下的觀測不是「已確認的失敗」，
  ## 因此既不进 stats.failures，也不该拿到 BoostFailure。策略本身沒有错，
  ## 它只是這次撞到的不是缺陷；衰減到下界就够，归零会把手法锁死。
  m.weights[s] = max(m.weights[s] * DecayNoise, MinWeight)

proc setTainted*(m: var Mutator, offsets: openArray[int]) =
  ## 回填感染點（由 core 從知識庫讀出後傳入）。
  m.taints.setLen(0)
  for o in offsets:
    if o >= 0 and o notin m.taints:
      m.taints.add o
      if m.taints.len >= MaxTainted: break

proc hasTaint*(m: Mutator): bool = m.taints.len > 0

proc taintedOffsets*(m: Mutator): seq[int] = m.taints

proc taintWindow(m: var Mutator, length: int): (int, int) =
  ## 以隨機選中的感染點為中心的爆破窗口，已夾到 `[0, length)`。
  let base = m.taints[m.rng.rand(m.taints.high)]
  (max(0, base - TaintWindow), min(length - 1, base + TaintWindow))

proc pickPos*(m: var Mutator, length: int): int =
  ## 在 `[0, length)` 取一個位址。有感染點時，`TaintChance` 的機率落在窗口內。
  ##
  ## 這就是「集中火力」的落點：字元級手法（位元翻轉、位元組覆寫、截斷、
  ## 插入）全部改從這裡取位置，於是與故障偏移量相依的位元組、以及緊鄰它的
  ## 長度欄位，會被聯合轟炸。
  ##
  ## `length` 是**合法位置的個數**，不是最後一個索引 —— 插入位置允許落在末尾，
  ## 所以呼叫端對插入要傳 `data.len + 1`。
  if length <= 0: return 0
  if m.taints.len > 0 and m.rng.rand(99) < TaintChance:
    let (lo, hi) = m.taintWindow(length)
    if hi >= lo: return lo + m.rng.rand(hi - lo)
  m.rng.rand(length - 1)

# ---------------------------------------------------------------------------
# 各破壞手法
# ---------------------------------------------------------------------------

proc mutBitFlip(m: var Mutator, data: var string) =
  if data.len == 0: return
  let n = 1 + m.rng.rand(min(8, data.len) - 1)
  for _ in 0 ..< n:
    let i = m.pickPos(data.len)
    let mask = uint8(1'u8 shl m.rng.rand(7))
    data[i] = char(cast[uint8](data[i].uint8 xor mask))

proc mutByteOverride(m: var Mutator, data: var string) =
  const extremes = ['\0', '\x01', '\x7f', '\xff', '"', '\\',
                    '{', '}', '[', ']', ':', ',', '-', 'e', 'E', '\n']
  if data.len == 0:
    data.add(extremes[m.rng.rand(extremes.high)])
  else:
    data[m.pickPos(data.len)] = extremes[m.rng.rand(extremes.high)]

proc mutBoundaryValue(m: var Mutator, data: var string) =
  ## 找出已有的數字欄位，替換成極端邊界值。
  ## 打 INT_DIV_BY_ZERO（>65535）、OverflowSuspect、以及 int 溢位 ValueError。
  if data.len == 0: return
  var spans: seq[(int, int)]
  var i = 0
  while i < data.len:
    if data[i] in Digits:
      let s = i
      while i < data.len and data[i] in Digits: inc i
      spans.add((s, i))
    else:
      inc i
  if spans.len == 0:
    # 沒有數字可替換時，直接注入一個。
    let at = m.rng.rand(data.len)
    data.insert(BoundaryValues[m.rng.rand(BoundaryValues.high)], at)
    return
  # 感染點存在時，優先選中與其窗口相交的數字欄位：長度、索引、計數這些
  # 指標都與故障偏移量相依，它們才是「聯合爆破」要一起打的東西，而不是
  # 隨便挑一個無關的數字。
  var choice = m.rng.rand(spans.high)
  if m.hasTaint and m.rng.rand(99) < TaintChance:
    var near: seq[int]
    for idx, sp in spans:
      for t in m.taints:
        let lo = max(0, t - TaintWindow)
        let hi = min(data.len - 1, t + TaintWindow)
        if sp[1] >= lo and sp[0] <= hi:
          near.add idx
          break
    if near.len > 0: choice = near[m.rng.rand(near.high)]
  let (s, e) = spans[choice]
  let pick = BoundaryValues[m.rng.rand(BoundaryValues.high)]
  data = data[0 ..< s] & pick & data[e .. ^1]

proc mutStructural(m: var Mutator, data: var string) =
  if data.len == 0: return
  case m.rng.rand(4)
  of 0:
    # 刪掉結尾的定界符號（模擬被截斷的結構）。
    var i = data.len - 1
    while i >= 0 and data[i] in {' ', '\t', '\r', '\n'}: dec i
    if i >= 0: data.setLen(i)
  of 1:
    # 直接截斷。落點在感染點附近 = 把檔案切在故障位置剛後方，暴露前綴。
    data.setLen(m.pickPos(data.len))
  of 2:
    # 插入非法跳脫序列。
    const bad = ["\\", "\\x", "\\u00", "\\\\", "\\q"]
    data.insert(bad[m.rng.rand(bad.high)], m.pickPos(data.len + 1))
  of 3:
    # 刪除中段。起點靠近感染點時，刪除的正好的是故障附近的幾個位元組。
    let s = m.pickPos(data.len)
    let e = min(data.len, s + 1 + m.rng.rand(8))
    data = data[0 ..< s] & data[e .. ^1]
  else:
    # 未閉合字串 + 孤立反斜線：把輸入截斷在某個開引號之後再補上 '\'
    # （等同於「檔案在跳脫序列中途被截斷」）。掃描器此時會拿到 0 的推進量。
    var quotes: seq[int]
    for idx, c in data:
      if c == '"': quotes.add(idx)
    if quotes.len > 0:
      data.setLen(quotes[m.rng.rand(quotes.high)] + 1)
      data.add('\\')
    else:
      data.add('"')
      data.add('\\')

proc mutRunInsert(m: var Mutator, data: var string) =
  ## 插入一串重複位元組：'A' 打空指標， '[' 打巢狀堆疊。
  let c = RunChars[m.rng.rand(RunChars.high)]
  let n = 1 + m.rng.rand(180)
  data.insert(repeat(c, n), m.pickPos(data.len + 1))

proc mutNestGrow(m: var Mutator, data: var string) =
  ## 在最前面鋪上一串 '['，直接把解析器往深處推。
  ## 放在最前面是刻意的：這樣巢狀一定會在抵達種子之前就被展開，深度可觀。
  let depth = 1 + m.rng.rand(200)
  data = repeat('[', depth) & data

proc mutBlockDuplicate(m: var Mutator, data: var string) =
  if data.len < 2: return
  # 複製區段的起點也走 pickPos：被搬運的內容本身要落在感染點附近，
  # 否則只是把無關的位元組複製到別處。
  let s = m.pickPos(data.len - 1)
  let e = s + 1 + m.rng.rand(min(64, data.len - s) - 1)
  data.insert(data[s ..< e], m.rng.rand(data.len))

proc mutTokenInject(m: var Mutator, data: var string) =
  let t = Tokens[m.rng.rand(Tokens.high)]
  data.insert(t, m.pickPos(data.len + 1))

proc mutate*(m: var Mutator, seed: string, s: MutationStrategy): string =
  ## 依指定策略產生下一代變異案例，並強制套用長度上限。
  ##
  ## 呼叫端的合約：msHypothesis **不可走這裡**，它的 payload 由適配器生成，
  ## core 會送空 payload 並把 Job 標為 generate。這裡仍回傳種子（而非拋錯），
  ## 是因為一個空 payload 真的會被寫進目標程式 —— 與其默默跑出一個空輸入，
  ## 不如讓它等同於「不變異」，那至少是個合法的案例。
  result = seed
  if s == msHypothesis: return
  case s
  of msBitFlip:        m.mutBitFlip(result)
  of msByteOverride:   m.mutByteOverride(result)
  of msBoundaryValue:  m.mutBoundaryValue(result)
  of msStructural:     m.mutStructural(result)
  of msRunInsert:      m.mutRunInsert(result)
  of msNestGrow:       m.mutNestGrow(result)
  of msBlockDuplicate: m.mutBlockDuplicate(result)
  of msTokenInject:    m.mutTokenInject(result)
  of msHypothesis:     discard   # 见上方「呼叫端的合约」
  if result.len > MaxInputLen:
    result.setLen(MaxInputLen)
  if result.len == 0:
    result = seed
    if result.len == 0: result = "{}"
