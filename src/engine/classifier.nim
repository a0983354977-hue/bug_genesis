## classifier — 錯誤族群分類與反例演化。
##
## 兩件事：
##
##   1. 分類 / 去重。同一個缺陷會被反覆命中，若不歸併，知識庫會被幾千筆
##      一模一樣的崩潰淹沒。判準是簽章完全相等（見 executor.signature），
##      不是「退出碼相同」—— 因為 exit 1 的 JsonError 與 exit 1 的
##      ValueError 是兩個不同的缺陷，必須分開。
##
##   2. 反例縮減（Delta Reduction）。發現一個 300 位元組的崩潰輸入時，真正
##      有價值的是它**最小**的重現體。這裡用標準的 delta debugging：
##      先用遞減的區塊粒度大刀闊斧地砍，再逐位元組收尾，直到再也砍不掉
##      一個位元組為止。每一步都必須重新驗證簽章完全相同，否則就不是在
##      縮減這個缺陷，而是在把缺陷換成另一個。

import std/strutils
import executor

const
  ReproProbes* = 3
    ## 重現閘門的探測次數：**全部**重現才算可重現。
    ##
    ## 不探測（等价于 N=1 次都不做）意味着任何一闪而过的假性逾时、任何
    ## 随机触发的第三方例外都会直接变成「缺陷族群」。若故障只有 p 的機率
    ## 出現，雜訊漏判率是 p^N —— N=3 時連 p=0.5 的偶發都只剩 12.5%。

  MaxNoiseStrikes* = 3
    ## 同一簽章連續被閘門擋下的次數上限；超過就不再花執行預算去重放。
    ##
    ## 只在**單次活動**內記憶：可重現性是當前環境的性質，換環境（換機器、
    ## 換負載）就該重新評估，因此不把它寫進知識庫永久封殺。

type
  BugFamily* = object
    id*:        int64
    signature*: string
    kindLabel*: string
    code*:      string
    hitCount*:  int64
    repro*:     string          ## 最小反例

proc describe*(f: BugFamily): string =
  ## 供終端機輸出的單行摘要。
  "family#" & $f.id & " [" & f.kindLabel & " " & f.code &
  "] hits=" & $f.hitCount &
  " repro=" & $f.repro.len & "B"

# ---------------------------------------------------------------------------
# 分類
# ---------------------------------------------------------------------------

proc classify*(r: ExecResult): tuple[sig, kindLabel, code: string] =
  ## 把一次執行結果壓縮成（簽章, 類型, 故障碼）三元組。
  result.sig = r.signature
  result.kindLabel = r.kind.label
  result.code = r.canonicalCode

# ---------------------------------------------------------------------------
# 重現閘門（模組 3）
# ---------------------------------------------------------------------------

proc confirmSignature*(binPath, workFile, input: string, timeoutMs: int,
                       wantSig: string, probes = ReproProbes,
                       interpreter = "", extraArgs = ""): int =
  ## 回傳 `probes` 次重放中簽章完全相符的次數（`0..probes`）。
  ##
  ## 與反例縮減共用 `reproduces`：同樣不經 bridge（重放要問的是「這批位元組
  ## 本身還會不會重現」，與誰產生它無關），同樣要求簽章逐字相等。
  ##
  ## 每次探測都是一次真實執行，掛死族群尤其贵（每次都要等滿整個逾時）——
  ## 因此探测次数是硬上限而不是“直到确认为止”的迴圈。
  for _ in 0 ..< probes:
    if reproduces(binPath, workFile, input, timeoutMs, wantSig,
                  interpreter, extraArgs):
      inc result

# ---------------------------------------------------------------------------
# 感染點抽取（模組 4）
# ---------------------------------------------------------------------------

proc extractOffset*(output: string): int =
  ## 從目標輸出抓出故障偏移量；找不到回傳 -1。
  ##
  ## 支援 `offset 123`、`offset=123`、`at index 123`、`byte 4096` 等目標常見
  ## 寫法，取**最早**出現的那一個 —— 解析器报的第一个位置就是它停下来的地方，
  ## 后面的往往是连锁反应。
  ##
  ## 前後必須是詞邊界：`myoffset=5` 這種嵌在識別字裡的字串不算，否則會把
  ## 一個無關的欄位名當成感染點，整個變異分佈會被帶到錯誤的區域。
  const keys = ["offset", "index", "byte", "position"]
  if output.len == 0: return -1
  let lower = toLowerAscii(output)
  var bestVal = -1
  var bestPos = -1
  for key in keys:
    var seek = 0
    while seek < lower.len:
      let at = lower.find(key, seek)
      if at < 0: break
      seek = at + 1
      # 前邊界：前一個字元不能是識別字字元。
      if at > 0 and (lower[at - 1] in {'a' .. 'z', '0' .. '9', '_'}): continue
      var p = at + key.len
      while p < lower.len and lower[p] in {' ', '\t', '=', ':', '#', '@',
                                           '[', ']', '(', ')'}:
        inc p
      if p >= lower.len or lower[p] notin Digits: continue
      var e = p
      while e < lower.len and lower[e] in Digits: inc e
      var v = -1
      try: v = parseInt(lower[p ..< e])
      except ValueError: continue
      if v >= 0 and (bestPos < 0 or at < bestPos):
        bestPos = at
        bestVal = v
  bestVal

# ---------------------------------------------------------------------------
# 反例縮減
# ---------------------------------------------------------------------------

proc reduce*(binPath, workFile: string, input: string, timeoutMs: int,
             wantSig: string,
             maxAttempts = 400,
             interpreter = "",
             extraArgs = ""): tuple[repro: string, attempts: int] =
  ##
  ## 傳回能重現 `wantSig` 的最短輸入，以及過程中實際花掉的執行次數。
  ##
  ## `interpreter` 必須與**執行器實際用的**完全相同（Phase 3 的腳本目標）。
  ## 少傳的話，縮減會拿二進位路徑去 exec 一個 .py，每一次 `keeps` 都得到
  ## 「啟動失敗」而非原簽章，於是所有反例都停在未縮減的長度 —— 而且不會
  ## 報任何錯，只是知識庫悄悄變差。
  ##
  ## 兩階段：先以 2 的冪次粒度切塊刪除（快速砍掉大片無關內容），收斂到 1
  ## 位元組粒度後再做一輪逐位元組測試。若連一個位元組都刪不掉，回傳值就是
  ## 已經是「1-最小」的了 —— 再多搜尋也只會浪費執行預算。
  ##
  ## `maxAttempts` 是硬性執行預算。縮減的最壞情況是 O(n) 次執行，而掛死家族
  ## 每一次都要等滿整個逾時，沒有預算就可能讓一次縮減吃掉整個活動的時間。
  ## 預算耗盡時回傳當前最好的結果（仍保證簽章正確），只是還沒到 1-最小。
  var current = input
  var attempts = 0

  proc exhausted(): bool = attempts >= maxAttempts

  proc keeps(s: string): bool =
    if s.len >= current.len or s.len == 0: return false
    if exhausted(): return false
    inc attempts
    reproduces(binPath, workFile, s, timeoutMs, wantSig, interpreter, extraArgs)

  # 階段一：由大到小的區塊刪除。
  var granularity = max(1, current.len div 2)
  while granularity >= 1 and not exhausted():
    var i = 0
    while i < current.len and not exhausted():
      let stop = min(i + granularity, current.len)
      let candidate = current[0 ..< i] & current[stop .. ^1]
      if keeps(candidate):
        # 同一個起點重新嘗試：砍掉前段後，後面的內容已經前移。
        current = candidate
      else:
        i += granularity
    granularity = granularity div 2

  # 階段二：逐位元組收尾，確保刪不掉任何單一位元組。
  var i = 0
  while i < current.len and not exhausted():
    let candidate = current[0 ..< i] & current[i + 1 .. ^1]
    if keeps(candidate):
      current = candidate
    else:
      inc i

  (current, attempts)

proc signatureSample*(sig: string, maxLen = 96): string =
  ## 顯示用：把簽章截斷到可讀長度。
  if sig.len <= maxLen: sig else: sig[0 ..< maxLen] & "…"
