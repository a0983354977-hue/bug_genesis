## vuln_parser — BUG GENESIS Phase 1 的測試標的。
##
## 這是一個刻意埋入多種**真實**缺陷的極簡 JSON 掃描器。它不是模擬器：
## 每一種失敗模式都由真實的底層記憶體或算術錯誤產生，因此執行器只能
## 看到作業系統親自回報的退出碼（Windows NTSTATUS / POSIX signal）。
##
## 退出碼合約（執行器據此正規化）：
##   0        解析成功
##   1        解析失敗或偵測到邏輯異常 —— Nim 例外，stderr 帶有可辨識簽章
##   真實崩潰  0xC0000005 空指標存取 / 0xC00000FD 堆疊溢位 / 0xC0000094 除零
##   掛死      字串掃描器在 EOF 前遇到孤立反斜線時停止推進（無窮迴圈）
##
## 用法：vuln_parser <輸入檔路徑>
##
## 缺陷觸發條件對照（變異引擎的策略就是照這幾條路設計的）：
##   ACCESS_VIOLATION    字串內含 >= AvTriggerRunLen 連續 'A'
##   STACK_OVERFLOW      巢狀深度 > 約 110 層
##   INT_DIV_BY_ZERO     任一數值欄位 > 65535
##   OverflowSuspect     數值落在 (LogicEnvelope, 65535]
##   ValueError          數值大到 int 無法表示
##   JsonError           其他畸形輸入
##   HANG                未閉合字串結尾是一個孤立反斜線

import std/[os, strutils]

const
  ## 觸發空指標存取所需的最小連續 'A' 長度。
  AvTriggerRunLen* = 16
  ## 每層遞迴吃掉的堆疊位元組。這模擬真實世界中「把大型 token 緩衝區放在
  ## 堆疊上」的常見缺陷。幀越大，越淺的巢狀深度就能壓垮預設的 1MB 堆疊，
  ## 也就越接近實際 fuzzing 中會被找到的深度。
  DeepFrameSize = 16384
  ## 邏輯異常的信封上界：超過即視為「值溢出預期欄位寬度」。
  LogicEnvelope = 32767

type
  JsonError = object of CatchableError
  OverflowSuspect = object of CatchableError

  Parser = object
    data: string
    pos: int

# ---------------------------------------------------------------------------
# 漏洞 1：未初始化的 interning 快取（真實空指標解引用）
# ---------------------------------------------------------------------------
# 這個快取在正常路徑上永遠不會被配置。查表程式碼卻假設「既然 token 這麼長，
# 快取一定早就建好了」，直接寫入。任何足夠長的連續 'A' 都會命中此假設。
var internCache: ptr UncheckedArray[byte] = nil

proc maybeInternA(token: string) =
  ## 觸發條件：token 內含一段長度達 AvTriggerRunLen 的連續 'A'。
  if token.len < AvTriggerRunLen: return
  var run = 0
  for c in token:
    if c == 'A':
      inc run
      if run >= AvTriggerRunLen:
        # 讀取並寫入一個從未配置的表格 —— 真實的 ACCESS_VIOLATION。
        let cell = internCache
        cell[0] = cell[0] xor byte(token.len)
        return
    else:
      run = 0

# ---------------------------------------------------------------------------
# 漏洞 2：跳脫序列推進量在 EOF 前回傳 0（真實無窮迴圈）
# ---------------------------------------------------------------------------
proc skipEscape(p: var Parser): int =
  ## 回傳此跳脫序列消耗的位元組數。
  ## BUG：字串在孤立反斜線後結束時回傳 0，呼叫端便永遠停在同一個位置。
  if p.pos + 1 >= p.data.len:
    return 0
  return 2

# ---------------------------------------------------------------------------
# 漏洞 3：16 位元截斷後的值被當成除數（真實 SIGFPE / 0xC0000094）
# ---------------------------------------------------------------------------
# 這個除法的除數刻意宣告成 volatile，而不是一般變數。
# 原因：截斷值恆等於 value mod 65536，所以除數在數學上恆為 0；若是一般
# 變數，最佳化器會直接證明「除以常數 0」並把它折疊成 ud2（非法指令
# 0xC000001D），於是我們拿到的是一個人為的編譯期陷阱，而不是目標程式
# 在真實執行期犯下的除零錯誤。volatile 強制編譯器在執行期從記憶體載入
# 除數，必須真的發出硬體 DIV 指令，故障才會由 CPU 親自產生。
proc storeTruncated(value: int) =
  ## 模擬「把整數塞進 uint16 欄位」的常見錯誤：先靜默截斷，再拿「完整精度」
  ## 與「截斷值」的差去當分片數。差恆為 0，於是最終的除法必然除以零。
  var chunkCount {.volatile.}: int32
  {.push checks: off, overflowChecks: off, rangeChecks: off.}
  let slot = uint16(value)
  chunkCount = int32(int(slot) - (value mod 65536))   # 恆為 0
  # 除法必須留在 checks: off 區塊內，否則 Nim 的除零檢查會把它轉成
  # DivByZeroDefect（一個可攔截的例外 → exit 1），而不是硬體故障。
  echo 1_000_000'i32 div chunkCount                  # 真實除零 → 執行序被終止
  {.pop.}

# ---------------------------------------------------------------------------
# 掃描器
# ---------------------------------------------------------------------------
proc skipWhitespace(p: var Parser) =
  while p.pos < p.data.len and p.data[p.pos] in {' ', '\t', '\r', '\n'}:
    inc p.pos

proc parseString(p: var Parser) =
  # 前置條件：p.data[p.pos] == '"'
  inc p.pos
  let tokenStart = p.pos
  while true:
    if p.pos >= p.data.len:
      raise newException(JsonError, "unterminated string literal")
    let c = p.data[p.pos]
    if c == '"':
      maybeInternA(p.data[tokenStart ..< p.pos])
      inc p.pos
      return
    elif c == '\\':
      let adv = skipEscape(p)
      if adv == 0:
        while true: discard    # 掛死：無窮迴圈
      p.pos += adv
    else:
      inc p.pos

proc parseNumber(p: var Parser) =
  let start = p.pos
  if p.pos < p.data.len and p.data[p.pos] in {'-', '+'}:
    inc p.pos
  var digits = 0
  while p.pos < p.data.len and p.data[p.pos] in Digits:
    inc p.pos
    inc digits
  if digits == 0:
    raise newException(JsonError, "malformed numeric literal")
  let text = p.data[start ..< p.pos]
  let value = parseInt(text)          # 超過 int 範圍會拋 ValueError
  if value > 65535:
    storeTruncated(value)             # → 真實除零崩潰
  if value < -LogicEnvelope or value > LogicEnvelope:
    raise newException(OverflowSuspect,
      "numeric field outside expected envelope: " & text)

proc parseValue(p: var Parser) {.noinline.} =
  # 每一層遞迴都保留一大塊堆疊。這是「巢狀深度無上限」缺陷得以成為真實
  # 堆疊溢位（0xC00000FD）的原因：沒有深度檢查，堆疊保護頁終究會被用盡。
  #
  # volatile 與首尾兩個索引的存取缺一不可：僅碰 frame[0] 時，最佳化器會
  # 把整塊陣列縮成一個位元組的堆疊插槽，堆疊實際上完全沒有增長，巢狀
  # 再深也不會溢位。存取第 0 與最後一個元素強制編譯器保留完整範圍。
  var frame {.volatile.}: array[DeepFrameSize, byte]
  frame[0] = byte(p.pos)
  frame[DeepFrameSize - 1] = byte(p.pos)

  skipWhitespace(p)
  if p.pos >= p.data.len:
    raise newException(JsonError, "unexpected end of input")

  case p.data[p.pos]
  of '{':
    inc p.pos
    skipWhitespace(p)
    if p.pos < p.data.len and p.data[p.pos] == '}':
      inc p.pos
    else:
      while true:
        skipWhitespace(p)
        if p.pos >= p.data.len or p.data[p.pos] != '"':
          raise newException(JsonError, "expected object key string")
        parseString(p)
        skipWhitespace(p)
        if p.pos >= p.data.len or p.data[p.pos] != ':':
          raise newException(JsonError, "expected ':' after object key")
        inc p.pos
        parseValue(p)
        skipWhitespace(p)
        if p.pos < p.data.len and p.data[p.pos] == ',':
          inc p.pos
          continue
        if p.pos < p.data.len and p.data[p.pos] == '}':
          inc p.pos
          break
        raise newException(JsonError, "unterminated object")
  of '[':
    inc p.pos
    # BUG：沒有深度上限。巢狀陣列會一路遞迴直到堆疊耗盡。
    skipWhitespace(p)
    if p.pos < p.data.len and p.data[p.pos] == ']':
      inc p.pos
    else:
      while true:
        parseValue(p)
        skipWhitespace(p)
        if p.pos < p.data.len and p.data[p.pos] == ',':
          inc p.pos
          continue
        if p.pos < p.data.len and p.data[p.pos] == ']':
          inc p.pos
          break
        raise newException(JsonError, "unterminated array")
  of '"':
    parseString(p)
  of '-', '+', '0'..'9':
    parseNumber(p)
  elif p.data[p.pos .. min(p.pos + 3, p.data.len - 1)] == "true":
    p.pos += 4
  elif p.data[p.pos .. min(p.pos + 3, p.data.len - 1)] == "fals" and
       p.data.len > p.pos + 4 and p.data[p.pos + 4] == 'e':
    p.pos += 5
  elif p.data[p.pos .. min(p.pos + 3, p.data.len - 1)] == "null":
    p.pos += 4
  else:
    raise newException(JsonError, "unexpected token at offset " & $p.pos)
  discard frame[0] xor frame[DeepFrameSize - 1]

proc main(): int =
  if paramCount() < 1:
    stderr.writeLine("usage: vuln_parser <input-file>")
    return 2
  let path = paramStr(1)
  if not fileExists(path):
    stderr.writeLine("input not found: " & path)
    return 2

  var p = Parser(data: readFile(path), pos: 0)
  try:
    parseValue(p)
    skipWhitespace(p)
    if p.pos != p.data.len:
      raise newException(JsonError,
        "trailing data after top-level value at offset " & $p.pos)
    echo "OK bytes=", p.data.len
    return 0
  except OverflowSuspect as e:
    stderr.writeLine("ANOMALY OverflowSuspect: " & e.msg)
    return 1
  except JsonError as e:
    stderr.writeLine("ANOMALY JsonError: " & e.msg)
    return 1
  except CatchableError as e:
    stderr.writeLine("ANOMALY " & $e.name & ": " & e.msg)
    return 1

when isMainModule:
  quit(main())
