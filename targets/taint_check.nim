## Does the taint engine point the mutation stream at the right bytes?
##
## Compile with the project's config.nims (it puts src/ on --path):
##     nim c -r --hints:off targets/taint_check.nim
##
## Module 4 makes two claims that are easy to state and easy to get wrong:
## an offset recognised from the target's output must be the *earliest* real
## one (a wrong offset silently aims every later mutation elsewhere), and the
## biased sampler must actually be biased (a no-op bias passes every
## single-value test you could write for it, so these are distributional).

import std/strutils
import engine/[mutator, classifier]

var failures = 0

proc check(what: string, ok: bool, detail = "") =
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), what,
       (if detail.len > 0: " -> " & detail else: "")

echo "== extractOffset: the position the parser actually stopped at =="
check("bare 'at offset 42'",
      extractOffset("ANOMALY JsonError: unexpected token at offset 42") == 42)
check("'offset=99'", extractOffset("parse failed: offset=99") == 99)
check("'at index 7'", extractOffset("corrupt at index 7 of block") == 7)
check("'byte 4096'", extractOffset("short read at byte 4096") == 4096)
check("earliest offset wins",
      extractOffset("offset 5 bad, later offset 9 also bad") == 5)
check("case insensitive", extractOffset("OFFSET 31") == 31)
check("no offset -> -1", extractOffset("Unrecognized archive format") == -1)
check("empty output -> -1", extractOffset("") == -1)
check("identifier containing the word is not an offset",
      extractOffset("myoffset=5") == -1)
check("word with no number is not an offset",
      extractOffset("the offset field is missing") == -1)

echo "== setTainted: sanitising the knowledge base's input =="
var m = initMutator(11)
m.setTainted([-4, 10, 10, 20])
check("negative offsets dropped, duplicates merged",
      m.taintedOffsets == @[10, 20], $m.taintedOffsets)
check("hasTaint reflects the state", m.hasTaint)
m.setTainted([-1, -2])
check("empty after sanitising clears the state", not m.hasTaint)
var many: seq[int]
for i in 0 ..< 40: many.add i * 3
m.setTainted(many)
check("capped at MaxTainted", m.taintedOffsets.len == MaxTainted,
      $m.taintedOffsets.len)
m.setTainted([])
check("clearing works", not m.hasTaint)

echo "== pickPos: the sampler must actually be biased =="
block:
  var b = initMutator(42)
  b.setTainted([100])
  const len = 1000
  const lo = 100 - TaintWindow
  const hi = 100 + TaintWindow
  var inWindow = 0
  const samples = 4000
  for _ in 0 ..< samples:
    let p = b.pickPos(len)
    if p < 0 or p >= len:
      check("pickPos stays inside the buffer", false, $p)
      break
    if p >= lo and p <= hi: inc inWindow
  let ratio = inWindow.float / samples.float
  echo "       in-window ratio with taint: ",
       formatFloat(ratio, ffDecimal, 3),
       "  (uniform baseline would be ~",
       formatFloat((hi - lo + 1).float / len.float, ffDecimal, 3), ")"
  check("tainted window is favoured", ratio > 0.5,
        formatFloat(ratio, ffDecimal, 3))

block:
  var b = initMutator(42)
  b.setTainted([])                       # 對照組：沒有感染點
  const len = 1000
  var inWindow = 0
  const samples = 4000
  for _ in 0 ..< samples:
    let p = b.pickPos(len)
    if p >= 100 - TaintWindow and p <= 100 + TaintWindow: inc inWindow
  let ratio = inWindow.float / samples.float
  echo "       in-window ratio without taint: ",
       formatFloat(ratio, ffDecimal, 3)
  check("no taint means no clustering", ratio < 0.25,
        formatFloat(ratio, ffDecimal, 3))

echo "== boundary strategy fires on length/index fields near the taint =="
# 兩個數字欄位：`11111` 緊鄰感染點，`77777` 遠在窗口之外。邊界值策略若真的
# 只在相依指標上開火，遠處那個就該大部分時候保持原樣。
# 選 11111/77777 是刻意的：BoundaryValues 裡沒有任何值含有這兩串，因此
# 「遠處欄位還在不在」是無歧義的觀測。
proc buildInput(): string =
  result = "a".repeat(200)
  result[10 ..< 15] = "77777"
  result[100 ..< 105] = "11111"

proc farKeptRatio(seed: int64, tainted: bool): float =
  var mm = initMutator(seed)
  if tainted: mm.setTainted([102])
  var kept = 0
  const samples = 400
  for _ in 0 ..< samples:
    let outData = mm.mutate(buildInput(), msBoundaryValue)
    if "77777" in outData: inc kept   # 遠處欄位未被碰 = 打中了近處
  kept.float / samples.float

let biased = farKeptRatio(5, tainted = true)
let plain = farKeptRatio(5, tainted = false)
echo "       far field untouched — with taint: ", formatFloat(biased, ffDecimal, 3),
     "  without: ", formatFloat(plain, ffDecimal, 3)
check("near field is favoured when tainted", biased > 0.65,
      formatFloat(biased, ffDecimal, 3))
check("without taint the choice is roughly even", plain < 0.60,
      formatFloat(plain, ffDecimal, 3))

echo "== mutate still respects the hard limits under taint =="
block:
  var mm = initMutator(9)
  mm.setTainted([3])
  var okAll = true
  for i in 0 ..< 500:
    let s = mm.mutate("x".repeat(300), msBitFlip)
    if s.len == 0 or s.len > MaxInputLen: okAll = false; break
    discard i
  check("output never empty and never exceeds MaxInputLen", okAll)

if failures == 0:
  echo "VERDICT: the mutation stream converges on the tainted offset."
else:
  echo "VERDICT: ", failures, " taint check(s) FAILED."
  quit(1)
