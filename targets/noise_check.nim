## Does the reproducibility gate actually tell a reproducible failure from noise?
##
## Compile with the project's config.nims (it puts src/ on --path):
##     nim c -r --hints:off targets/noise_check.nim     (needs build/vuln_parser)
##
## Three claims, all of which fail silently when wrong:
##
##   1. confirmSignature counts probes that reproduce the *same* signature.
##      A gate that returns `probes` for every input admits everything — the
##      symptom is a knowledge base full of one-shot "failures".
##   2. A different failure does not count as a reproduction. Otherwise the
##      gate merges two defects and the family records a signature that no
##      single input actually has.
##   3. recordNoise down-weights and stops at a floor, and does not count the
##      observation as a confirmed failure.

import std/[os, strutils]
import engine/[executor, classifier, mutator]

var failures = 0

proc check(what: string, ok: bool, detail = "") =
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), what,
       (if detail.len > 0: " -> " & detail else: "")

let exe = "build" / (if defined(windows): "vuln_parser.exe" else: "vuln_parser")
if not fileExists(exe):
  echo "  FAIL ", exe, " not found — run `nimble buildAll` first"
  quit(1)

let work = getTempDir() / "bug_genesis_noise_check.in"
let timeoutMs = 1000

# 觀測一個失敗、取其簽章，這就是閘門要驗證的目標簽章。
let bad = "x"
let rb = execute(exe, work, bad, timeoutMs)
check("fixture input fails", rb.kind.isFailure, rb.output.strip())
let wantSig = rb.signature

echo "== confirmSignature: a reproducible failure counts every probe =="
let n = confirmSignature(exe, work, bad, timeoutMs, wantSig, ReproProbes)
check("reproduces on all probes", n == ReproProbes, $n & "/" & $ReproProbes)

echo "== a *different* failure is not a reproduction =="
# `[1,` 走「unterminated array」，與 `x` 的「unexpected token」是兩個模板 ——
# 簽章必須不同，否則閘門會把兩個缺陷混成一個。
let other = "[1,"
let ro = execute(exe, work, other, timeoutMs)
check("second fixture also fails", ro.kind.isFailure, ro.output.strip())
check("the two failures have different signatures",
      ro.signature != wantSig)
let cross = confirmSignature(exe, work, other, timeoutMs, wantSig, ReproProbes)
check("different failure does not confirm this signature", cross == 0, $cross)

echo "== a passing input confirms nothing =="
let good = "{\"a\": 1}"
let rg = execute(exe, work, good, timeoutMs)
check("control input passes", not rg.kind.isFailure,
      "kind=" & rg.kind.label)
let passProbe = confirmSignature(exe, work, good, timeoutMs, wantSig,
                                 ReproProbes)
check("passing input yields zero confirmations", passProbe == 0, $passProbe)

echo "== recordNoise: down-weight, floor, and not a confirmed failure =="
var m = initMutator(7)
let s = msBitFlip
let start = m.weightOf(s)
m.recordNoise(s)
let after = m.weightOf(s)
check("weight drops after noise", after < start,
      formatFloat(start, ffDecimal, 4) & " -> " & formatFloat(after, ffDecimal, 4))
check("noise is not counted as a confirmed failure",
      m.stats.failures[s] == 0, $m.stats.failures[s])
# 打到下界就必須停住：無限衰減會把手法永久餓死，之後再也抽不到它。
for _ in 0 ..< 5000: m.recordNoise(s)
let floored = m.weightOf(s)
check("weight stops at a floor (no infinite decay)", floored > 0.0,
      formatFloat(floored, ffDecimal, 6))
m.recordNoise(s)
check("floor is stable", m.weightOf(s) == floored)
check("noise still never counted as confirmed failure",
      m.stats.failures[s] == 0, $m.stats.failures[s])

try: removeFile(work)
except OSError: discard

if failures == 0:
  echo "VERDICT: the gate separates reproducible failures from environmental noise."
else:
  echo "VERDICT: ", failures, " noise check(s) FAILED."
  quit(1)
