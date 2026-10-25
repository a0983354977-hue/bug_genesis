## Does detectFormat actually say the right thing about real bytes?
##
## Compile with the project's config.nims (it puts src/ on --path):
##     nim c -r --hints:off targets/profile_check.nim
##
## This is an assertion program, not a demo: a wrong answer here silently
## routes a whole campaign's generators at the wrong dialect, and the symptom
## is a campaign that reports progress while never reaching the parser.

import std/[strutils]
import engine/profile

var failures = 0

proc check(what, data, wantKind, wantDialect: string) =
  let got = detectFormat(data)
  let ok = got.kind == wantKind and got.dialect == wantDialect
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), what,
      " -> kind=", got.kind, " dialect=", got.dialect,
      " (via ", got.via, ")",
      (if ok: "" else: "  expected " & wantKind & "/" & wantDialect)

echo "== magic numbers =="
check("ELF",        "\x7fELF\x02\x01\x01\x00",                    "elf",   "raw")
check("PE/MZ",      "MZ\x90\x00\x03",                             "pe",    "raw")
check("PDF",        "%PDF-1.7\n1 0 obj",                          "pdf",   "raw")
check("ZIP",        "PK\x03\x04\x14\x00",                         "zip",   "raw")
check("gzip",       "\x1f\x8b\x08\x00",                           "gzip",  "raw")
check("xz",         "\xfd7zXZ\x00\x00",                           "xz",    "raw")
check("PNG",        "\x89PNG\r\n\x1a\n\x00\x00",                  "png",   "raw")
check("JPEG",       "\xff\xd8\xff\xe0\x00\x10JFIF",               "jpeg",  "raw")
check("GIF",        "GIF89a...",                                  "gif",   "raw")
check("CAB",        "MSCF\x00\x00",                               "cab",   "raw")


echo "== tar: magic lives at offset 257, not 0 =="
# newString fills with NUL, which is not what a real tar header looks like.
# Fill with printable bytes so the fixture is a *header*, and the test really
# is about offset 257 rather than about NUL detection.
var tar = repeat(' ', 512)
tar[0 ..< 5] = "hello"
tar[257 ..< 262] = "ustar"
check("tar (ustar @257)", tar, "tar", "raw")
var notTar = repeat(' ', 512)
notTar[0 ..< 5] = "hello"
check("512B without ustar", notTar, "text", "raw")


echo "== structured text =="
check("INI seed",  "[server]\nport = 8080\n",                     "ini",   "ini")
check("JSON seed", "{\"k\": [1, 2, 3]}",                          "json",  "json")
check("prose",     "this is just a sentence with no structure",   "text",  "raw")
check("UTF-8/CJK", "# \xe6\xb7\xb1\xe5\xb1\xa2\xe5\xad\x90\n[server]\nport = 1\n",
                                                                        "ini",   "ini")


echo "== binary with no known magic =="
# Control bytes, not "random" ones: a buffer that is 95% printable 'Z' is
# correctly read as text, and a fixture built that way would be testing the
# fixture rather than the profiler.
let control = repeat("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10\x11\x12\x13\x14", 8)
block:
  var nonPrintable = 0
  for c in control:
    if ord(c) < 32 and c notin {'\t', '\n', '\r'}: inc nonPrintable
  echo "       (fixture: ", nonPrintable, "/", control.len, " non-printable)"
check("control bytes 128B", control,                              "binary", "raw")
check("empty",       "",                                             "binary", "raw")


echo "== dominantProfile over a corpus =="
block:
  let iniSeeds = ["[server]\nport = 1\n", "[client]\ntls = true\n"]
  let p = dominantProfile(iniSeeds)
  let ok = p.dialect == "ini"
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), "uniform INI corpus -> ", p.dialect
block:
  # A corpus that mixes formats has no single right dialect. Claiming one
  # would permanently stop generating for the other class, so the answer
  # must be `raw` -- weaker, but never wrong.
  let mixed = ["[server]\nport = 1\n", "%PDF-1.7\n"]
  let p = dominantProfile(mixed)
  let ok = p.dialect == "raw" and p.kind == "mixed"
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), "mixed corpus -> ", p.dialect, "/", p.kind
block:
  let p = dominantProfile([])
  let ok = p.dialect == "raw"
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), "empty corpus -> ", p.dialect


if failures == 0:
  echo "VERDICT: every profile matches the bytes it was given."
  quit(0)
echo "VERDICT: ", failures, " profile(s) disagree with their input."
quit(1)