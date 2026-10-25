## profile — heuristic file-type detection for the Universal Binary Adapter.
##
## Phase 4.1 asks the engine to look at what it was actually given instead of
## guessing from the target's file extension. Two things depend on it:
##
##   * which Hypothesis family the bridge draws from (dialect), and
##   * what the campaign banner tells the operator it is about to do.
##
## The detection is deliberately **cheap and conservative**: a magic-number
## table, then a printable-text heuristic, then the JSON/INI sniffers the
## extension table used to stand in for. It never guesses a *structured* dialect
## on weak evidence, because the failure mode of a wrong structured guess is
## silent non-coverage — every generated input is rejected before it reaches the
## parser, and the campaign still reports progress. Guessing `raw` instead is
## always safe: raw inputs are never "wrong" for an unknown format, they are
## simply unstructured.
##
## This is a *profile*, not an identification: a `.bin` full of ASCII is
## reported as `text`, and a file that starts with `MZ` as `pe`, regardless of
## whether that claim is true.

import std/[strutils, tables]

type
  Profile* = object
    kind*:    string   ## pe | elf | pdf | zip | gzip | bzip2 | xz | s7z | rar |
                       ## png | jpeg | gif | cab | tar | json | ini | text |
                       ## binary
    dialect*: string   ## json | ini | raw — what the bridge should generate
    via*:     string   ## which rule decided, for the banner

proc startsWith(data: string, magic: string, at = 0): bool =
  if data.len < at + magic.len: return false
  for i in 0 ..< magic.len:
    if data[at + i] != magic[i]: return false
  true

# ---------------------------------------------------------------------------

const
  #: (offset, magic, profile). Checked in order; first match wins.
  MagicTable = [
    (0, "\x7fELF",      "elf"),
    (0, "MZ",           "pe"),
    (0, "%PDF",         "pdf"),
    (0, "PK\x03\x04",   "zip"),
    (0, "\x1f\x8b",     "gzip"),
    (0, "BZh",          "bzip2"),
    (0, "\xfd7zXZ\x00", "xz"),
    (0, "7z\xbc\xaf\x27\x1c", "s7z"),
    (0, "Rar!\x1a\x07", "rar"),
    (0, "\x89PNG\r\n\x1a\n", "png"),
    (0, "\xff\xd8\xff", "jpeg"),
    (0, "GIF87a",       "gif"),
    (0, "GIF89a",       "gif"),
    (0, "MSCF",         "cab"),
    (0, "\xca\xfe\xba\xbe", "pe"),   # Java class / Mach-O fat, handled as PE-family
    (257, "ustar",      "tar"),
  ]

proc looksPrintable(data: string): bool =
  ## Mostly ASCII text? NUL and high bytes count against.
  if data.len == 0: return true
  var printable = 0
  let n = min(data.len, 4096)
  for i in 0 ..< n:
    let c = ord(data[i])
    if c in {9, 10, 13} or (c >= 32 and c < 127) or c >= 128:
      inc printable
  # 0x80+ is allowed so UTF-8 / CP950 text still counts as text — this project
  # runs on a CP950 host and rejecting non-ASCII as "binary" would silently
  # route every Chinese-comment seed to the raw generators.
  printable * 100 >= n * 85

proc looksJson(data: string): bool =
  let t = data.strip()
  if t.len == 0: return false
  if t[0] != '{' and t[0] != '[': return false
  ('"' in t) or (':' in t)

proc looksIni(data: string): bool =
  ## A `[section]` header or a `key = value` line — the two shapes
  ## targets/cfgparser.py accepts. A single `=` anywhere is far too weak:
  #  most prose contains one.
  var hasSection = false
  var hasKeyValue = false
  for line in data.splitLines():
    let t = line.strip()
    if t.len == 0: continue
    if t[0] == '[' and ']' in t:
      hasSection = true
    elif '=' in t:
      # `key = value`, not a bare `=`: the '=' must be preceded by something.
      # A line that is only `=` is punctuation, not a key/value pair.
      if t.find('=') > 0:
        hasKeyValue = true
    if hasSection and hasKeyValue: return true
  hasSection or hasKeyValue

# ---------------------------------------------------------------------------

proc detectFormat*(data: string): Profile =
  ## Profile one buffer. Empty input is `binary`/`raw`: there is no header to
  ## read, and claiming `text` for zero bytes would be a coin flip.
  if data.len == 0:
    return Profile(kind: "binary", dialect: "raw", via: "empty input")

  for (offset, magic, kind) in MagicTable:
    if startsWith(data, magic, offset):
      # Container formats are `raw`: nothing in the bridge builds tar/PE/PDF
      # payloads yet, so claiming a structured dialect we cannot honour would
      # be exactly the silent degradation this module exists to prevent.
      return Profile(kind: kind, dialect: "raw",
                     via: "magic @" & $offset)

  if looksPrintable(data):
    if looksJson(data):
      return Profile(kind: "json", dialect: "json", via: "printable + {/[ + \":\"")
    if looksIni(data):
      return Profile(kind: "ini", dialect: "ini", via: "printable + section/key")
    return Profile(kind: "text", dialect: "raw", via: "printable, neither json nor ini")

  Profile(kind: "binary", dialect: "raw", via: "no magic, not printable")

proc dominantProfile*(samples: openArray[string]): Profile =
  ## Profile a whole seed corpus and pick the dialect the campaign should use.
  ##
  ## All samples must agree on the dialect; a corpus mixing an INI seed with a
  ## PE seed has no single right answer, and picking one would leave the other
  ## class permanently ungenerated. In that case we return `raw`, which is
  ## valid for everything — a weaker choice that still generates usable input,
  ## rather than a precise one that silently ignores half the corpus.
  if samples.len == 0:
    return Profile(kind: "empty", dialect: "raw", via: "no seeds")

  var first = detectFormat(samples[0])
  var mixed = false
  for i in 1 ..< samples.len:
    let p = detectFormat(samples[i])
    if p.dialect != first.dialect:
      mixed = true
      break

  if mixed:
    return Profile(kind: "mixed", dialect: "raw",
                   via: "seeds disagree (" & first.dialect & " vs others)")

  # Report the most common kind so the banner is informative, but the dialect
  # is already decided above.
  var counts = initCountTable[string]()
  for s in samples:
    counts.inc detectFormat(s).kind
  var kind = first.kind
  var best = -1
  for k, v in counts:
    if v > best:
      best = v
      kind = k
  Profile(kind: kind, dialect: first.dialect, via: first.via)