## storage/db — SQLite 知識庫（Phase 2 起為跨語言合約層）。
##
## 「錯誤知識累積」的落地層。引擎跑完就結束，但知識庫不結束：族群、簽章、
## 最小反例、每個策略的戰績都會留下來，下一輪可以直接接著挖，不必從零開始。
##
## ── Phase 2 合約升級：Hex → 原生 BLOB ─────────────────────────────────────
##
## Phase 1 的 `content_hex` / `repro_hex`（TEXT）是為繞過一個底層事實而生：
## `db_connector` 的 `exec(query, varargs[string])` 是把參數經 `dbQuote`
## **字串化**後拼進 SQL 的，帶 NUL 或任意位元組的內容會在中途中斷。
## Phase 2 全面改走 prepared statement + `bindParam`：
##   * 文字欄位 → `sqlite3_bind_text`
##   * content 欄位 → `sqlite3_bind_blob`（二進位無損，含 `\x00`）
## 讀取端 `setRow` / `getValue((stmt))` 對 `SQLITE_BLOB` 走 `column_blob` +
## `copyMem`，同樣無損。於是 Python `sqlite3` 讀 `sqlite3.BLOB`、Rust
## `rusqlite::blob`、TS `node:sqlite` Buffer 都拿到同一串位元組 ——
## 部署前的資料庫可以用原生工具直接驗證，不需要任何 hex 解碼器。
##
## ── 兩條寫入路徑，各有其不可省的理由 ───────────────────────────────────────
##
##   `exec(t, args)`（prepared）：**所有可變資料**都走這裡 —— content 是
##   BLOB，簽章與輸出含任意位元組與引號，`dbQuote` 對它們不保證安全。
##
##   `exec(sql"...", ...)`（字串插值）：只用在 `nowIso()`、`$整數` 這類
##   **全程式集構造**的值。這不是疏忽，是刻意的限制邊界。
##
## ── 兩個底層地雷（都已在此模組封鎖） ───────────────────────────────────────
##  ##   1. `bindParam(ps, idx, openArray[byte])` 的實作是 `val[0].unsafeAddr`，
  ##      **空陣列會越界**。實測結果是 `IndexDefect`（不可攔截的 Defect），
  ##      一次呼叫就能殺死引擎。所以：`content`（NOT NULL）走 `blobBytes()`，
  ##      空值直接拋 `ValueError`；`repro`（可空）走 `bindBlobOrNull()`。
##   2. `getValue` 只回傳**第一個欄位的第一列**（文件明載）。多欄位查詢
##      必須用 `getAllRows`。Phase 1 正是栽在這裡：`repro_len` 恆讀為 0，
##      於是每一次後續命中都把已縮減的最小反例覆寫回未縮減的大輸入。
##
## ── 主鍵與跨語言可攜性 ─────────────────────────────────────────────────────
##
## `id` / `family_id` 是 **TEXT**（ULID：時間有序 + 隨機尾綴）。跨語言
## 寫入者（Python adapter）無法安全共用 SQLite 的 `AUTOINCREMENT` 計數器，
## 而 ULID 讓任何語言都能獨立生成不衝突、且按時間可排序的鍵值。
## `bug_families.signature` 維持 UNIQUE —— 去重合約跨語言不變。
##
## 所有次時間欄位維持 ISO-8601 UTC（**非** SQLite TIMESTAMP（text）別名），
## 因為 `TIMESTAMP` 在 Python 會被 `detect_types` 解析成 naive `datetime`
## 帶到 UTC 之外，跨語言讀取者語意不明。

import std/[strutils, times, hashes, monotimes]
import db_connector/db_sqlite
import engine/[mutator, executor, classifier]

type
  FamilyRow* = object
    id*:        string
    signature*: string
    kindLabel*: string
    code*:      string
    hitCount*:  int64
    repro*:     string          ## BLOB 解碼後的最小反例
    reproLen*:  int64
    firstSeen*: string
    lastSeen*:  string

  CaseRow* = object
    id*:        string
    familyId*:  string
    kindLabel*: string
    rawExit*:   int32
    elapsedMs*: int64
    len*:       int64
    strategy*:  string
    repro*:     bool

  RunRow* = object
    id*:        string
    startedAt*: string
    target*:    string
    workers*:   int
    timeoutMs*: int
    execs*:     int64
    families*:  int64

proc describe*(f: FamilyRow): string =
  ## 供終端機輸出的單行摘要。
  "family " & f.id & " [" & f.kindLabel & " " & f.code &
  "] hits=" & $f.hitCount & " repro=" & $f.reproLen & "B"

const
  Schema* = """
CREATE TABLE IF NOT EXISTS bug_families(
  id          TEXT    PRIMARY KEY,
  signature   TEXT    NOT NULL UNIQUE,
  kind_label  TEXT    NOT NULL,
  code        TEXT    NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 0,
  repro       BLOB,
  repro_len   INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT    NOT NULL,
  last_seen   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS test_cases(
  id           TEXT    PRIMARY KEY,
  family_id    TEXT,
  content      BLOB    NOT NULL,
  content_hash TEXT    NOT NULL,
  content_len  INTEGER NOT NULL,
  kind_label   TEXT    NOT NULL,
  raw_exit     INTEGER NOT NULL,
  elapsed_ms   INTEGER NOT NULL,
  output       TEXT    NOT NULL DEFAULT '',
  strategy     TEXT    NOT NULL,
  signature    TEXT    NOT NULL DEFAULT '',
  is_repro     INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT    NOT NULL,
  FOREIGN KEY (family_id) REFERENCES bug_families(id)
);
CREATE INDEX IF NOT EXISTS idx_tc_family ON test_cases(family_id);
CREATE INDEX IF NOT EXISTS idx_tc_hash   ON test_cases(content_hash);
CREATE INDEX IF NOT EXISTS idx_tc_kind   ON test_cases(kind_label);
CREATE INDEX IF NOT EXISTS idx_tc_repro  ON test_cases(is_repro);
CREATE TABLE IF NOT EXISTS strategy_stats(
  strategy      TEXT    PRIMARY KEY,
  tries         INTEGER NOT NULL DEFAULT 0,
  failures      INTEGER NOT NULL DEFAULT 0,
  new_families  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_log(
  id         TEXT    PRIMARY KEY,
  started_at TEXT    NOT NULL,
  target     TEXT    NOT NULL,
  workers    INTEGER NOT NULL,
  timeout_ms INTEGER NOT NULL,
  seed_hex   TEXT    NOT NULL,
  execs      INTEGER NOT NULL DEFAULT 0,
  families   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS noise_log(
  id          TEXT    PRIMARY KEY,
  signature   TEXT    NOT NULL,
  kind_label  TEXT    NOT NULL,
  code        TEXT    NOT NULL,
  strategy    TEXT    NOT NULL,
  probes_ok   INTEGER NOT NULL,
  probes      INTEGER NOT NULL,
  output      TEXT    NOT NULL DEFAULT '',
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_noise_sig ON noise_log(signature);
CREATE TABLE IF NOT EXISTS tainted_offsets(
  byte_offset INTEGER PRIMARY KEY,
  hits        INTEGER NOT NULL DEFAULT 1,
  signature   TEXT    NOT NULL DEFAULT '',
  last_seen   TEXT    NOT NULL
);
"""

# ---------------------------------------------------------------------------
# 合約底層：時間、鍵值、安全繫結
# ---------------------------------------------------------------------------

proc nowIso(): string =
  ## UTC 時刻，格式固定為 `yyyy-MM-dd'T'HH:mm:ss'Z'`。
  ## 不使用 `TIMESTAMP` 型別語意：見模組檔頭的跨語言時區說明。
  now().format("yyyy-MM-dd'T'HH:mm:ss'Z'")

## 同一毫秒內的呼叫去重計數。
## 只有主執行緒寫入知識庫（見 genesis_core 的執行緒契約），
## 因此普通全域計數就足夠，不需要原子操作。
var idCounter: uint64 = 0

proc newId*(prefix: char): string =
  ## 產生跨語言可獨立生成的鍵值。
  ##
  ## 格式 `<prefix>_<14 位基 32 時間碼><12 位基 32 隨機碼>`，去掉了易混淆的
  ## 字元（I、L、O、U），因此純字面量可安全朗讀、可比較、可排序。
  ## 時間碼在前讓主鍵天然按創建時間有序 —— SQLite 的 B-tree 主鍵直接從中
  ## 得益，避免 AUTOINCREMENT 在跨語言並行插入時的序列化瓶頸。
  var ts = int64(epochTime() * 1000)
  const Digits = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  var tbuf = newString(14)
  for i in countdown(13, 0):
    tbuf[i] = Digits[int(ts and 31)]
    ts = ts shr 5
  # 以單調時鐘混合 nonce，避免同一毫秒內的呼叫產生相同前綴。
  # 注意運算必須在 uint64 上進行：LCG 的乘法一定會溢出預設 int，
  # 而在 overflowChecks 開啟時那是 OverflowDefect 而非靜默環繞。
  inc idCounter
  let mixed = cast[uint64](getMonoTime().ticks) xor
              (idCounter * 0x9E3779B97F4A7C15'u64)
  var state = mixed or 1'u64
  var rbuf = newString(12)
  for i in 0 ..< 12:
    state = state * 6364136223846793005'u64 + 1442695040888963407'u64
    rbuf[i] = Digits[int((state shr 58) and 31'u64)]
  result = prefix & "_" & tbuf & rbuf

proc blobBytes*(s: string): seq[byte] =
  ## **所有** BLOB 繫結的入口。
  ##
  ## 為什麼不直接把 `string` 當 `openArray[byte]` 傳：`db_connector` 的
  ## `bindParam(_, _, openArray[byte])` 實作是 `val[0].unsafeAddr` ——
  ## 空輸入會對長度為 0 的陣列取址並解引用。
  ##
  ## 這不是理論風險，是實測到的崩潰：空內容會拋 `IndexDefect`，而 Defect
  ## 不屬 `CatchableError`，一次呼叫就能殺死整個引擎執行緒。所以這裡
  ## **主動拒絕空值**，把它轉成帶明確原因的 `ValueError` ——
  ## 合約層的錯誤必須是可攔截、可診斷的，而不是靜默 UB。
  if s.len == 0:
    raise newException(ValueError,
      "cannot bind an empty BLOB: db_connector's bindParam(openArray[byte]) " &
      "dereferences val[0] and crashes on a zero-length array")
  result = newSeqOfCap[byte](s.len)
  for c in s: result.add byte(c)

proc bindBlobOrNull*(ps: SqlPrepared, idx: int, s: string) =
  ## 可空 BLOB 欄位的繫結：空 → NULL，非空 → 原生 BLOB。
  ##
  ## 用於 `repro`（欄位本身允許 NULL，語意為「尚未縮減」）。
  ## 不用於 `content`：那欄是 NOT NULL，空內容是合約違反而非「沒有值」。
  if s.len == 0: ps.bindNull(idx)
  else:          ps.bindParam(idx, blobBytes(s), copy = true)

proc lastInsertId(db: DbConn): int64 =
  ## prepared-statement 路徑沒有 `insertID`（那只有字串插值 API），
  ## 所以這裡直接查 SQLite 自身的函數。
  parseBiggestInt(db.getValue(sql"SELECT last_insert_rowid()"))

# ---------------------------------------------------------------------------
# 連線
# ---------------------------------------------------------------------------

proc openDb*(path: string): DbConn =
  ## `path` 同時作為資料庫檔案與 journal；不存在時自動建立。
  open(path, "", "", "")

proc initSchema*(db: DbConn) =
  # WAL：模糊測試是持續寫入的小交易負載，預設的 rollback journal 每筆都要
  # fsync 整個 journal。WAL 讓寫入追加到尾端，並允許讀寫並行。
  # synchronous=NORMAL 在 WAL 下是安全的折衷：程序崩潰不會損毀資料庫，
  # 只可能損失最後一次 checkpoint 後的交易，而引擎本來就能重跑。
  db.exec(sql"PRAGMA journal_mode=WAL")
  db.exec(sql"PRAGMA synchronous=NORMAL")
  for stmt in Schema.split(';'):
    let s = stmt.strip()
    if s.len > 0:
      db.exec(sql(s))

proc hashOf*(content: string): string =
  ## 內容指紋：64-bit 雜湊 + 長度尾綴。
  ##
  ## 這只服務於「這個輸入見過了嗎」的快速判斷，不是金鑤或簽章，因此不需要
  ## SHA-1 —— `std/sha1` 已標記棄用，而為了索引多拉一條第三方依賴不划算。
  ## 長度尾綴讓不同長度的輸入不可能落到同一個鍵值格式。
  toHex(cast[uint64](hash(content)), 16) & "#" & $content.len

proc preview*(s: string, maxLen = 100): string =
  ## 把任意位元組串變成安全可印的預覽。
  ## 不用 strutils.escape，因為它不會把不可印位元組轉成 \\xNN，
  ## 變異輸入經常含控制字元，直接印會汙染終端。
  var printable = true
  for c in s:
    if c.ord < 32 or c.ord > 126: printable = false; break
  if printable:
    result = if s.len <= maxLen: s else: s[0 ..< maxLen] & "…"
  else:
    let hex = toHex(s)
    result = if hex.len <= maxLen: "0x" & hex
             else: "0x" & hex[0 ..< maxLen] & "…"

# ---------------------------------------------------------------------------
# Bug families
# ---------------------------------------------------------------------------

proc upsertFamily*(db: DbConn, sig, kindLabel, code: string): tuple[id: string, isNew: bool] =
  ## 依簽章回報族群 id。簽章已存在則累加命中數；否則建立新族群。回傳 isNew
  ## 供主迴圈判斷是否要觸發縮減與列印。
  ##
  ## ⚠ 這裡**不收** repro。`bug_families.repro` 只有一個寫入者：`saveRepro`。
  ## 曾經這裡會順手把命中的輸入存成反例，造成兩個後果，而且都很難察覺：
  ## `repro IS NULL`（「尚未縮減」的查詢契約）從此永不成立；以及後來的命中
  ## 會把**已經驗證過的最小反例**覆寫回任意命中的輸入，知識庫悄悄弄丟最值錢
  ## 的成果。
  let found = db.getAllRows(
    sql"SELECT id FROM bug_families WHERE signature = ?", sig)
  let ts = nowIso()

  if found.len > 0:
    let t = db.prepare("""UPDATE bug_families
                           SET hit_count = hit_count + 1, last_seen = ?
                           WHERE id = ?""")
    t.bindParams(ts, found[0][0])
    db.exec(t)
    finalize(t)
    (found[0][0], false)
  else:
    let id = newId('F')
    # 還沒有反例（縮減還沒跑）：以 NULL 綁定，讓 `repro IS NULL` 可用於
    # 「尚未縮減」的查詢，而不是用空 BLOB 混淆「反例就是空的」。
    let t = db.prepare("""INSERT INTO bug_families
                           (id, signature, kind_label, code, hit_count,
                            repro, repro_len, first_seen, last_seen)
                         VALUES (?,?,?,?,?,NULL,'0',?,?)""")
    t.bindParams(id, sig, kindLabel, code, "1", ts, ts)
    db.exec(t)
    finalize(t)
    (id, true)

proc familyIdBySig*(db: DbConn, sig: string): string =
  ## 已登記族群的 id；未登記回傳空字串。
  ##
  ## 供重現閘門（模組 3）在 upsert **之前**判定「這個簽章到底進過知識庫沒」。
  ## 閘門必須先於 upsertFamily：一旦先 upsert 就已經建了族群，再回頭擋雜訊
  ## 就得刪列，而「先建再刪」會在 hit_count 與 first_seen 留下假事實。
  db.getValue(sql"SELECT id FROM bug_families WHERE signature = ?", sig)

proc saveRepro*(db: DbConn, familyId: string, repro: string) =
  ## 縮減完成後回寫最小反例。**唯一的寫入者** —— `upsertFamily` 不碰這欄。
  ## 只在新的更短時才覆寫，保留最精簡的版本。
  ##
  ## 空 `repro` 是 no-op 而不是錯誤：欄位可空，NULL 已經承載了「尚未縮減」
  ## 的語意，把空字串寫進去沒有任何意義，更不該為此崩潰。
  if repro.len == 0: return
  let rows = db.getAllRows(
    sql"SELECT repro_len FROM bug_families WHERE id = ?", familyId)
  let cur =
    if rows.len > 0 and rows[0][0].len > 0: parseBiggestInt(rows[0][0])
    else: 0'i64
  if cur == 0 or repro.len < cur:
    let t = db.prepare("""UPDATE bug_families SET repro = ?, repro_len = ?
                          WHERE id = ?""")
    t.bindParams(blobBytes(repro), $repro.len, familyId)
    db.exec(t)
    finalize(t)

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

proc saveTestCase*(db: DbConn, content: string, r: ExecResult, sig: string,
                   familyId: string, strategy: string, isRepro: bool): string =
  ## 寫入一筆失敗案例並回傳其 ULID。
  ## content 以原生 BLOB 綁定 —— 變異輸入富含 NUL 與高位元組，
  ## 這正是 Phase 2 犧牲 hex 換來的正確性。
  ##
  ## `content` 是 NOT NULL 欄位，因此空內容是合約違反而非「沒有值」，
  ## 在這裡明確拒絕（`blobBytes` 也會攔，但那則錯誤訊息不會指向欄位名）。
  if content.len == 0:
    raise newException(ValueError,
      "saveTestCase: 'content' must be non-empty (column is NOT NULL BLOB)")
  let id = newId('C')
  let t = db.prepare("""INSERT INTO test_cases
        (id, family_id, content, content_hash, content_len, kind_label, raw_exit,
         elapsed_ms, output, strategy, signature, is_repro, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""")
  if familyId.len > 0:
    t.bindParams(id, familyId, blobBytes(content), hashOf(content), $content.len,
                 r.kind.label, $r.rawExit, $r.elapsedMs, r.output,
                 strategy, sig, (if isRepro: "1" else: "0"), nowIso())
  else:
    t.bindParams(id, nil, blobBytes(content), hashOf(content), $content.len,
                 r.kind.label, $r.rawExit, $r.elapsedMs, r.output,
                 strategy, sig, (if isRepro: "1" else: "0"), nowIso())
  db.exec(t)
  finalize(t)
  id

proc savePassingCase*(db: DbConn, content: string, r: ExecResult,
                      strategy: string): string =
  ## 通過的案例也入庫 —— 知識庫要能回答「哪些輸入是已知可行的」，
  ## 而不是只存壞掉的東西。family_id 為 NULL，signature 恆為空。
  if content.len == 0:
    raise newException(ValueError,
      "savePassingCase: 'content' must be non-empty (column is NOT NULL BLOB)")
  let id = newId('C')
  let t = db.prepare("""INSERT INTO test_cases
        (id, family_id, content, content_hash, content_len, kind_label, raw_exit,
         elapsed_ms, output, strategy, signature, is_repro, created_at)
        VALUES (?,NULL,?,?,?,?,?,?,?,?,?,'0',?)""")
  t.bindParams(id, blobBytes(content), hashOf(content), $content.len,
               r.kind.label, $r.rawExit, $r.elapsedMs, r.output, strategy, "",
               nowIso())
  db.exec(t)
  finalize(t)
  id

proc seenBefore*(db: DbConn, content: string): bool =
  ## 查這個輸入是否已入庫。
  ##
  ## 比對的是 `content_hash`（由 `hashOf` 產生的純文字索引鍵），**不是**
  ## content 欄位本身：後者是 BLOB，把它拿去 bind_text 與 BLOB 比對會牽扯到
  ## SQLite 的文字/二進位 affinity 轉換，語意不確定。雜湊鍵則完全在文字域。
  db.getValue(sql"SELECT 1 FROM test_cases WHERE content_hash = ? LIMIT 1",
              hashOf(content)).len > 0

# ---------------------------------------------------------------------------
# 環境雜訊（模組 3）與感染點（模組 4）
# ---------------------------------------------------------------------------

proc saveNoise*(db: DbConn, sig, kindLabel, code, strategy, output: string,
                probesOk, probes: int) =
  ## 記錄一次**被重現閘門擋下**的觀測。
  ##
  ## 擋下不等於抹掉：被排除的觀測必須可被審計，否則「雜訊過濾」與「默默丟棄
  ## 資料」在事後完全無法區分。`probes_ok / probes` 就是當時的重現證據。
  let id = newId('N')
  let t = db.prepare("""INSERT INTO noise_log
        (id, signature, kind_label, code, strategy, probes_ok, probes,
         output, created_at)
        VALUES (?,?,?,?,?,?,?,?,?)""")
  t.bindParams(id, sig, kindLabel, code, strategy, $probesOk, $probes,
               output, nowIso())
  db.exec(t)
  finalize(t)

proc noiseCount*(db: DbConn): int64 =
  ## 本知識库累計排除的環境雜訊次數。
  parseBiggestInt(db.getValue(sql"SELECT COUNT(*) FROM noise_log"))

const
  TaintHits* = 2
    ## 偏移量需要**反覆**引發異常才升格為活躍感染點。
    ##
    ## 一次就夠的話，位元組級解析器的每一次失敗都會造一個新“感染點”（實測
    ## 200 次執行冒出 19 個），而“到处都是高優先级”等於没有優先級 —— 變異
    ## 分佈被摊平，模組 4 与不做任何偏置没有区别。2 次是“不是偶然”的最小证据。

proc upsertTainted*(db: DbConn, byteOffset: int, sig: string): int64 =
  ## 登記/累加一個偏移量的命中，回傳**累計命中次數**（新偏移量为 1）。
  ##
  ## 只有通过重現閘門的觀測才能進到這裡（呼叫端保證），否則雜訊也會把
  ## 偏移量升格成高優先級轟炸目標 —— 那正好與模組 3 的目的相反。
  ##
  ## 回傳命中數而非「是否新」：升格條件是 `hits >= TaintHits`，呼叫端要的
  ## 正是這個數字來判斷「剛剛越過門檻没有」。
  let ts = nowIso()
  let found = db.getAllRows(
    sql"SELECT byte_offset FROM tainted_offsets WHERE byte_offset = ?",
    byteOffset)
  if found.len > 0:
    let t = db.prepare("""UPDATE tainted_offsets
                           SET hits = hits + 1, last_seen = ?
                           WHERE byte_offset = ?""")
    t.bindParams(ts, $byteOffset)
    db.exec(t)
    finalize(t)
    parseBiggestInt(db.getValue(
      sql"SELECT hits FROM tainted_offsets WHERE byte_offset = ?",
      $byteOffset))
  else:
    let t = db.prepare("""INSERT INTO tainted_offsets
                           (byte_offset, hits, signature, last_seen)
                         VALUES (?,1,?,?)""")
    t.bindParams($byteOffset, sig, ts)
    db.exec(t)
    finalize(t)
    1'i64

proc loadTainted*(db: DbConn, limit = 8): seq[int] =
  ## 取回**活躍**感染點（hits >= TaintHits），依命中強度排序。
  ##
  ## 只回報真的會被變異引擎追蹤的那一組：把未達門檻的偏移量也列進來，會讓
  ## 報表聲稱「N 個偏移量正在被優先轟炸」，而 mutator 实际只记住了其中 8 个。
  for row in db.getAllRows(
      sql"""SELECT byte_offset FROM tainted_offsets
            WHERE hits >= ?
            ORDER BY hits DESC, byte_offset ASC LIMIT ?""",
      $TaintHits, $limit):
    try:
      result.add parseInt(row[0])
    except ValueError:
      discard  # 主鍵由 upsertTainted 以 int 寫入；不可解析就跳過而非讓活動崩潰

proc taintedCount*(db: DbConn): int64 =
  ## 活躍感染點數（與 loadTainted 同一門檻），供報表與收尾摘要使用。
  parseBiggestInt(db.getValue(
    sql"SELECT COUNT(*) FROM tainted_offsets WHERE hits >= ?", $TaintHits))

# ---------------------------------------------------------------------------
# Strategy statistics（Failure-Directed 的持久化）
# ---------------------------------------------------------------------------

proc loadStats*(db: DbConn): StrategyStats =
  for row in db.getAllRows(
      sql"SELECT strategy, tries, failures, new_families FROM strategy_stats"):
    let s = parseStrategy(row[0])
    result.tries[s] = parseBiggestInt(row[1])
    result.failures[s] = parseBiggestInt(row[2])
    result.newFamilies[s] = parseBiggestInt(row[3])

proc saveStats*(db: DbConn, st: StrategyStats) =
  ## 規格化戰績。這裡的參數全是 `$int` / `s.label` —— **全程式集構造值**，
  ## 不含使用者輸入，因此允許走字串插值路徑（見模組檔頭的路徑邊界）。
  for s in MutationStrategy:
    db.exec(sql"""INSERT INTO strategy_stats
                     (strategy, tries, failures, new_families)
                  VALUES (?,?,?,?)
                  ON CONFLICT(strategy) DO UPDATE SET
                    tries = excluded.tries,
                    failures = excluded.failures,
                    new_families = excluded.new_families""",
            s.label, $st.tries[s], $st.failures[s], $st.newFamilies[s])

# ---------------------------------------------------------------------------
# 查詢與報表
# ---------------------------------------------------------------------------

proc getFailureHistory*(db: DbConn, limit = 20): seq[FamilyRow] =
  for row in db.getAllRows(
      sql"""SELECT id, signature, kind_label, code, hit_count, repro,
                   repro_len, first_seen, last_seen
            FROM bug_families ORDER BY hit_count DESC, id ASC LIMIT ?""",
      $limit):
    result.add FamilyRow(
      id: row[0],
      signature: row[1],
      kindLabel: row[2],
      code: row[3],
      hitCount: parseBiggestInt(row[4]),
      # BLOB 經 `setRow` 的 column_blob + copyMem 讀回，含 NUL 無損。
      repro: row[5],
      reproLen: if row[6].len > 0: parseBiggestInt(row[6]) else: 0'i64,
      firstSeen: row[7],
      lastSeen: row[8])

proc getMinimalRepros*(db: DbConn): seq[FamilyRow] =
  ## 只回傳**已縮減**的族群（repro 非 NULL）。
  var all = db.getFailureHistory(1_000_000)
  for f in all.mitems:
    if f.repro.len == 0: continue
    result.add f

proc counts*(db: DbConn): tuple[cases, failures, families, repros: int64] =
  ## `repros` 只數**縮減真的跑過並驗證過**的族群（`repro_len > 0` 現在等價於
  ## 「`saveRepro` 寫過」），因此與 `reproCaseCount` 必須相等；不等就是落庫漏了。
  result.cases = parseBiggestInt(db.getValue(sql"SELECT COUNT(*) FROM test_cases"))
  result.failures = parseBiggestInt(db.getValue(
    sql"SELECT COUNT(*) FROM test_cases WHERE family_id IS NOT NULL"))
  result.families = parseBiggestInt(
    db.getValue(sql"SELECT COUNT(*) FROM bug_families"))
  result.repros = parseBiggestInt(db.getValue(
    sql"SELECT COUNT(*) FROM bug_families WHERE repro_len > 0"))

proc reproCaseCount*(db: DbConn): int64 =
  ## 正式登記為「最小反例」的案例列數。
  parseBiggestInt(db.getValue(
    sql"SELECT COUNT(*) FROM test_cases WHERE is_repro = 1"))

proc kindHistogram*(db: DbConn): seq[(string, int64)] =
  for row in db.getAllRows(
      sql"""SELECT kind_label, COUNT(*) FROM test_cases
            GROUP BY kind_label ORDER BY COUNT(*) DESC"""):
    result.add (row[0], parseBiggestInt(row[1]))

proc strategyTable*(db: DbConn): seq[tuple[strategy: string, tries, failures,
                                            newFamilies: int64]] =
  ## Failure-Directed 的戰績。供報表與跨語言檢視使用。
  for row in db.getAllRows(
      sql"""SELECT strategy, tries, failures, new_families FROM strategy_stats
            ORDER BY new_families DESC, failures DESC, strategy ASC"""):
    result.add (row[0], parseBiggestInt(row[1]), parseBiggestInt(row[2]),
                parseBiggestInt(row[3]))

proc startRun*(db: DbConn, target: string, workers, timeoutMs: int,
               seedHex: string): string =
  let id = newId('R')
  let t = db.prepare("""INSERT INTO run_log
        (id, started_at, target, workers, timeout_ms, seed_hex, execs, families)
        VALUES (?,?,?,?,?,?,0,0)""")
  t.bindParams(id, nowIso(), target, $workers, $timeoutMs, seedHex)
  db.exec(t)
  finalize(t)
  id

proc finishRun*(db: DbConn, runId: string, execs, families: int64) =
  let t = db.prepare(
    "UPDATE run_log SET execs = ?, families = ? WHERE id = ?")
  t.bindParams($execs, $families, runId)
  db.exec(t)
  finalize(t)

proc getRunHistory*(db: DbConn): seq[RunRow] =
  for row in db.getAllRows(
      sql"""SELECT id, started_at, target, workers, timeout_ms, execs, families
            FROM run_log ORDER BY started_at ASC"""):
    result.add RunRow(
      id: row[0], startedAt: row[1], target: row[2],
      workers: parseInt(row[3]), timeoutMs: parseInt(row[4]),
      execs: parseBiggestInt(row[5]), families: parseBiggestInt(row[6]))

# ---------------------------------------------------------------------------
# 報表
# ---------------------------------------------------------------------------

proc renderReport*(db: DbConn): string =
  ## 終端機與驗收用的完整摘要（知識庫累積的全貌，跨輪次累加）。
  let c = db.counts
  var lines: seq[string]
  lines.add ""
  lines.add repeat('=', 78)
  lines.add "BUG GENESIS — Phase 2 結果報告"
  lines.add repeat('=', 78)
  lines.add "執行次數        : " & $c.cases
  lines.add "失敗次數        : " & $c.failures
  lines.add "錯誤族群        : " & $c.families
  lines.add "已縮減最小反例  : " & $c.repros & " 個族群 / " &
             $db.reproCaseCount & " 筆案例"
  if c.repros != db.reproCaseCount:
    # 兩個數字來自不同的表（bug_families vs test_cases），任何落庫遺漏都會在
    # 這裡現形。寧可讓它大聲失敗，也不要印一個自相矛盾卻看起來正常的報表。
    lines.add "  !! 不一致：族群反例數與最小反例案例數不符，知識庫有落庫缺口"
  lines.add "合約格式        : 原生 BLOB（content / repro）+ TEXT 主鍵"
  # 被排除的觀測也是知識的一部分：只報「找到幾個族群」而不報「擋掉了幾次」，
  # 会让一個把所有偶發故障都當雜訊丟掉的活動看起來與成功活動一模一樣。
  lines.add "環境雜訊        : " & $db.noiseCount & " 次觀測未通過重現閘門"
  let tn = db.taintedCount
  if tn > 0:
    var offs: seq[string]
    for o in db.loadTainted(8): offs.add $o
    lines.add "感染點          : " & $tn &
               " 個偏移量反覆引發異常（變異追蹤前 8，依命中排序）: " &
               join(offs, ", ")
  else:
    lines.add "感染點          : 0"
  # 不在這裡印吞吐量：它是「這一輪」的指標，而且真正的轟炸耗時必須扣除
  # 反例縮減，否則會把縮減的一次性成本誤報成引擎跑不快。見 genesis_core。
  lines.add ""
  lines.add "失敗型態分佈："
  for (k, n) in db.kindHistogram:
    lines.add "  " & alignLeft(k, 24) & $n

  lines.add ""
  lines.add "變異策略戰績（Failure-Directed）："
  lines.add "  " & alignLeft("strategy", 24) &
            alignLeft("tries", 10) & alignLeft("fails", 10) & "newFam"
  for r in db.strategyTable:
    lines.add "  " & alignLeft(r.strategy, 24) &
              alignLeft($r.tries, 10) & alignLeft($r.failures, 10) &
              $r.newFamilies

  lines.add ""
  lines.add "錯誤族群與最小反例："
  for f in db.getFailureHistory(50):
    lines.add "  " & f.describe
    lines.add "      簽章: " & signatureSample(f.signature, 74)
    if f.repro.len > 0:
      lines.add "      反例: " & preview(f.repro)
    else:
      lines.add "      反例: (尚未縮減)"
  lines.add repeat('=', 78)
  lines.add ""
  lines.join("\n")
