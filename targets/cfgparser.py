#!/usr/bin/env python3
"""cfgparser -- BUG GENESIS Phase 3 的第二個測試標的（Python 目標）。

這是一個設定檔解析器：INI 風格的區段與鍵值，解析後**必須通過語意驗證**
（型別、範圍、互斥欄位、跨欄位相依）。它刻意埋入多種真實缺陷，因此
模糊測試引擎只能看到作業系統或直譯器親自回報的結果。

為什麼需要第二個標的：Phase 1/2 的標的 `vuln_parser` 是 Nim 編譯的二進位。
P3 要證明的是**跨語言**閉環 —— 引擎能指揮 Python/Hypothesis 產生結構化
輸入，並且這些輸入的觀測結果能與原生標的寫進同一套簽章空間。

退出碼合約（與 vuln_parser 逐字一致，執行器據此正規化）：

  0        解析且語意驗證通過
  1        解析或驗證失敗 -- stderr 帶有可辨識的 ANOMALY 簽章
  真實崩潰  0xC0000005 空指標存取（ctypes）/ 0xC00000FD 堆疊溢位（不可能）
  掛死      續行跳脫序列在 EOF 前停止推進（無窮迴圈）

用法：cfgparser <輸入檔路徑>

缺陷觸發條件對照（第三步的 Hypothesis 產生器就是照這幾條路設計的）：

  AV_TRIGGER_RUN_LEN  數值欄位內含 >= 16 連續 'A'（真實空指標解引用）
  NEST_LIMIT          區段巢狀深度 > 200（無深度上限 -> RecursionError）
  DIV_ZERO_MASK       port 經 16 位元截斷後為 0（隨後被當成除數）
  HANG_CONTINUATION   行尾是孤立反斜線且檔案在此結束（游標不再推進）
  XOR_KEY_SEED        標記內部狀態的魔術值，命中即寫入未配置的快取
"""

from __future__ import annotations

import ctypes
import os
import sys

# ---------------------------------------------------------------------------
# 觸發常數 -- 與 vuln_parser 的常數刻意對齊，讓兩套策略可以互相對照
# ---------------------------------------------------------------------------

#: 觸發真實空指標存取所需的最小連續 'A' 長度。
AV_TRIGGER_RUN_LEN = 16

#: 區段巢狀深度上限。**缺陷：這個常數宣告了卻從未被檢查**。
NEST_LIMIT = 200

#: port 欄位的截斷遮罩。缺陷：截斷後的值直接被當成除數。
#:
#: 8 位元而不是 16 位元，因為觸發條件必須**可達**：16 位元時只有 0 會被截成
#: 0，而 0 會先撞 NotPositive；8 位元時 port=256 就能截成 0，而 256 既過得了
#: 範圍檢查也過得了正數檢查。這正是真實世界裡「port 存進 8 位元欄位」的經典
#: 截斷缺陷 —— 而一個不可達的缺陷只是死程式碼。
DIV_ZERO_MASK = 0xFF

#: 內部 interning 快取的魔術種子值。
XOR_KEY_SEED = 0x5A

#: 邏輯異常的信封上界：超出即視為「值溢出預期欄位寬度」。
LOGIC_ENVELOPE = 32767

#: 快取容量。缺陷：快取從未配置，容量檢查卻假設它早就存在。
CACHE_CAPACITY = 64

#: 每一層巢狀實際消耗的堆疊幀數（見 `_recurse_nesting`）。
NEST_COST = 8

# ---------------------------------------------------------------------------
# 缺陷 1：未初始化的 interning 快取（真實空指標寫入）
# ---------------------------------------------------------------------------
# 這個快取在正常路徑上永遠不會被配置。查表程式碼卻假設「既然 token 這麼長，
# 快取一定早就建好了」，直接寫入。任何足夠長的連續 'A' 都會命中此假設。
#
# ⚠ 這個缺陷**不會產生崩潰家族**，必須先說清楚，否則整個基準測試會在這裡
# 說謊。CPython 在 Windows 上安裝了自己的結構化例外處理器，會把存取違例轉成
# 可被 `except OSError` 接住的例外（實測：`ctypes.memset(0,...)` 一律拋
# OSError，退出碼 1）。因此 Python 目標只能覆蓋 ok / logic_error / hang 三種
# 失敗型態，**無法**覆蓋 CRASH_* 家族。
#
# 曾考慮用 `ntdll.RtlExitUserProcess(0xC0000005)` 取得那個退出碼 —— 它真的
# 能給出 NTSTATUS。但那是程序**自己要求**用該狀態碼結束，不是作業系統親自
# 回報的故障；把它記進知識庫就是偽造觀測。所以這裡保留真實的缺陷，並誠實
# 接受它被直譯器遮蔽後的結果。
#
# 崩潰家族的覆蓋由原生標的 vuln_parser 負責（見 P1）。
_intern_cache = None


def _maybe_intern(token: str) -> None:
    """把 token 送進 interning 快取。

    BUG：容量檢查只看 token 長度，從不確認快取真的被配置過。
    """
    if len(token) < AV_TRIGGER_RUN_LEN:
        return
    run = 0
    for ch in token:
        if ch == "A":
            run += 1
            if run >= AV_TRIGGER_RUN_LEN:
                if _intern_cache is None or len(_intern_cache) < CACHE_CAPACITY:
                    # 寫入一個從未配置的表格 -- 真實的 ACCESS VIOLATION。
                    ctypes.memset(0, XOR_KEY_SEED, 1)
                return
        else:
            run = 0


# ---------------------------------------------------------------------------
# 缺陷 2：續行跳脫序列在 EOF 前回傳 0（真實無窮迴圈）
# ---------------------------------------------------------------------------


def _continuation_advance(line: str) -> int:
    """回傳此行消耗的邏輯行數（1 或 2，續行會合併下一行）。

    BUG：行尾是孤立反斜線時回傳 0，呼叫端便永遠停在同一個位置。
    """
    stripped = line.rstrip("\r\n")
    if stripped.endswith("\\"):
        return 0
    return 1


# ---------------------------------------------------------------------------
# 缺陷 3：16 位元截斷後的值被當成除數（真實 ZeroDivisionError）
# ---------------------------------------------------------------------------


def _scale_port(raw_port: int, workers: int) -> int:
    """依 worker 數把 port 做正規化。

    BUG：截斷後的值在數學上可能恆為 0（raw_port 是 65536 的倍數），
    卻沒有被檢查就被拿來當除數。
    """
    truncated = raw_port & DIV_ZERO_MASK
    return (raw_port * workers) // truncated


# ---------------------------------------------------------------------------
# 語意驗證規則 -- 這正是 P3 要的「語意驗證需求」
# ---------------------------------------------------------------------------

#: 各欄位的型別轉換器。
_COERCERS = {
    "port": int,
    "workers": int,
    "timeout_ms": int,
    "retries": int,
    "tls": bool,
    "cert": str,
    "bind_addr": str,
    "bind_iface": str,
}

#: 不允許同時出現的欄位組。
MUTEX_PAIRS = (("bind_addr", "bind_iface"),)

#: 需要正整數的欄位。
POSITIVE = ("port", "workers", "timeout_ms")

#: 未知區段一律拒絕 —— 靜默接受會讓打錯的區段名悄悄失效。
KNOWN_SECTIONS = ("server", "client", "logging", "tls")


class ConfigError(Exception):
    """語意或語法驗證失敗。訊息會成為簽章的一部分，因此措辭必須穩定。"""


def _coerce(key: str, raw: str):
    """把字串值轉成欄位型別。

    BUG：`int(x, 0)` 會接受 0x / 0o / 0b 前綴，於是十六進位的 port 值
    能繞過後續的範圍檢查語意（呼叫端以為自己拿到的是十進位）。
    """
    kind = _COERCERS.get(key)
    if kind is None:
        return raw
    if kind is bool:
        low = raw.strip().lower()
        if low in ("true", "yes", "on", "1"):
            return True
        if low in ("false", "no", "off", "0"):
            return False
        raise ConfigError("TypeMismatch key=%s value=%r expected=boolean" % (key, raw))
    if kind is int:
        try:
            return int(raw.strip(), 0)
        except ValueError:
            raise ConfigError("TypeMismatch key=%s value=%r expected=integer"
                              % (key, raw))
    return raw


def parse_config(text: str) -> dict:
    """解析設定檔並回傳 {section: {key: value}}。

    回傳前會跑完整套語意驗證。任何一項失敗都拋 ConfigError。
    """
    sections: dict[str, dict[str, object]] = {}
    current: dict[str, object] | None = None
    current_name = ""
    lines = text.splitlines(keepends=True)
    i = 0

    while i < len(lines):
        line = lines[i]
        advance = _continuation_advance(line)
        if advance == 0:
            # 缺陷 2：游標不推進，這個 while 迴圈永不結束。
            continue
        i += advance

        body = line.strip()
        if not body or body.startswith(("#", ";")):
            continue

        if body.startswith("[") and body.endswith("]"):
            name = body[1:-1].strip()
            if not name:
                raise ConfigError("EmptySectionHeader")
            if name.count("[") != name.count("]"):
                raise ConfigError("UnbalancedSectionHeader name=%r" % name)
            # 區段標頭是一條**路徑**：`[server][tls]` 指向 server 底下的 tls。
            # 先解析路徑（下面的遞迴），再逐段驗證名稱 —— 順序不能反，否則
            # 任何深層路徑都會先撞 UnknownSection，缺陷 3 就永遠不可達。
            _check_nesting(name)
            for part in name.split("]["):
                if part not in KNOWN_SECTIONS:
                    raise ConfigError("UnknownSection name=%r" % part)
            current_name = name
            current = sections.setdefault(name, {})
            continue

        if "=" not in body:
            raise ConfigError("MalformedLine %r" % body)

        key, _, raw_value = body.partition("=")
        key = key.strip()
        if current is None:
            raise ConfigError("KeyOutsideSection key=%r" % key)
        if key in current:
            raise ConfigError("DuplicateKey section=%s key=%s" % (current_name, key))

        # 先 intern **原文**，再做型別轉換 —— 順序很重要。
        # 反過來的話 `port = 1AAAAAAAAAAAAAAAA` 會先撞 TypeMismatch，
        # 於是缺陷 1 永遠不可達；token 化本來就該發生在值解析之前。
        _maybe_intern(key)
        _maybe_intern(raw_value)

        value = _coerce(key, raw_value.strip())

        # 缺陷：範圍檢查用 `>` 而非 `>=`，於是 port=0 被放行。
        if key in POSITIVE and isinstance(value, int) and value > LOGIC_ENVELOPE:
            raise ConfigError("OutOfRange key=%s value=%d envelope=%d"
                              % (key, value, LOGIC_ENVELOPE))

        current[key] = value

    _validate(sections)
    return sections


def _check_nesting(name: str) -> None:
    """解析區段路徑的巢狀深度。

    BUG：NEST_LIMIT 從未被使用。`[a][b][c]...` 這樣的深層路徑會讓下面的
    遞迴一路展開到 Python 的堆疊上限，拋出 RecursionError。
    """
    depth = name.count("][") + 1
    return _recurse_nesting(depth * NEST_COST)


def _recurse_nesting(depth: int) -> int:
    """每個巢狀層實際消耗的堆疊幀數。

    每層不止一幀是刻意的：真實的設定檔解析器在每一層會做查表、正規化、
    預設值填補等多個步驟。這裡讓每一層消耗 NEST_COST 個幀，於是約 130
    層的巢狀就能壓垮 Python 的預設堆疊 —— 換算成輸入大小約 500 位元組，
    這才是模糊測試實際會撞到的量級。
    """
    if depth <= 0:
        return 0
    # 每層留下一個不小的暫存，讓堆疊壓力與原生標的的 DeepFrameSize 同量級。
    scratch = "x" * 256
    return (len(scratch) + _recurse_nesting(depth - 1)) % 1024


def _validate(sections: dict) -> None:
    """跨欄位語意驗證。

    這裡是 P3 的重點：Hypothesis 產生的結構化輸入必須能命中這些規則之間
    的縫隙，而不是只把檔案弄成垃圾位元組。
    """
    for section_name, kv in sections.items():
        tls = kv.get("tls")

        # 規則：TLS 啟用時必須提供憑證。
        # 缺陷：只檢查 key 存在，不檢查值非空 —— `cert =` 會被放行。
        if tls is True and "cert" not in kv:
            raise ConfigError("MissingRequired section=%s key=cert reason=tls_enabled"
                              % section_name)

        # 規則：port 與 workers 必須為正數。
        # 缺陷：上面的範圍檢查用了 `>`，所以 0 一路走到這裡。
        for key in POSITIVE:
            if key in kv and isinstance(kv[key], int) and kv[key] <= 0:
                raise ConfigError("NotPositive section=%s key=%s value=%r"
                                  % (section_name, key, kv[key]))

        # 規則：互斥欄位不可同時出現。
        # 缺陷：只檢查兩個都非空，於是 `bind_iface =`（空值）能繞過。
        for a, b in MUTEX_PAIRS:
            va, vb = kv.get(a), kv.get(b)
            if va and vb:
                raise ConfigError("MutuallyExclusive section=%s keys=%s,%s"
                                  % (section_name, a, b))

        # 規則：port 與 workers 的組合必須能被安全正規化。
        if section_name == "server" and "port" in kv:
            port = kv["port"]
            if isinstance(port, int):
                workers = kv.get("workers", 1)
                if not isinstance(workers, int):
                    workers = 1
                try:
                    _scale_port(port, max(1, workers))
                except ZeroDivisionError:
                    raise ConfigError("ScaledPortCollapse port=%d workers=%d"
                                      % (port, workers))
                except Exception as exc:                               # noqa: BLE001
                    raise ConfigError("ScaledPortFailure port=%d reason=%r"
                                      % (port, exc))


def main(argv: list) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: cfgparser <input-file>\n")
        return 2
    path = argv[1]
    if not os.path.exists(path):
        sys.stderr.write("input not found: %s\n" % path)
        return 2

    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        sys.stderr.write("ANOMALY OSError: %s\n" % exc)
        return 1

    try:
        # surrogateescape：變異輸入富含高位元組與 NUL，直接 decode 會拋
        # UnicodeDecodeError，那會把一個**解析缺陷**偽裝成**編碼缺陷**。
        text = raw.decode("utf-8", "surrogateescape")
    except Exception as exc:                                           # noqa: BLE001
        sys.stderr.write("ANOMALY UnicodeError: %r\n" % exc)
        return 1

    try:
        sections = parse_config(text)
    except RecursionError:
        # 缺陷 1 的另一面：巢狀深度沒有上限，Python 先於作業系統回報。
        sys.stderr.write("ANOMALY RecursionError: section nesting exceeded\n")
        return 1
    except ConfigError as exc:
        sys.stderr.write("ANOMALY ConfigError: %s\n" % exc)
        return 1
    except Exception as exc:                                           # noqa: BLE001
        sys.stderr.write("ANOMALY %s: %s\n" % (type(exc).__name__, exc))
        return 1

    total = sum(len(kv) for kv in sections.values())
    sys.stdout.write("OK sections=%d keys=%d bytes=%d\n"
                     % (len(sections), total, len(raw)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
