"""環境雜訊夾具：模組 3 重現閘門的負向對照組。

這個目標的行為刻意與「缺陷」相反：

  * 同一批位元組跑一百次，有時候過、有時候不過 —— 失敗與輸入內容無關。
  * 每次失敗的**訊息模板都不一樣**（記憶體、權限、逾時、工作集），因為現實
    中的環境性故障本來就是這樣：Windows 不會每次都用同一句話描述資源不足。

為什麼模板必須不同：引擎的簽章（executor.normalizeOutput）會把所有數字摺成
`#`、把引號內容摺成 `#`，只保留訊息模板。所以「隨機數字」不足以製造雜訊 ——
只有模板本身的差異才會讓簽章每次都不同，重放於是拿不到同一個簽章。

驗收標準（見 campaign）：
    0 個錯誤族群、noise_log 有列、策略被降權。

    一個把所有偶發故障都當真缺陷的引擎，會在這裡產生大量族群；一個把所有
    東西都當雜訊丟掉的引擎，會在正常目標（targets/cfgparser.py）上也產生
    0 族群 —— 因此這個夾具必須與正向對照一起跑，單看一邊都會誤判。

Usage: python targets/flaky_env.py <input-file>
"""
import sys
import time

MESSAGES = [
    "OSError: [Errno 12] Cannot allocate memory",
    "PermissionError: [Errno 13] process cannot access the file",
    "TimeoutError: [WinError 121] semaphore timeout period expired",
    "MemoryError: failed to grow the working set",
]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: flaky_env <input-file>\n")
        return 2

    # 讀輸入 —— 讓「檔案被鎖定 / 路徑不存在」這類環境問題仍然是可能的觀測，
    # 與真實目標一樣把輸入當回事，而不是無視它。
    try:
        with open(argv[1], "rb") as fh:
            fh.read()
    except OSError as exc:
        sys.stderr.write("ANOMALY EnvironmentError: %s\n" % exc)
        return 1

    tick = time.time_ns() // 1_000_000
    if tick % 2 == 0:
        sys.stdout.write("OK\n")
        return 0

    # 與 pass/fail 的位元分開取樣，避免只輪到一半的訊息。
    sys.stderr.write("ANOMALY " + MESSAGES[(tick // 2) % len(MESSAGES)] + "\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
