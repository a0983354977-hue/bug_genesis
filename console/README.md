# BUG GENESIS — 知識庫控制台

唯讀的 3D 視覺化，直接讀引擎的 SQLite 知識庫。沒有後端、沒有 API、沒有寫入。

## 為什麼是唯讀

P4 的選項之一是「本地 API server」，這裡刻意沒做：sql.js（WASM 版 SQLite）可以在
瀏覽器裡直接載入一個 `.db` 位元組組，於是「查詢層」就是一次 fetch。多一個常駐行程
就多一個要維護、要排錯、要確保不寫壞知識庫的元件，而唯讀視覺化根本不需要它。

## 啟動

```bash
cd console
npm install
cp node_modules/sql.js/dist/sql-wasm.wasm public/   # sql.js 用純 fetch 載入，不經打包器
cp ../p3_g2.db public/kb.db                          # 任一 campaign 結束後的知識庫
npm run dev                                          # http://localhost:5178
```

Vite 8 只綁 IPv6，所以要用 `localhost`，`127.0.0.1` 連不上。

沒有放 `public/kb.db` 也能用：按左上角「開啟 .db」挑任意知識庫。

## 座標軸的意義

刻意不做力導向排版——族群之間沒有邊可用，力導向只會變成一團毛球。每個座標都是
資料裡真實的欄位：

| 軸 | 來源 |
|---|---|
| x | `bug_families.first_seen`（發現時間） |
| y | 缺陷類別 `kind_label \| code`（泳道） |
| z | 該族群多數案例所屬的 `strategy` |
| 半徑 | `sqrt(hit_count)`，用面積而非半徑對應命中數 |

「▶ 重播發現過程」依 `first_seen` 依序揭示節點。

## 這套控制台**不能**做什麼

誠實列出，因為 P4 的驗收標準裡有幾條不在「唯讀」的範圍內：

- **不能觸發或停止 campaign。** 需要常駐 server 與 WebSocket，那是另一個範圍。
- **不能即時監控 exec/s。** `run_log` 只有每輪的 `execs` 總數，沒有時間序列，
  所以面板顯示的是「平均 exec/run」，不是即時速率。要即時曲線得先在引擎端取樣。
- **不能在瀏覽器裡執行反例。** 只能下載 `repro.bin`，面板會依 `run_log.target`
  給出對應的重放指令。
- **策略權重演化歷史沒有資料。** `strategy_stats` 只在 campaign 正常結束時寫入
  最終累積值，被 `timeout` 砍掉的輪次是空表。前端顯示的是策略產出率，不是權重曲線。

## 已知限制

- **WAL：** campaign 被強制中斷時會留下 `*.db-wal` / `*.db-shm`。sql.js 讀不到未
  checkpoint 的資料，看起來會比實際少。等 campaign 正常結束再讀。
- **`nest_grow` 之類的策略**在某些資料集上會產生大量近似族群；簽章正規化
  （`executor.normalizeOutput`）已把引號迴印的輸入抽象成 `#`，族群數才有可讀性。

## 型別檢查與建置

```bash
npx tsc --noEmit   # 型別錯誤會使 process 以非零碼結束
npx vite build     # 產出 dist/（~620 KB，主要是 three.js）
```