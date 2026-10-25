# BUG GENESIS

繁體中文 | [English](README.en.md)

BUG GENESIS 是一個以失敗回饋調整變異策略的本機模糊測試（fuzzing）研究工具。它從測試種子產生輸入、啟動指定的本機目標程式、分類可重現的失敗、縮減反例，並把案例與統計存進 SQLite。專案附有刻意含有缺陷的 JSON 與設定檔解析器，供本機測試引擎本身使用。

它不是覆蓋率導向的 fuzzer：目前不蒐集程式碼 coverage，而是根據成功、失敗、新缺陷族群與環境雜訊回饋策略權重。

## 安全用途與雙重用途聲明

本工具的設計用途是**防禦性的軟體測試、品質保證、資安研究與教育**。請只對自己擁有、受委託或已取得明確書面授權的程式執行測試，並在隔離、可復原的測試環境中使用。未經授權測試可能違反法律、合約或服務條款；使用者須自行確認適用規範與取得授權。

引擎會反覆啟動本機目標、提供變異輸入，並可能終止逾時的子程序。附帶的 `vuln_parser` 與 `cfgparser.py` 是**故意有缺陷的測試標的**，不是可用於正式環境的解析器。不要以未知或生產環境程式作為目標；先用低執行次數、短逾時與獨立資料庫驗證設定。引擎不是網路掃描器，也不提供遠端目標發現功能；外部目標程式自身的行為不受本專案控制。

軟體與範例按「現況」提供，不保證適用性、不中斷或測試結果完整；在法律允許範圍內，作者不承擔因使用或誤用造成的損害或法律責任。這段聲明不會授予測試他人系統的權限，也不能取代適用法律、合約或正式授權條款。

**授權狀態：** `bug_genesis.nimble` 的套件 metadata 標示 MIT，但目前根目錄沒有 `LICENSE` 檔。README 的免責文字不是開源授權；在發布或再散布前，請確認權利人與授權內容並補上正式授權檔。第三方套件亦各自受其授權條款約束。

## 功能概覽

- 原生變異策略：位元翻轉、位元組覆寫、邊界值、結構破壞、重複位元組、巢狀成長、區塊複製、token 插入。
- 可選的 Python/Hypothesis 產生器：支援 JSON、INI 與 raw 輸入方言；方言可明確指定，或由種子內容剖析。
- 失敗導向回饋：對新族群提高相應策略權重，對無效或無新結果的策略降權但保留探索機會。
- 失敗重現閘門：重播觀測並比對簽章，避免把偶發環境逾時直接當成已確認缺陷。
- 缺陷族群去重、最小反例縮減、故障位置（tainted offset）追蹤與後續偏向變異。
- SQLite 保存測試案例原始位元組、族群、重現輸入、策略統計與執行紀錄。
- 瀏覽器唯讀控制台：以 3D 圖、時間軸與明細瀏覽知識庫；可下載反例，但不會在瀏覽器執行目標。
- 內附可重現性、格式剖析、橋接計時、資料庫往返與程序清理等檢查工具。

橋接器依方言選擇產生器：JSON 使用 `hypothesis_nested_json`、`hypothesis_extreme_num`、`hypothesis_string_run`、`hypothesis_malformed`；INI 使用 `hypothesis_cfg_semantic`、`hypothesis_cfg_nesting`、`hypothesis_cfg_port`、`hypothesis_cfg_continuation`、`hypothesis_cfg_token`；raw 使用 `raw_bytes`、`raw_text`、`raw_magic`。

## 環境需求

- Windows：下列操作範例以 PowerShell 為主；引擎使用 Nim 與 Nimble。
- Nim 2.0 或更新版本，以及 Nimble；SQLite driver 依賴由 `bug_genesis.nimble` 宣告為 `db_connector`。
- Python（建議 Python 3.9+）用於 Python 目標及橋接器。Hypothesis 是可選功能；啟用時需安裝：`python -m pip install hypothesis`。
- Node.js/npm 僅在需要執行網頁控制台時使用。

## 建置與執行

在專案根目錄開啟 PowerShell：

```powershell
nimble buildAll
```

這會建立 `build\genesis_core.exe` 與刻意有缺陷的 `build\vuln_parser.exe`。以預設 JSON 解析器進行短測試時，建議使用獨立資料庫，避免覆寫根目錄既有的 `bugs.db`：

```powershell
.\build\genesis_core.exe --target=.\build\vuln_parser.exe --seed-dir=.\seeds --iters=500 --workers=2 --timeout=150 --seed=42 --db=.\build\demo.db
```

程式在執行預算用完後結束。`--seed` 使用非零值可重現引擎的隨機選擇序列；目標程式、作業系統排程等外部因素仍可能使結果不同。測試 Python 設定檔標的時，需明確指定 `--target-kind=interpreted`（預設是 `executable`）：

```powershell
python -m pip install hypothesis
.\build\genesis_core.exe --target=.\targets\cfgparser.py --target-kind=interpreted --dialect=ini --seed-dir=.\seeds_cfg --python=python --iters=500 --workers=2 --timeout=300 --seed=42 --db=.\build\cfg-demo.db
```

不想使用 Hypothesis 時加上 `--no-hypothesis`；此時引擎只抽取原生變異策略。`--target-args` 以空白拆分參數，不解析 shell 引號；若指定 `{input}`，輸入檔路徑會放在該位置，否則附加在參數末尾。

### CLI 選項

| 選項 | 預設值／用途 |
|---|---|
| `--help` | 顯示說明。 |
| `--target=PATH` | 目標程式路徑；未指定時尋找與引擎執行檔同目錄的 `vuln_parser`。 |
| `--target-kind=KIND` | `executable` 或 `interpreted`；預設 `executable`。Python 腳本需明確指定 `interpreted`。 |
| `--dialect=NAME` | `json`、`ini` 或 `raw`；未指定時依種子內容剖析。 |
| `--target-args=ARGS` | 目標程式額外參數；支援 `{input}` 佔位符。 |
| `--seed-dir=PATH` | 種子資料夾；預設 `.\seeds`。只讀取該資料夾的直接檔案，大小須為 1–4096 bytes。 |
| `--db=PATH` | SQLite 知識庫；預設 `bugs.db`。 |
| `--iters=N` | 執行案例數；預設 5000。 |
| `--timeout=MS` | 每次目標執行的逾時；預設 150 ms，低於 10 ms 會調整為 10 ms。 |
| `--workers=N` | 工作者數；預設最多 16 個或 CPU 數。使用 Hypothesis 時上限為 6。 |
| `--seed=N` | 引擎 RNG 種子；未提供或為 0 時採用時間值。 |
| `--report-every=N` | 進度輸出間隔；預設 1000。 |
| `--max-reduce=N` | 每個新族群反例縮減最多執行次數；預設 400。 |
| `--no-reduce` | 不進行反例縮減。 |
| `--python=PATH` | Python 直譯器；預設 `python`，供橋接器及 Python 目標使用。 |
| `--python-bridge=PATH` | Hypothesis 橋接器路徑；預設 `adapters\python\bridge.py`。 |
| `--no-hypothesis` | 停用 Python/Hypothesis 產生器，只使用原生策略。 |
| `--quiet` | 隱藏逐筆失敗輸出，不停用資料庫記錄。 |

## 所有 `.exe` 的用途與操作

目前 `build\` 中有以下六個可執行檔。這些檔案是建置產物；若下載的版本沒有它們，先執行 `nimble buildAll` 建立引擎與 JSON 標的，再依下表用 Nim 編譯四個檢查程式。

| 執行檔 | 功能 | 操作方式 |
|---|---|---|
| `genesis_core.exe` | 主模糊測試引擎：產生/變異案例、執行目標、分類與確認失敗、縮減反例、寫入 SQLite。 | `.\build\genesis_core.exe --help` 查看選項；依「建置與執行」章節啟動。 |
| `vuln_parser.exe` | 刻意有缺陷的 JSON 解析器測試目標，不是引擎。輸入是檔案路徑。 | `.\build\vuln_parser.exe .\seeds\01_object.json`。單獨使用時只會回報該輸入的解析結果。 |
| `noise_check.exe` | 驗證重現閘門只承認相同簽章，並檢查環境雜訊會降低策略權重而不被計為確認失敗。 | `.\build\noise_check.exe`；依賴 `build\vuln_parser.exe`。重建/執行：`nim c -r --hints:off targets\noise_check.nim`。 |
| `profile_check.exe` | 驗證種子格式剖析、magic bytes、JSON/INI/raw 方言選擇及混合種子的降級處理。 | `.\build\profile_check.exe`；重建/執行：`nim c -r --hints:off targets\profile_check.nim`。 |
| `reaper_check.exe` | Windows 專用程序回收檢查：確認只清除命令列指向測試暫存目錄的程序，且不會回收引擎自身。非 Windows 平台會略過 Job Object 檢查。 | `.\build\reaper_check.exe`；會建立並清理測試程序。重建/執行：`nim c -r --hints:off targets\reaper_check.nim`。 |
| `taint_check.exe` | 驗證故障輸出中的 byte offset 擷取、感染點清理及偏向該位置的變異取樣。 | `.\build\taint_check.exe`；重建/執行：`nim c -r --hints:off targets\taint_check.nim`。 |

四個 `*_check.exe` 是本機驗證程式，不接受 CLI 選項，也不會替代主引擎。避免在不了解來源的環境中執行任意二進位檔。

## 專案檔案導覽

以下說明專案自有的原始碼、資料與工具。`build\`、`console\node_modules\`、`console\dist\`、`__pycache__\` 與 `.hypothesis\` 是建置、套件或執行時產物，不是專案原始碼。

### 根目錄與建置

| 路徑 | 用途 |
|---|---|
| `bug_genesis.nimble` | Nimble 套件中繼資料與任務：`buildTarget`、`buildEngine`、`buildAll`、`testAll`。`testAll` 會建置後執行 1500 次、4 個工作者的 campaign，且使用預設資料庫路徑。 |
| `config.nims` | Nim 編譯共用設定：ORC 記憶體管理、多執行緒、最佳化、`src` 搜尋路徑及 `build` 輸出目錄。 |
| `launch_console.bat` | Windows 控制台啟動器：切換到 `console`、開啟 `http://localhost:5178`，並執行 Vite 開發伺服器。 |
| `bugs.db` | 引擎預設 SQLite 知識庫；可能包含既有測試輸入與結果。新測試建議使用新的 `--db` 路徑。 |
| `p3_*.db` | 多個既有 Phase 3 實驗/活動資料庫快照（包括 `p3_bench.db`、`p3_bin.db`、`p3_bin_hp.db`、`p3_cfg.db`、`p3_final.db`、`p3_g1.db`、`p3_g2.db`、`p3_g3.db`、`p3_native.db`、`p3_orphan.db`、`p3_reap.db`、`p3_t2.db`–`p3_t12.db`、`p3_trace.db`、`p3_w.db`）。檔名本身不足以完整說明各次實驗設定；可透過控制台或 SQLite `run_log` 檢視資料。 |
| `bench.log`、`campaign.log`、`p3_cfg.log` | 既有測試/活動文字輸出，不是引擎設定或執行所需的原始碼。 |
| `p3_orphan.db-wal`、`p3_orphan.db-shm` | SQLite WAL/共享記憶體旁檔。活動中途終止時，主 `.db` 可能尚未包含 WAL 中的最新資料；不要只複製正在使用中的主資料庫檔。 |

### 引擎與測試目標

| 路徑 | 功能 |
|---|---|
| `src\genesis_core.nim` | CLI、設定解析、種子與目標設定、工作者排程、策略回饋、資料庫寫入及活動摘要的主入口。 |
| `src\engine\mutator.nim` | 原生變異策略、策略抽樣/權重更新、輸入長度上限、感染點導向取樣。 |
| `src\engine\executor.nim` | 啟動/終止目標、逾時確認、輸出正規化與簽章、重播，以及原生/Python 目標適配器生命週期。 |
| `src\engine\classifier.nim` | 失敗簽章分類、重現閘門、輸出中 offset 擷取、delta debugging 反例縮減。 |
| `src\engine\profile.nim` | 依 magic bytes 與文字結構剖析種子格式，決定 Hypothesis 方言；混合格式保守地使用 raw。 |
| `src\engine\reaper.nim` | Windows Job Object 子程序生命週期管理及啟動時的孤兒程序清理；非 Windows 不提供 Job Object 即時回收。 |
| `src\storage\db.nim` | SQLite schema、案例/族群/重現輸入/策略統計/執行記錄/雜訊/感染點的讀寫與摘要報表。 |
| `src\target\vuln_parser.nim` | 編譯成 `vuln_parser.exe` 的故意脆弱 JSON 解析器基準標的。僅限本機受控測試。 |

### Python 橋接與協定

| 路徑 | 功能 |
|---|---|
| `adapters\python\bridge.py` | 常駐 Python 子程序：透過 JSON Lines 接受產生/執行請求，使用 Hypothesis 產生輸入並執行 Python 或二進位目標。`--serve` 是引擎使用的會話模式；`--generate` 是內部產生器介面，不是一般互動 CLI。 |
| `docs\adapter-protocol.md` | 橋接協定 v1：訊息格式、輸入/輸出、狀態、逾時、簽章、適配器錯誤與程序管理契約。 |

### Python 測試標的與檢查工具

| 路徑 | 功能 |
|---|---|
| `targets\cfgparser.py` | 第二個故意有缺陷的測試目標：解析並驗證 INI 風格設定。可透過 `--target-kind=interpreted` 指定給引擎。 |
| `targets\flaky_env.py` | 非決定性環境雜訊負向測試標的，用來檢查偶發錯誤是否被錯誤記為穩定缺陷。 |
| `targets\check_cfgparser.py` | 逐項確認 `cfgparser.py` 的預期輸入路徑可觸達，並檢查觀測到的狀態/訊息。 |
| `targets\check_bridge_timing.py` | 比較直接執行與經橋接器執行的相同測試，檢查橋接器是否造成額外逾時。 |
| `targets\check_hang_backslash.py` | 統計資料庫中被記為 hang 的案例是否符合標的的結尾反斜線特徵；可傳入資料庫路徑，預設讀取 `p3_cfg.db`。 |
| `targets\check_hang_reduce.py` | 從資料庫取出 hang 案例，以不同預算重播並檢查縮減探測是否能保留相同結果。 |
| `targets\check_hang_replay.py` | 重播資料庫中已存的 hang 案例並統計重現狀況；會執行測試標的。 |
| `targets\check_odd_hangs.py` | 以較長預算多次重播非典型 hang，區分穩定掛死與慢速/偶發執行。 |
| `targets\check_kb_roundtrip.py` | 檢查知識庫 byte BLOB、重現輸入與簽章資料是否可往返，並可重播確認族群；請以 `python targets\check_kb_roundtrip.py --help` 查看其參數。 |
| `targets\measure_load_timeout.py` | 在並行負載下重播設定種子，量測執行時間分布與逾時誤判風險。 |
| `targets\measure_signature_granularity.py` | 對資料庫中簽章套用候選正規化規則並比較族群合併數；是量測工具，不會替資料庫改寫簽章。 |
| `targets\noise_check.nim` | `noise_check.exe` 的測試原始碼。 |
| `targets\profile_check.nim` | `profile_check.exe` 的測試原始碼。 |
| `targets\reaper_check.nim` | `reaper_check.exe` 的測試原始碼。 |
| `targets\taint_check.nim` | `taint_check.exe` 的測試原始碼。 |

檢查腳本中部分會執行目標或讀取資料庫；執行前請確認輸入資料庫與目標路徑，必要時先複製資料庫。根目錄所附 `p3_*.db` 是可供分析的實驗快照，不代表建議用它們覆寫新的活動結果。

### 種子資料

- `seeds\01_object.json`–`15_config.json`：15 個 JSON/文字種子，提供不同 JSON 結構與測試輸入起點。
- `seeds_cfg\boundary_port.cfg`、`full.cfg`、`minimal.cfg`、`nested.cfg`：INI 風格設定檔種子。
- `seeds_bin\archive.tar`、`blob.bin`、`header.zip`、`notes.txt`、`real.tar`、`sample.gz`：二進位/文字格式剖析與 raw 產生器的樣本。

引擎只讀取指定種子目錄中的直接檔案，不遞迴掃描子目錄；大於 4096 bytes 或空檔不會載入。

### 知識庫控制台

| 路徑 | 功能 |
|---|---|
| `console\index.html` | 控制台 HTML 外殼：知識庫選擇、時間滑桿、重播控制、畫布與資訊區。 |
| `console\src\main.ts` | 載入資料庫、摘要/時間軸/族群明細、反例下載與發現過程重播。 |
| `console\src\kb.ts` | 使用 sql.js/WASM 在瀏覽器唯讀解析 SQLite 表格，整理族群、案例、策略與執行資料。 |
| `console\src\graph.ts` | 使用 Three.js 顯示族群 3D 圖；座標代表發現時間、缺陷類別與主要策略。 |
| `console\src\style.css` | 控制台樣式。 |
| `console\package.json`、`console\package-lock.json` | npm scripts 與鎖定的前端依賴版本。 |
| `console\tsconfig.json`、`console\vite.config.ts` | TypeScript 與 Vite 設定；開發伺服器使用 `localhost:5178`，允許讀取上一層資料夾。 |
| `console\public\sql-wasm.wasm` | sql.js 執行 SQLite 查詢所需的 WebAssembly 模組。 |
| `console\public\kb.db` | 可自行放入的本機資料庫快照（不納入 Git）；存在時控制台會自動載入，不會因引擎產生新資料而自動更新。 |
| `console\README.md` | 控制台的獨立說明與已知限制。 |

啟動控制台：

```powershell
cd console
npm install
npm run dev
```

開啟 `http://localhost:5178`。也可在專案根目錄執行 `.\launch_console.bat`（需先安裝 npm 依賴）。為避免發佈本機測試資料，Git 不追蹤資料庫檔案；若 `console\public\kb.db` 存在，控制台會自動讀取，否則用左上角「開啟 .db」選取資料庫。若要建立或更新本機預載快照，請等 campaign 正常結束後，再從專案根目錄複製：

```powershell
Copy-Item .\build\demo.db .\console\public\kb.db -Force
```

控制台只讀資料，不會觸發/停止 campaign，也不會在瀏覽器執行反例。資料庫仍在使用或留下 WAL/SHM 時，不要只複製主 `.db` 檔；請待正常結束後再更新快照。

## 資料與限制

- `test_cases.content` 與族群 `repro` 保存原始 bytes；資料庫可能含有測試輸入，分享前請先檢查。
- 反例縮減需花額外目標執行次數；`--max-reduce` 設有單族群預算，`--no-reduce` 可停用。
- timeout 先重試確認；環境負載仍會影響執行時間。跨作業系統的崩潰碼分類能力不同，POSIX 訊號無法總是區分不同硬體故障。
- 引擎將目標輸出擷取限制在 4096 bytes；大量輸出目標可能因 pipe 緩衝而被判為逾時。
- Windows 使用 Job Object 管理子程序；其他平台不具備相同的即時孤兒程序回收機制。
- 前端最多讀取 200,000 筆案例與 500 筆執行紀錄；時間軸與策略圖是對既有資料的視覺呈現，不是即時監控。

## 驗證與前端建置

```powershell
nimble buildAll
python targets\check_cfgparser.py
python targets\check_bridge_timing.py
cd console
npm run build
```

`nimble testAll` 會執行一個 1500 次的短 campaign，且使用預設 `bugs.db`；如需避免改動既有資料庫，請改用前述明確指定 `--db` 的引擎指令。
