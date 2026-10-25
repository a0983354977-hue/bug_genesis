version       = "0.1.0"
author        = "BUG GENESIS"
description   = "Failure-directed evolutionary fuzzing engine (Phase 1)"
license       = "MIT"
srcDir        = "src"
binDir        = "build"
bin           = @["genesis_core"]

# db_sqlite 自 Nim 2.0 起從標準庫移出，獨立為 db_connector 套件。
requires "nim >= 2.0.0"
requires "db_connector >= 0.1.0"

# 目標程式必須關閉 Nim 的訊號處理器，否則 SIGSEGV 會被攔截成 exit 1，
# 執行器就只能看到假的「邏輯錯誤」而非真實的作業系統崩潰碼。
task buildTarget, "Build the deliberately vulnerable JSON parser target":
  mkDir "build"
  when defined(windows):
    const exe = ".exe"
  else:
    const exe = ""
  exec "nim c -d:release -d:noSignalHandler --mm:orc --hints:off " &
       "-o:build/vuln_parser" & exe & " src/target/vuln_parser.nim"

task buildEngine, "Build the fuzzing engine":
  mkDir "build"
  when defined(windows):
    const exe = ".exe"
  else:
    const exe = ""
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
       "-o:build/genesis_core" & exe & " src/genesis_core.nim"

task buildAll, "Build engine and target":
  buildTargetTask()
  buildEngineTask()

task testAll, "Build everything then run a short campaign":
  buildAllTask()
  exec "./build/genesis_core --iters=1500 --workers=4"
