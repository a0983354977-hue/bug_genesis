# 全域編譯旗標：引擎與目標共用。
#
# ORC：確定性引用計數，讓多執行緒 + 通道傳遞 seq/string 不受 GC 暫停影響，
#      對每秒數千次的程序啟停至關重要。
# threads: 執行器池需要。
# opt:speed：引擎加速；目標程式的崩潰行為由其自身檔案的檢查開關控制。

--mm:orc
--threads:on
--opt:speed
--panics:off

--outdir:"build"
--path:"src"

when defined(release):
  --stacktrace:off
  --linetrace:off
