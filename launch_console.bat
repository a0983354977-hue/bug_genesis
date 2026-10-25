@echo off
chcp 65001 >nul
title BUG GENESIS - 3D Knowledge Console

echo [!] 正在啟動 BUG GENESIS 視覺化控制台...
cd /d "%~dp0console"

start "" /min cmd /c "timeout /t 2 >nul & start http://localhost:5178"

npm run dev
