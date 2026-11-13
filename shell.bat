@echo off
chcp 65001 >nul
title Ravenne Shell - compiling then GUI
cd /d "%~dp0"
echo Starting Ravenne Shell (first build takes a few minutes)...
call npx tauri dev
