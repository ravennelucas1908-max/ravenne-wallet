@echo off
chcp 65001 >nul
title Ravenne Wallet
cd /d "%~dp0"
if exist dist\ravenne.exe (dist\ravenne.exe) else (node ravenne.js)
