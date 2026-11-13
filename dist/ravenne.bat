@echo off
chcp 65001 >nul
title Ravenne Wallet
if exist "%~dp0ravenne.exe" ("%~dp0ravenne.exe" %*) else node "%~dp0ravenne.cjs" %*
