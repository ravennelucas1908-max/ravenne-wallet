@echo off
chcp 65001 >nul
title Ravenne Wallet
node "%~dp0ravenne.js" %*
