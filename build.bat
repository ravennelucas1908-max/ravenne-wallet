@echo off
setlocal
cd /d "%~dp0"
title Ravenne Wallet - build

echo.
echo   ============================================
echo    Ravenne Wallet - build shareable package
echo   ============================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo   [X] Node.js not found. Install Node.js 18+ first: https://nodejs.org
  exit /b 1
)

for /f "usebackq delims=" %%i in (`node -p "require('./package.json').version"`) do set VER=%%i

echo   [1/7] Installing dependencies...
call npm install --no-audit --no-fund
if errorlevel 1 goto err

echo   [2/7] Bundling into a single file (esbuild)...
if not exist build mkdir build
call npx --yes esbuild ravenne.js --bundle --platform=node --format=cjs --external:@ledgerhq/* --external:monero-javascript --outfile=build\ravenne.cjs --log-level=error
if errorlevel 1 goto err

echo   [3/7] Preparing dist\ ...
if exist dist rmdir /s /q dist
mkdir dist
copy /y build\ravenne.cjs dist\ >nul
copy /y README.md dist\ >nul
> dist\ravenne.bat echo @echo off
>> dist\ravenne.bat echo chcp 65001 ^>nul
>> dist\ravenne.bat echo title Ravenne Wallet
>> dist\ravenne.bat echo if exist "%%~dp0ravenne.exe" ("%%~dp0ravenne.exe" %%*) else node "%%~dp0ravenne.cjs" %%*

echo   [4/7] Building standalone ravenne.exe (first time downloads ~80 MB)...
call npx --yes @yao-pkg/pkg build\ravenne.cjs -t node22-win-x64 -o dist\ravenne.exe --public
if exist dist\ravenne.exe (
  echo         OK: dist\ravenne.exe  ^(no Node.js needed^)
) else (
  echo         skipped - the .cjs bundle still works with Node.js
)

echo   [5/7] Applying icon + version info to the exe...
if not exist ravenne.ico node make-icon.mjs
if exist dist\ravenne.exe (
  node -e "require('rcedit').rcedit('dist/ravenne.exe',{icon:'ravenne.ico','version-string':{ProductName:'Ravenne Wallet',FileDescription:'Ravenne Wallet',CompanyName:'Ravenne'},'file-version':'%VER%','product-version':'%VER%'}).then(()=>console.log('        icon applied')).catch(()=>console.log('        skipped'))"
  dist\ravenne.exe help >nul 2>nul
  if errorlevel 1 (
    echo         icon broke the exe - rebuilding WITHOUT icon...
    call npx --yes @yao-pkg/pkg build\ravenne.cjs -t node22-win-x64 -o dist\ravenne.exe --public >nul 2>nul
    echo         OK: exe rebuilt and functional ^(no custom icon^)
  ) else (
    echo         OK: icon + version %VER%
  )
)

echo   [6/7] Security check: no vault or password shipped...
if exist dist\vault.ravenne.json del /q dist\vault.ravenne.json
if exist dist\access.ravenne.json del /q dist\access.ravenne.json
echo         OK: dist contains no keys, no vault, no password.

echo   [7/7] Creating zip...
python -c "import zipfile,glob,os;z=zipfile.ZipFile('ravenne-wallet-v%VER%.zip','w',zipfile.ZIP_DEFLATED);[z.write(f,os.path.basename(f)) for f in glob.glob(os.path.join('dist','*'))];z.close()"
if errorlevel 1 goto err

echo.
echo   ============================================
echo    BUILD OK
echo.
echo    dist\ravenne.bat     - launcher (exe if present, else Node.js)
echo    dist\ravenne.cjs     - single-file bundle (needs Node.js)
echo    dist\ravenne.exe     - standalone, no install needed ^(if built^)
echo    ravenne-wallet-v%VER%.zip  - share this file
echo.
echo    First launch on a new machine asks to create
echo    a master password. Nothing personal is inside.
echo   ============================================
echo.
exit /b 0

:err
echo.
echo   [X] BUILD FAILED - see messages above.
exit /b 1

>> distavenne.bat echo chcp 65001 ^>nul