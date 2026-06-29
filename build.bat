@echo off
setlocal enabledelayedexpansion
title KeyBase Builder - Build

echo.
echo  ==========================================
echo   KeyBase Builder ^|  Build All Targets
echo  ==========================================
echo.

if not exist "%~dp0dist" mkdir "%~dp0dist"

echo  [1/2] Windows (GUI, native)...
pushd "%~dp0Builder"
cargo build --release
if errorlevel 1 (
    echo  [FAILED] Windows build.
    popd
    goto :fail
)
popd
copy /y "%~dp0Builder\target\release\keybase-builder.exe" "%~dp0dist\keybase-builder-windows.exe" >nul
echo  [OK]  dist\keybase-builder-windows.exe
echo.

echo  [2/2] Linux (TUI, x86_64-unknown-linux-musl via cross)...
pushd "%~dp0Builder"
cross build --release --target x86_64-unknown-linux-musl
if errorlevel 1 (
    echo  [FAILED] Linux build.
    popd
    goto :fail
)
popd
copy /y "%~dp0Builder\target\x86_64-unknown-linux-musl\release\keybase-builder" "%~dp0dist\keybase-builder-linux" >nul
echo  [OK]  dist\keybase-builder-linux
echo.

echo  ==========================================
echo   Done!  Output: dist\
echo    keybase-builder-windows.exe  (Windows)
echo    keybase-builder-linux        (Linux)
echo  ==========================================
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
