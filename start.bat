@echo off
chcp 65001 >nul
title Rastgele IP Web Tarayici
cd /d "%~dp0"
echo ============================================================
echo        RASTGELE IP WEB TARAYICI BASLATILIYOR...
echo   (404 ve Timeout'lar atlanir, 200 ve 403 kaydedilir)
echo ============================================================
echo.
python main.py %*
if %errorlevel% neq 0 (
    echo.
    echo Bir hata meydana geldi.
    pause
)
