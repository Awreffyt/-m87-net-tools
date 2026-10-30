@echo off
chcp 65001 >nul
cd /d "%~dp0"
title M87 本地版

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 set "PY=python"
)

if not defined PY goto NOPYTHON

%PY% "%~dp0m87.py"
if errorlevel 1 pause
exit /b 0

:NOPYTHON
echo.
echo   这台电脑还没装 Python 3，只差这一步就可以用了：
echo.
echo     1. 打开 https://www.python.org/downloads/
echo     2. 点黄色按钮下载，双击安装
echo     3. 安装第一页最下面勾选 "Add python.exe to PATH"
echo     4. 装完后，重新双击「启动M87.bat」
echo.
pause
exit /b 1
