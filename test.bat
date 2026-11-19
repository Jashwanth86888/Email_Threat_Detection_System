@echo off
title Test Suite - Email Threat Detection Platform
cd /d "%~dp0"

set "PYTHON_EXE=C:\Users\Pandugolla\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if not exist "%PYTHON_EXE%" (
    set "PYTHON_EXE=python"
)

"%PYTHON_EXE%" test_system.py
echo.
pause
