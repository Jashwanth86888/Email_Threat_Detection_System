@echo off
title Email Threat Detection Platform - Team 21
echo ===================================================================
echo  Starting Email Threat Detection Platform (Flask Server)
echo  Vasavi College of Engineering - CN 5th Sem (Team 21)
echo ===================================================================
echo.

cd /d "%~dp0"

set "PYTHON_EXE=C:\Users\Pandugolla\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if not exist "%PYTHON_EXE%" (
    set "PYTHON_EXE=python"
)

echo Using Python at: %PYTHON_EXE%
echo Opening application at http://127.0.0.1:5000/
start http://127.0.0.1:5000/
echo.
"%PYTHON_EXE%" app.py
pause
