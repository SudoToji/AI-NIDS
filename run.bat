@echo off
title AI-NIDS - Network Intrusion Detection System
echo ========================================
echo   AI-NIDS - Network Intrusion Detection
echo ========================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ first.
    pause
    exit /b 1
)

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo [1/4] Creating virtual environment...
    python -m venv venv
    echo.
)

REM Activate virtual environment
echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo [3/4] Installing dependencies...
pip install -r requirements.txt >nul 2>&1

REM Check for .env file
if not exist ".env" (
    echo.
    echo [WARN] No .env file found. Create one for OpenRouter API key.
    echo        Copy .env.example to .env and add your OPENROUTER_API_KEY
    echo.
)

echo.
echo ========================================
echo   Starting AI-NIDS Server...
echo ========================================
echo.
echo Dashboard: http://localhost:5000
echo.
echo Press CTRL+C to stop the server
echo.

REM Start the server
python -m src.api.server
