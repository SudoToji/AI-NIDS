@echo off
echo ========================================
echo   AI-NIDS - Network Intrusion Detection
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo [1/3] Creating virtual environment...
    python -m venv venv
    echo.
)

REM Activate virtual environment
echo [2/3] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo [3/3] Installing dependencies...
pip install -r requirements.txt >nul 2>&1

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
