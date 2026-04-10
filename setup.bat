@echo off
setlocal EnableDelayedExpansion

title LLM Security Workbench — Native Setup

echo.
echo  ==========================================
echo   LLM Security Workbench — Native Setup
echo  ==========================================
echo.

:: ── 1. Require Python 3.11 ───────────────────────────────────────────────────
py -3.11 --version >nul 2>&1
if errorlevel 1 (
    echo [Error] Python 3.11 not found.
    echo         Install it from https://www.python.org/downloads/release/python-3119/
    echo         Then re-run this script.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('py -3.11 --version') do echo [Python] Using: %%v

:: ── 2. Create virtual environment ────────────────────────────────────────────
if exist "venv\" (
    echo [venv]   Already exists -- skipping creation.
) else (
    echo [venv]   Creating virtual environment with Python 3.11...
    py -3.11 -m venv venv
    echo [venv]   Created.
)

:: ── 3. Upgrade pip ────────────────────────────────────────────────────────────
echo [pip]    Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet

:: ── 4. Install dependencies ───────────────────────────────────────────────────
echo [pip]    Installing requirements (this may take a few minutes)...
venv\Scripts\pip.exe install -r requirements.txt ^
    --extra-index-url https://download.pytorch.org/whl/cpu ^
    --quiet

if errorlevel 1 (
    echo [Error] pip install failed. Check the output above.
    pause
    exit /b 1
)

echo [pip]    All dependencies installed.

:: ── 5. Copy .env if missing ──────────────────────────────────────────────────
if not exist ".env" (
    if exist ".env.example" (
        copy /Y ".env.example" ".env" >nul
        echo [env]    .env created from .env.example.
        echo          Open .env and confirm OLLAMA_HOST=http://localhost:11434
    )
) else (
    echo [env]    .env already exists -- skipping.
)

:: ── 6. Done ──────────────────────────────────────────────────────────────────
echo.
echo  ==========================================
echo   Setup complete.
echo.
echo   To start the app:
echo     venv\Scripts\activate
echo     python -m streamlit run app.py
echo  ==========================================
echo.

endlocal
