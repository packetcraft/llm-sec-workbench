@echo off
:: start.bat — Native launcher for LLM Security Workbench (Python 3.11 venv)
::
:: Usage:
::   start.bat            native venv (default)
::   start.bat --docker   docker compose path
::
setlocal EnableDelayedExpansion

title LLM Security Workbench

echo.
echo  ==========================================
echo   LLM Security Workbench - Starting Up
echo  ==========================================
echo.

:: ── Parse flags ───────────────────────────────────────────────────────────────
set DOCKER_MODE=0
for %%A in (%*) do (
    if "%%A"=="--docker" set DOCKER_MODE=1
)

:: ── .env bootstrap ────────────────────────────────────────────────────────────
if not exist ".env" (
    if exist ".env.example" (
        echo [Setup] No .env found - copying .env.example to .env ...
        copy /Y ".env.example" ".env" >nul
        echo [Setup] .env created. Edit it to set PANW_API_KEY if needed.
    ) else (
        echo [Warning] Neither .env nor .env.example found. Continuing anyway.
    )
) else (
    echo [Setup] .env already exists. Skipping copy.
)
echo.

:: ══════════════════════════════════════════════════════════════════════════════
:: DOCKER PATH
:: ══════════════════════════════════════════════════════════════════════════════
if %DOCKER_MODE%==1 (
    docker info >nul 2>&1
    if errorlevel 1 (
        echo [Error] Docker is not running. Start Docker Desktop and retry.
        pause & exit /b 1
    )
    curl -s -o nul -w "%%{http_code}" http://localhost:11434 2>nul | findstr "200" >nul
    if errorlevel 1 (
        echo [Warning] Ollama not reachable. LLM features will be unavailable.
        echo.
    )
    echo [Docker] Running docker compose up --build -d ...
    docker compose up --build -d
    if errorlevel 1 ( echo [Error] docker compose failed. & pause & exit /b 1 )
    echo.
    echo [Ready] Waiting for Streamlit to become healthy...
    set /a ATTEMPTS=0
    :DOCKER_WAIT
        set /a ATTEMPTS+=1
        if !ATTEMPTS! GTR 20 (
            echo [Timeout] Run: docker compose logs workbench
            pause & exit /b 1
        )
        curl -s -f http://localhost:8501/_stcore/health >nul 2>&1
        if errorlevel 1 ( timeout /t 3 /nobreak >nul & goto DOCKER_WAIT )
    start "" http://localhost:8501
    echo.
    echo  Workbench running at http://localhost:8501  (stop: docker compose down)
    echo.
    endlocal & exit /b 0
)

:: ══════════════════════════════════════════════════════════════════════════════
:: NATIVE PATH (default)
:: ══════════════════════════════════════════════════════════════════════════════

:: ── 1. Locate Python 3.11 ─────────────────────────────────────────────────────
py -3.11 --version >nul 2>&1
if errorlevel 1 (
    echo [Error] Python 3.11 not found.
    echo         Install it from https://www.python.org/downloads/release/python-3119/
    echo         or run:  py --list  to see available versions.
    pause & exit /b 1
)
for /f "tokens=*" %%V in ('py -3.11 --version') do echo [Python] Using: %%V

:: ── 2. Create venv if it doesn't exist ───────────────────────────────────────
if not exist "venv\" (
    echo [Venv] Creating Python 3.11 virtual environment in .\venv ...
    py -3.11 -m venv venv
    echo [Venv] Created.
)

:: ── 3. Activate venv ─────────────────────────────────────────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo [Error] venv\Scripts\activate.bat not found. Delete .\venv and retry.
    pause & exit /b 1
)
call venv\Scripts\activate.bat
for /f "tokens=*" %%V in ('python --version') do echo [Venv] Activated: %%V

:: ── 4. Install / sync dependencies ───────────────────────────────────────────
echo.
echo [Deps] Checking requirements.txt ...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo [Deps] Dependencies OK.

:: ── 5. Bootstrap spaCy model for presidio-analyzer ───────────────────────────
python -c "import spacy; spacy.load('en_core_web_lg')" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [spaCy] Downloading en_core_web_lg (~750 MB^) - one-time setup ...
    python -m spacy download en_core_web_lg
    echo [spaCy] Model ready.
) else (
    echo [spaCy] en_core_web_lg already installed. Skipping download.
)

:: ── 6. Check Ollama & pull required models ────────────────────────────────────
echo.
curl -s -o nul -w "%%{http_code}" http://localhost:11434 2>nul | findstr "200" >nul
if errorlevel 1 (
    echo [Warning] Ollama not reachable at http://localhost:11434.
    echo           LLM features will be unavailable until Ollama is running.
    echo           Download: https://ollama.com/download
    echo.
) else (
    ollama list 2>nul | findstr "qwen2.5:1.5b" >nul
    if errorlevel 1 (
        echo [Ollama] Pulling qwen2.5:1.5b (Little Canary canary model, ~934 MB^) ...
        ollama pull qwen2.5:1.5b
        echo [Ollama] qwen2.5:1.5b ready.
    ) else (
        echo [Ollama] qwen2.5:1.5b already present.
    )
)

:: ── 7. Launch Streamlit ───────────────────────────────────────────────────────
echo [Start] Launching Streamlit ...
echo.
echo  ==========================================
echo   Workbench starting at http://localhost:8501
echo   Stop with: Ctrl+C
echo  ==========================================
echo.
streamlit run app.py

endlocal
