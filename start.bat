@echo off
setlocal EnableDelayedExpansion

title LLM Security Workbench

echo.
echo  ==========================================
echo   LLM Security Workbench — Starting Up
echo  ==========================================
echo.

:: ── 1. Copy .env.example to .env if no .env exists ──────────────────────────
if not exist ".env" (
    if exist ".env.example" (
        echo [Setup] No .env file found. Copying .env.example to .env ...
        copy /Y ".env.example" ".env" >nul
        echo [Setup] .env created. Edit it to set your PANW_API_KEY if needed.
    ) else (
        echo [Warning] Neither .env nor .env.example found. Continuing without env file.
    )
) else (
    echo [Setup] .env already exists. Skipping copy.
)

echo.

:: ── 2. Check that Docker is available ───────────────────────────────────────
docker info >nul 2>&1
if errorlevel 1 (
    echo [Error] Docker does not appear to be running.
    echo         Please start Docker Desktop and re-run this script.
    echo.
    pause
    exit /b 1
)

:: ── 3. Check that Ollama is reachable ────────────────────────────────────────
echo [Check] Verifying Ollama is reachable...
curl -s -o nul -w "%%{http_code}" http://localhost:11434 2>nul | findstr "200" >nul
if errorlevel 1 (
    echo [Warning] Ollama does not appear to be running at http://localhost:11434.
    echo           The app will start but LLM features will not work until Ollama is running.
    echo           Download Ollama from: https://ollama.com/download
    echo.
)

:: ── 4. Start the stack with Docker Compose ───────────────────────────────────
echo [Docker] Starting containers with docker-compose up --build -d ...
docker compose up --build -d
if errorlevel 1 (
    echo [Error] docker-compose up failed. Check the output above for details.
    pause
    exit /b 1
)

echo.
echo [Ready] Containers started. Waiting for Streamlit to become healthy...
echo.

:: ── 5. Wait for Streamlit healthcheck ────────────────────────────────────────
set /a ATTEMPTS=0
:WAIT_LOOP
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 20 (
    echo [Timeout] App did not become healthy after 60 seconds.
    echo           Run: docker compose logs workbench
    pause
    exit /b 1
)
curl -s -f http://localhost:8501/_stcore/health >nul 2>&1
if errorlevel 1 (
    timeout /t 3 /nobreak >nul
    goto WAIT_LOOP
)

:: ── 6. Open the browser ───────────────────────────────────────────────────────
echo [Open] Opening http://localhost:8501 ...
start "" http://localhost:8501

echo.
echo  ==========================================
echo   Workbench is running at localhost:8501
echo   To stop:  docker compose down
echo  ==========================================
echo.

endlocal
