@echo off
setlocal enabledelayedexpansion

REM ===============================================================================
REM  AuthShield - Master Process Launcher (Windows Batch)
REM  Launches each service, simulation, and test in its own dedicated terminal window.
REM ===============================================================================

title AuthShield Master Launcher
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

REM -------------------------------------------------------------------------------
REM  Detect Python Interpreter
REM -------------------------------------------------------------------------------
set "PYTHON_EXE=python"
set "ENV_STATUS=System Python"

if exist "%PROJECT_DIR%.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%.venv\Scripts\python.exe"
    set "ENV_STATUS=.venv (Isolated Environment)"
) else if exist "%PROJECT_DIR%venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%venv\Scripts\python.exe"
    set "ENV_STATUS=venv (Isolated Environment)"
)

"%PYTHON_EXE%" --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ===============================================================================
    echo  [!] ERROR: Python executable could not be found or executed.
    echo      Please verify that Python 3.10+ is installed and available in your PATH.
    echo ===============================================================================
    echo.
    pause
    exit /b 1
)

REM -------------------------------------------------------------------------------
REM  Parse CLI Arguments
REM -------------------------------------------------------------------------------
set "PARAM=%~1"
if /i "%PARAM%"=="table"       goto :run_table_order
if /i "%PARAM%"=="--table"     goto :run_table_order
if /i "%PARAM%"=="services"    goto :run_services_only
if /i "%PARAM%"=="--services"  goto :run_services_only
if /i "%PARAM%"=="tests"       goto :run_tests_only
if /i "%PARAM%"=="--tests"     goto :run_tests_only
if /i "%PARAM%"=="menu"        goto :menu
if /i "%PARAM%"=="--menu"      goto :menu
if /i "%PARAM%"=="-m"          goto :menu
if /i "%PARAM%"=="help"        goto :help
if /i "%PARAM%"=="--help"      goto :help
if /i "%PARAM%"=="-h"          goto :help

REM Default: Recommended Dependency Order
goto :run_recommended_order


REM ===============================================================================
REM  RECOMMENDED ORDER (Dependency Safe)
REM  1. DB Re-seed       -> Prepares SQLite tables and seed accounts
REM  2. FastAPI Backend  -> REST API starts on port 8000
REM  3. Streamlit SOC    -> Security Operations Dashboard starts on port 8501
REM  4. Attack Simulation-> Hits live backend, generating alerts for Streamlit UI
REM  5. Pytest Suite     -> Executes full test suite
REM  6. Pytest Coverage  -> Generates code coverage report
REM ===============================================================================
:run_recommended_order
cls
echo ===============================================================================
echo                AuthShield - Master Process Launcher
echo ===============================================================================
echo  Project Root : %PROJECT_DIR%
echo  Interpreter  : %PYTHON_EXE%
echo  Environment  : %ENV_STATUS%
echo  Order Mode   : Recommended Dependency Order [1 to 6]
echo ===============================================================================
echo.
echo  [1/6] Database Re-seed       : python -m app.database.init_db
echo  [2/6] FastAPI Backend        : python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
echo  [3/6] Streamlit Dashboard    : python -m streamlit run dashboard/app.py
echo  [4/6] Attack Simulation      : python scripts/simulate_attacks.py
echo  [5/6] Pytest Test Suite      : python -m pytest -v
echo  [6/6] Pytest Coverage        : python -m pytest --cov=app tests/
echo.
echo ===============================================================================
echo  Spawning terminals in sequence with startup delays...
echo ===============================================================================
echo.

REM 1. Database Re-seed
echo [*] [1/6] Launching Database Re-seed...
start "AuthShield [1/6] - Database Re-seed" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m app.database.init_db & echo. & echo ======================================================== & echo  [SUCCESS] Database initialized and seeded with default users! & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 2. FastAPI Backend
echo [*] [2/6] Launching FastAPI Backend Server (Port 8000)...
start "AuthShield [2/6] - FastAPI Backend (Port 8000)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
echo     Waiting 5 seconds for backend to bind port 8000...
timeout /t 5 /nobreak >nul

REM 3. Streamlit Dashboard
echo [*] [3/6] Launching Streamlit SOC Dashboard (Port 8501)...
start "AuthShield [3/6] - Streamlit Dashboard (Port 8501)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m streamlit run dashboard/app.py"
echo     Waiting 4 seconds for dashboard to initialize...
timeout /t 4 /nobreak >nul

REM 4. Attack Simulation
echo [*] [4/6] Launching IAM Threat Attack Simulation...
start "AuthShield [4/6] - Attack Simulation" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" scripts/simulate_attacks.py & echo. & echo ======================================================== & echo  [SUCCESS] Attack simulations completed! & echo  Check live events and alerts in your Streamlit dashboard. & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 5. Pytest Test Suite
echo [*] [5/6] Launching Pytest Test Suite (-v)...
start "AuthShield [5/6] - Pytest Test Suite" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest -v & echo. & echo ======================================================== & echo  [SUCCESS] Pytest test run completed! & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 6. Pytest Coverage
echo [*] [6/6] Launching Pytest Coverage Analysis...
start "AuthShield [6/6] - Pytest Coverage" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest --cov=app tests/ & echo. & echo ======================================================== & echo  [SUCCESS] Pytest coverage analysis completed! & echo  This terminal will remain open for your inspection. & echo ========================================================"

goto :finish_summary


REM ===============================================================================
REM  TABLE ORDER (Exact Cheat Sheet Order)
REM ===============================================================================
:run_table_order
cls
echo ===============================================================================
echo                AuthShield - Master Process Launcher
echo ===============================================================================
echo  Project Root : %PROJECT_DIR%
echo  Interpreter  : %PYTHON_EXE%
echo  Order Mode   : Quick Commands Cheat Sheet Table Order [1 to 6]
echo ===============================================================================
echo.
echo  [1/6] FastAPI Backend        : python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
echo  [2/6] Streamlit Dashboard    : python -m streamlit run dashboard/app.py
echo  [3/6] Attack Simulation      : python scripts/simulate_attacks.py
echo  [4/6] Pytest Test Suite      : python -m pytest -v
echo  [5/6] Pytest Coverage        : python -m pytest --cov=app tests/
echo  [6/6] Database Re-seed       : python -m app.database.init_db
echo.
echo ===============================================================================
echo  Spawning terminals in sequence...
echo ===============================================================================
echo.

REM 1. FastAPI Backend
echo [*] [1/6] Launching FastAPI Backend Server (Port 8000)...
start "AuthShield [1/6] - FastAPI Backend (Port 8000)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 5 /nobreak >nul

REM 2. Streamlit Dashboard
echo [*] [2/6] Launching Streamlit SOC Dashboard (Port 8501)...
start "AuthShield [2/6] - Streamlit Dashboard (Port 8501)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m streamlit run dashboard/app.py"
timeout /t 4 /nobreak >nul

REM 3. Attack Simulation
echo [*] [3/6] Launching Attack Simulation...
start "AuthShield [3/6] - Attack Simulation" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" scripts/simulate_attacks.py & echo. & echo ======================================================== & echo  [SUCCESS] Attack simulations completed! & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 4. Pytest Test Suite
echo [*] [4/6] Launching Pytest Test Suite...
start "AuthShield [4/6] - Pytest Test Suite" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest -v & echo. & echo ======================================================== & echo  [SUCCESS] Pytest test run completed! & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 5. Pytest Coverage
echo [*] [5/6] Launching Pytest Coverage Analysis...
start "AuthShield [5/6] - Pytest Coverage" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest --cov=app tests/ & echo. & echo ======================================================== & echo  [SUCCESS] Pytest coverage analysis completed! & echo  This terminal will remain open for your inspection. & echo ========================================================"
timeout /t 3 /nobreak >nul

REM 6. Database Re-seed
echo [*] [6/6] Launching Database Re-seed...
start "AuthShield [6/6] - Database Re-seed" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m app.database.init_db & echo. & echo ======================================================== & echo  [SUCCESS] Database initialized and seeded with default users! & echo  This terminal will remain open for your inspection. & echo ========================================================"

goto :finish_summary


REM ===============================================================================
REM  SERVICES ONLY
REM ===============================================================================
:run_services_only
cls
echo ===============================================================================
echo       AuthShield - Starting Core Services (Backend + Dashboard)
echo ===============================================================================
echo.
echo [*] Initializing Database first...
start "AuthShield - Database Re-seed" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m app.database.init_db & echo. & echo [OK] Database ready."
timeout /t 3 /nobreak >nul

echo [*] Launching FastAPI Backend Server (Port 8000)...
start "AuthShield - FastAPI Backend (Port 8000)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 4 /nobreak >nul

echo [*] Launching Streamlit SOC Dashboard (Port 8501)...
start "AuthShield - Streamlit Dashboard (Port 8501)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m streamlit run dashboard/app.py"

goto :finish_summary


REM ===============================================================================
REM  TESTS ONLY
REM ===============================================================================
:run_tests_only
cls
echo ===============================================================================
echo       AuthShield - Running Attack Simulations ^& Test Suites
echo ===============================================================================
echo.
echo [*] Launching Attack Simulation...
start "AuthShield - Attack Simulation" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" scripts/simulate_attacks.py"
timeout /t 2 /nobreak >nul

echo [*] Launching Pytest Test Suite...
start "AuthShield - Pytest Test Suite" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest -v"
timeout /t 2 /nobreak >nul

echo [*] Launching Pytest Coverage Analysis...
start "AuthShield - Pytest Coverage" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest --cov=app tests/"

goto :finish_summary


REM ===============================================================================
REM  INTERACTIVE MENU
REM ===============================================================================
:menu
cls
echo ===============================================================================
echo                AuthShield - Interactive Command Menu
echo ===============================================================================
echo  Project Root : %PROJECT_DIR%
echo  Environment  : %ENV_STATUS%
echo ===============================================================================
echo.
echo   [1] Run ALL in Recommended Order (DB -^> Backend -^> Dashboard -^> Attacks -^> Tests -^> Coverage)
echo   [2] Run ALL in Cheat Sheet Table Order (Backend -^> Dashboard -^> Attacks -^> Tests -^> Coverage -^> DB)
echo   [3] Core Services Only (DB Init + FastAPI Backend + Streamlit Dashboard)
echo   [4] Tests ^& Simulation Only (Attack Simulation + Pytest Suite + Coverage)
echo   -----------------------------------------------------------------------------
echo   [5] Individual: Database Re-seed (python -m app.database.init_db)
echo   [6] Individual: FastAPI Backend (Port 8000)
echo   [7] Individual: Streamlit Dashboard (Port 8501)
echo   [8] Individual: Attack Simulation Script
echo   [9] Individual: Pytest Test Suite (-v)
echo   [10] Individual: Pytest Coverage (--cov=app)
echo   [0] Exit
echo.
echo ===============================================================================
set /p "CHOICE=Enter selection [1-10, 0]: "

if "%CHOICE%"=="1" goto :run_recommended_order
if "%CHOICE%"=="2" goto :run_table_order
if "%CHOICE%"=="3" goto :run_services_only
if "%CHOICE%"=="4" goto :run_tests_only
if "%CHOICE%"=="5" (
    start "AuthShield - Database Re-seed" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m app.database.init_db"
    goto :menu
)
if "%CHOICE%"=="6" (
    start "AuthShield - FastAPI Backend (Port 8000)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
    goto :menu
)
if "%CHOICE%"=="7" (
    start "AuthShield - Streamlit Dashboard (Port 8501)" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m streamlit run dashboard/app.py"
    goto :menu
)
if "%CHOICE%"=="8" (
    start "AuthShield - Attack Simulation" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" scripts/simulate_attacks.py"
    goto :menu
)
if "%CHOICE%"=="9" (
    start "AuthShield - Pytest Test Suite" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest -v"
    goto :menu
)
if "%CHOICE%"=="10" (
    start "AuthShield - Pytest Coverage" /D "%PROJECT_DIR%" cmd /k ""%PYTHON_EXE%" -m pytest --cov=app tests/"
    goto :menu
)
if "%CHOICE%"=="0" exit /b 0

echo Invalid choice. Try again.
timeout /t 2 >nul
goto :menu


REM ===============================================================================
REM  HELP SCREEN
REM ===============================================================================
:help
cls
echo ===============================================================================
echo                AuthShield Launcher - Help ^& CLI Usage
echo ===============================================================================
echo.
echo  Usage:
echo    run_all.bat [MODE]
echo.
echo  Available Modes:
echo    run_all.bat               Runs all 6 components in recommended order
echo    run_all.bat --table       Runs all 6 components in cheat sheet table order
echo    run_all.bat --services    Runs only DB init, FastAPI Backend, and Streamlit
echo    run_all.bat --tests       Runs only Attack Simulation, Pytest, and Coverage
echo    run_all.bat --menu        Opens the interactive selection menu
echo    run_all.bat --help        Displays this help guide
echo.
echo  Web Endpoints:
echo    * FastAPI Swagger UI  : http://127.0.0.1:8000/docs
echo    * FastAPI ReDoc Docs  : http://127.0.0.1:8000/redoc
echo    * FastAPI Health      : http://127.0.0.1:8000/health
echo    * Streamlit Dashboard : http://localhost:8501
echo.
echo ===============================================================================
pause
exit /b 0


REM ===============================================================================
REM  COMPLETION SUMMARY
REM ===============================================================================
:finish_summary
echo.
echo ===============================================================================
echo  All requested processes have been spawned in dedicated terminal windows!
echo ===============================================================================
echo.
echo  Active Endpoints:
echo    * FastAPI Swagger UI  : http://127.0.0.1:8000/docs
echo    * FastAPI ReDoc Docs  : http://127.0.0.1:8000/redoc
echo    * FastAPI Health API  : http://127.0.0.1:8000/health
echo    * Streamlit SOC UI    : http://localhost:8501
echo.
echo  Default Seed Credentials:
echo    * Admin User   : admin@authshield.io   / AdminPassword123!
echo    * Analyst User : analyst@authshield.io / AnalystPassword123!
echo    * Normal User  : user@authshield.io    / UserPassword123!
echo.
echo  Documentation & Guides:
echo    * Execution Guide   : docs\RUN_GUIDE.md
echo    * Life & Logic Flow : docs\life_logical_flow.md
echo    * Business Pipeline : docs\project_business_flow.md
echo.
echo  Note: To stop FastAPI or Streamlit, switch to their windows and press Ctrl+C.
echo ===============================================================================
echo.
echo Press any key to exit this launcher window (spawned terminals will stay open)...
pause >nul
exit /b 0
