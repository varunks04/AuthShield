<#
.SYNOPSIS
    AuthShield Master Process Launcher for PowerShell
.DESCRIPTION
    Launches each AuthShield service, attack simulation, and test suite in its own dedicated terminal window.
.EXAMPLE
    .\run_all.ps1
    .\run_all.ps1 -Mode Services
    .\run_all.ps1 -Mode Tests
    .\run_all.ps1 -Mode Table
    .\run_all.ps1 -Mode Menu
#>

[CmdletBinding()]
param(
    [ValidateSet("Recommended", "Table", "Services", "Tests", "Menu", "Help")]
    [string]$Mode = "Recommended"
)

$ProjectDir = $PSScriptRoot
Set-Location -Path $ProjectDir

# Detect Python interpreter
$PythonExe = "python"
$EnvStatus = "System Python"

if (Test-Path "$ProjectDir\.venv\Scripts\python.exe") {
    $PythonExe = "$ProjectDir\.venv\Scripts\python.exe"
    $EnvStatus = ".venv (Virtual Environment)"
} elseif (Test-Path "$ProjectDir\venv\Scripts\python.exe") {
    $PythonExe = "$ProjectDir\venv\Scripts\python.exe"
    $EnvStatus = "venv (Virtual Environment)"
}

function Launch-Terminal {
    param(
        [string]$Title,
        [string]$CommandText
    )

    $encodedScript = "
        `$host.UI.RawUI.WindowTitle = '$Title'
        Set-Location -Path '$ProjectDir'
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host '  AuthShield: $Title' -ForegroundColor Green
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host 'Running: $CommandText' -ForegroundColor Yellow
        Write-Host ''
        & $CommandText
    "
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $encodedScript
}

function Show-Header {
    param([string]$OrderDescription)
    Clear-Host
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "               🛡️  AuthShield - Master Process Launcher" -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "  Project Root : $ProjectDir"
    Write-Host "  Interpreter  : $PythonExe"
    Write-Host "  Environment  : $EnvStatus"
    Write-Host "  Execution    : $OrderDescription" -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Summary {
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host " 🚀 All requested processes have been spawned in dedicated terminal windows!" -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " Active Endpoints:"
    Write-Host "   * FastAPI Swagger UI  : http://127.0.0.1:8000/docs"
    Write-Host "   * FastAPI ReDoc Docs  : http://127.0.0.1:8000/redoc"
    Write-Host "   * FastAPI Health API  : http://127.0.0.1:8000/health"
    Write-Host "   * Streamlit SOC UI    : http://localhost:8501"
    Write-Host ""
    Write-Host " Default Seed Credentials:"
    Write-Host "   * Admin User   : admin@authshield.io   / AdminPassword123!"
    Write-Host "   * Analyst User : analyst@authshield.io / AnalystPassword123!"
    Write-Host "   * Normal User  : user@authshield.io    / UserPassword123!"
    Write-Host ""
    Write-Host " Documentation & Guides:"
    Write-Host "   * Execution Guide   : docs/RUN_GUIDE.md"
    Write-Host "   * Life & Logic Flow : docs/life_logical_flow.md"
    Write-Host "   * Business Pipeline : docs/project_business_flow.md"
    Write-Host ""
    Write-Host " Note: To stop FastAPI or Streamlit, switch to their windows and press Ctrl+C."
    Write-Host "===============================================================================" -ForegroundColor Green
}

switch ($Mode) {
    "Recommended" {
        Show-Header "Recommended Dependency Order [1 to 6]"
        Write-Host "  [1/6] Database Re-seed       : $PythonExe -m app.database.init_db"
        Write-Host "  [2/6] FastAPI Backend        : $PythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
        Write-Host "  [3/6] Streamlit Dashboard    : $PythonExe -m streamlit run dashboard/app.py"
        Write-Host "  [4/6] Attack Simulation      : $PythonExe scripts/simulate_attacks.py"
        Write-Host "  [5/6] Pytest Test Suite      : $PythonExe -m pytest -v"
        Write-Host "  [6/6] Pytest Coverage        : $PythonExe -m pytest --cov=app tests/"
        Write-Host ""
        Write-Host "Spawning terminals with startup delays..." -ForegroundColor Yellow

        Write-Host "[*] [1/6] Launching Database Re-seed..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [1/6] - Database Re-seed" "$PythonExe -m app.database.init_db"
        Start-Sleep -Seconds 3

        Write-Host "[*] [2/6] Launching FastAPI Backend Server (Port 8000)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [2/6] - FastAPI Backend" "$PythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
        Start-Sleep -Seconds 5

        Write-Host "[*] [3/6] Launching Streamlit SOC Dashboard (Port 8501)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [3/6] - Streamlit Dashboard" "$PythonExe -m streamlit run dashboard/app.py"
        Start-Sleep -Seconds 4

        Write-Host "[*] [4/6] Launching IAM Threat Attack Simulation..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [4/6] - Attack Simulation" "$PythonExe scripts/simulate_attacks.py"
        Start-Sleep -Seconds 3

        Write-Host "[*] [5/6] Launching Pytest Test Suite..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [5/6] - Pytest Test Suite" "$PythonExe -m pytest -v"
        Start-Sleep -Seconds 3

        Write-Host "[*] [6/6] Launching Pytest Coverage Analysis..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [6/6] - Pytest Coverage" "$PythonExe -m pytest --cov=app tests/"

        Show-Summary
    }

    "Table" {
        Show-Header "Cheat Sheet Table Order [1 to 6]"
        Write-Host "[*] [1/6] Launching FastAPI Backend (Port 8000)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [1/6] - FastAPI Backend" "$PythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
        Start-Sleep -Seconds 5

        Write-Host "[*] [2/6] Launching Streamlit Dashboard (Port 8501)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [2/6] - Streamlit Dashboard" "$PythonExe -m streamlit run dashboard/app.py"
        Start-Sleep -Seconds 4

        Write-Host "[*] [3/6] Launching Attack Simulation..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [3/6] - Attack Simulation" "$PythonExe scripts/simulate_attacks.py"
        Start-Sleep -Seconds 3

        Write-Host "[*] [4/6] Launching Pytest Test Suite..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [4/6] - Pytest Test Suite" "$PythonExe -m pytest -v"
        Start-Sleep -Seconds 3

        Write-Host "[*] [5/6] Launching Pytest Coverage Analysis..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [5/6] - Pytest Coverage" "$PythonExe -m pytest --cov=app tests/"
        Start-Sleep -Seconds 3

        Write-Host "[*] [6/6] Launching Database Re-seed..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield [6/6] - Database Re-seed" "$PythonExe -m app.database.init_db"

        Show-Summary
    }

    "Services" {
        Show-Header "Core Services Only (Backend + Dashboard)"
        Write-Host "[*] Initializing Database..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - Database Re-seed" "$PythonExe -m app.database.init_db"
        Start-Sleep -Seconds 3

        Write-Host "[*] Launching FastAPI Backend (Port 8000)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - FastAPI Backend" "$PythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
        Start-Sleep -Seconds 4

        Write-Host "[*] Launching Streamlit Dashboard (Port 8501)..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - Streamlit Dashboard" "$PythonExe -m streamlit run dashboard/app.py"

        Show-Summary
    }

    "Tests" {
        Show-Header "Tests & Simulation Only"
        Write-Host "[*] Launching Attack Simulation..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - Attack Simulation" "$PythonExe scripts/simulate_attacks.py"
        Start-Sleep -Seconds 2

        Write-Host "[*] Launching Pytest Test Suite..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - Pytest Test Suite" "$PythonExe -m pytest -v"
        Start-Sleep -Seconds 2

        Write-Host "[*] Launching Pytest Coverage..." -ForegroundColor Cyan
        Launch-Terminal "AuthShield - Pytest Coverage" "$PythonExe -m pytest --cov=app tests/"

        Show-Summary
    }

    "Help" {
        Get-Help $MyInvocation.MyCommand.Path -Full
    }
}
