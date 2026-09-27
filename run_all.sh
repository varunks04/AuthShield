#!/usr/bin/env bash

# ===============================================================================
#  AuthShield - Master Process Launcher (POSIX Shell: Linux / macOS / Git Bash)
#  Launches each service, simulation, and test in its own dedicated terminal window.
# ===============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Colors for terminal output
BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

# -------------------------------------------------------------------------------
#  Detect Python Interpreter & Environment
# -------------------------------------------------------------------------------
PYTHON_EXE="python3"
ENV_STATUS="System Python"

if [ -f "$PROJECT_DIR/.venv/bin/python" ]; then
    PYTHON_EXE="$PROJECT_DIR/.venv/bin/python"
    ENV_STATUS=".venv (Linux/macOS Virtualenv)"
elif [ -f "$PROJECT_DIR/.venv/Scripts/python.exe" ]; then
    PYTHON_EXE="$PROJECT_DIR/.venv/Scripts/python.exe"
    ENV_STATUS=".venv (Windows Virtualenv)"
elif [ -f "$PROJECT_DIR/venv/bin/python" ]; then
    PYTHON_EXE="$PROJECT_DIR/venv/bin/python"
    ENV_STATUS="venv (Linux/macOS Virtualenv)"
elif [ -f "$PROJECT_DIR/venv/Scripts/python.exe" ]; then
    PYTHON_EXE="$PROJECT_DIR/venv/Scripts/python.exe"
    ENV_STATUS="venv (Windows Virtualenv)"
elif command -v python3 &>/dev/null; then
    PYTHON_EXE="python3"
elif command -v python &>/dev/null; then
    PYTHON_EXE="python"
else
    echo -e "${RED}[!] ERROR: Neither 'python3' nor 'python' was found in your PATH.${RESET}"
    exit 1
fi

# -------------------------------------------------------------------------------
#  Helper: Launch command in a new terminal window
# -------------------------------------------------------------------------------
launch_terminal() {
    local title="$1"
    local run_cmd="$2"
    local keep_open="${3:-true}"

    local final_cmd
    if [ "$keep_open" = "true" ]; then
        final_cmd="cd '$PROJECT_DIR' && $run_cmd; echo ''; echo '========================================================'; echo ' [PROCESS COMPLETED] Terminal will remain open.'; echo '========================================================'; read -p 'Press Enter to exit...' -r"
    else
        final_cmd="cd '$PROJECT_DIR' && $run_cmd"
    fi

    # 1. Windows Git Bash / MSYS2 / Cygwin
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            local win_dir
            win_dir="$(cygpath -w "$PROJECT_DIR" 2>/dev/null || echo "$PROJECT_DIR")"
            cmd.exe /c start "$title" /D "$win_dir" cmd.exe /k "$run_cmd"
            return 0
            ;;
    esac

    # 2. macOS (Darwin)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        osascript -e "tell application \"Terminal\" to do script \"cd '$PROJECT_DIR' && $run_cmd\""
        return 0
    fi

    # 3. Linux GUI Terminal Emulators
    if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
        if command -v gnome-terminal &>/dev/null; then
            gnome-terminal --title="$title" -- bash -c "$final_cmd"
            return 0
        elif command -v x-terminal-emulator &>/dev/null; then
            x-terminal-emulator -T "$title" -e bash -c "$final_cmd"
            return 0
        elif command -v konsole &>/dev/null; then
            konsole -p tabtitle="$title" -e bash -c "$final_cmd"
            return 0
        elif command -v xfce4-terminal &>/dev/null; then
            xfce4-terminal --title="$title" -e "bash -c '$final_cmd'"
            return 0
        elif command -v alacritty &>/dev/null; then
            alacritty -t "$title" -e bash -c "$final_cmd"
            return 0
        elif command -v kitty &>/dev/null; then
            kitty --title "$title" bash -c "$final_cmd"
            return 0
        elif command -v xterm &>/dev/null; then
            xterm -T "$title" -e bash -c "$final_cmd"
            return 0
        fi
    fi

    # 4. Fallback for headless Linux / SSH
    echo -e "${YELLOW}[!] No GUI terminal detected. Running '$title' in background...${RESET}"
    mkdir -p "$PROJECT_DIR/logs"
    local safe_log_name
    safe_log_name=$(echo "$title" | tr ' /:' '___')
    nohup bash -c "cd '$PROJECT_DIR' && $run_cmd" > "$PROJECT_DIR/logs/${safe_log_name}.log" 2>&1 &
    echo -e "    PID: $! | Output log: logs/${safe_log_name}.log"
}

# -------------------------------------------------------------------------------
#  Execution Workflows
# -------------------------------------------------------------------------------
run_recommended_order() {
    clear 2>/dev/null || true
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "${BOLD}${CYAN}               🛡️  AuthShield - Master Process Launcher${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "  Project Root : ${PROJECT_DIR}"
    echo -e "  Interpreter  : ${PYTHON_EXE}"
    echo -e "  Environment  : ${ENV_STATUS}"
    echo -e "  Order Mode   : ${GREEN}Recommended Dependency Order [1 to 6]${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo ""
    echo "  [1/6] Database Re-seed       : $PYTHON_EXE -m app.database.init_db"
    echo "  [2/6] FastAPI Backend        : $PYTHON_EXE -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
    echo "  [3/6] Streamlit Dashboard    : $PYTHON_EXE -m streamlit run dashboard/app.py"
    echo "  [4/6] Attack Simulation      : $PYTHON_EXE scripts/simulate_attacks.py"
    echo "  [5/6] Pytest Test Suite      : $PYTHON_EXE -m pytest -v"
    echo "  [6/6] Pytest Coverage        : $PYTHON_EXE -m pytest --cov=app tests/"
    echo ""
    echo -e "${BOLD}Spawning terminals in sequence with startup delays...${RESET}"
    echo ""

    echo -e "${CYAN}[*] [1/6] Launching Database Re-seed...${RESET}"
    launch_terminal "AuthShield [1/6] - Database Re-seed" "$PYTHON_EXE -m app.database.init_db"
    sleep 3

    echo -e "${CYAN}[*] [2/6] Launching FastAPI Backend Server (Port 8000)...${RESET}"
    launch_terminal "AuthShield [2/6] - FastAPI Backend (Port 8000)" "$PYTHON_EXE -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
    echo "    Waiting 5 seconds for backend to bind port 8000..."
    sleep 5

    echo -e "${CYAN}[*] [3/6] Launching Streamlit SOC Dashboard (Port 8501)...${RESET}"
    launch_terminal "AuthShield [3/6] - Streamlit Dashboard (Port 8501)" "$PYTHON_EXE -m streamlit run dashboard/app.py"
    echo "    Waiting 4 seconds for dashboard to initialize..."
    sleep 4

    echo -e "${CYAN}[*] [4/6] Launching IAM Threat Attack Simulation...${RESET}"
    launch_terminal "AuthShield [4/6] - Attack Simulation" "$PYTHON_EXE scripts/simulate_attacks.py"
    sleep 3

    echo -e "${CYAN}[*] [5/6] Launching Pytest Test Suite (-v)...${RESET}"
    launch_terminal "AuthShield [5/6] - Pytest Test Suite" "$PYTHON_EXE -m pytest -v"
    sleep 3

    echo -e "${CYAN}[*] [6/6] Launching Pytest Coverage Analysis...${RESET}"
    launch_terminal "AuthShield [6/6] - Pytest Coverage" "$PYTHON_EXE -m pytest --cov=app tests/"

    finish_summary
}

run_table_order() {
    clear 2>/dev/null || true
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "${BOLD}${CYAN}               🛡️  AuthShield - Master Process Launcher${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "  Order Mode : ${GREEN}Quick Commands Cheat Sheet Table Order [1 to 6]${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo ""

    echo -e "${CYAN}[*] [1/6] Launching FastAPI Backend Server (Port 8000)...${RESET}"
    launch_terminal "AuthShield [1/6] - FastAPI Backend" "$PYTHON_EXE -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
    sleep 5

    echo -e "${CYAN}[*] [2/6] Launching Streamlit SOC Dashboard (Port 8501)...${RESET}"
    launch_terminal "AuthShield [2/6] - Streamlit Dashboard" "$PYTHON_EXE -m streamlit run dashboard/app.py"
    sleep 4

    echo -e "${CYAN}[*] [3/6] Launching Attack Simulation...${RESET}"
    launch_terminal "AuthShield [3/6] - Attack Simulation" "$PYTHON_EXE scripts/simulate_attacks.py"
    sleep 3

    echo -e "${CYAN}[*] [4/6] Launching Pytest Test Suite...${RESET}"
    launch_terminal "AuthShield [4/6] - Pytest Test Suite" "$PYTHON_EXE -m pytest -v"
    sleep 3

    echo -e "${CYAN}[*] [5/6] Launching Pytest Coverage Analysis...${RESET}"
    launch_terminal "AuthShield [5/6] - Pytest Coverage" "$PYTHON_EXE -m pytest --cov=app tests/"
    sleep 3

    echo -e "${CYAN}[*] [6/6] Launching Database Re-seed...${RESET}"
    launch_terminal "AuthShield [6/6] - Database Re-seed" "$PYTHON_EXE -m app.database.init_db"

    finish_summary
}

run_services_only() {
    echo -e "${CYAN}[*] Initializing Database...${RESET}"
    launch_terminal "AuthShield - Database Re-seed" "$PYTHON_EXE -m app.database.init_db"
    sleep 3

    echo -e "${CYAN}[*] Launching FastAPI Backend Server (Port 8000)...${RESET}"
    launch_terminal "AuthShield - FastAPI Backend (Port 8000)" "$PYTHON_EXE -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
    sleep 4

    echo -e "${CYAN}[*] Launching Streamlit Dashboard (Port 8501)...${RESET}"
    launch_terminal "AuthShield - Streamlit Dashboard (Port 8501)" "$PYTHON_EXE -m streamlit run dashboard/app.py"

    finish_summary
}

run_tests_only() {
    echo -e "${CYAN}[*] Launching Attack Simulation...${RESET}"
    launch_terminal "AuthShield - Attack Simulation" "$PYTHON_EXE scripts/simulate_attacks.py"
    sleep 2

    echo -e "${CYAN}[*] Launching Pytest Test Suite...${RESET}"
    launch_terminal "AuthShield - Pytest Test Suite" "$PYTHON_EXE -m pytest -v"
    sleep 2

    echo -e "${CYAN}[*] Launching Pytest Coverage Analysis...${RESET}"
    launch_terminal "AuthShield - Pytest Coverage" "$PYTHON_EXE -m pytest --cov=app tests/"

    finish_summary
}

show_menu() {
    clear 2>/dev/null || true
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "${BOLD}${CYAN}               🛡️  AuthShield - Interactive Command Menu${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "  Project Root : ${PROJECT_DIR}"
    echo -e "  Interpreter  : ${PYTHON_EXE}"
    echo -e "  Environment  : ${ENV_STATUS}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo ""
    echo "  [1] Run ALL in Recommended Order (DB -> Backend -> Dashboard -> Attacks -> Tests -> Coverage)"
    echo "  [2] Run ALL in Cheat Sheet Table Order (Backend -> Dashboard -> Attacks -> Tests -> Coverage -> DB)"
    echo "  [3] Core Services Only (DB Init + FastAPI Backend + Streamlit Dashboard)"
    echo "  [4] Tests & Simulation Only (Attack Simulation + Pytest Suite + Coverage)"
    echo "  -----------------------------------------------------------------------------"
    echo "  [5] Individual: Database Re-seed (python -m app.database.init_db)"
    echo "  [6] Individual: FastAPI Backend (Port 8000)"
    echo "  [7] Individual: Streamlit Dashboard (Port 8501)"
    echo "  [8] Individual: Attack Simulation Script"
    echo "  [9] Individual: Pytest Test Suite (-v)"
    echo "  [10] Individual: Pytest Coverage (--cov=app)"
    echo "  [0] Exit"
    echo ""
    read -p "Enter choice [1-10, 0]: " -r choice

    case "$choice" in
        1) run_recommended_order ;;
        2) run_table_order ;;
        3) run_services_only ;;
        4) run_tests_only ;;
        5) launch_terminal "AuthShield - Database Re-seed" "$PYTHON_EXE -m app.database.init_db"; show_menu ;;
        6) launch_terminal "AuthShield - FastAPI Backend" "$PYTHON_EXE -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"; show_menu ;;
        7) launch_terminal "AuthShield - Streamlit Dashboard" "$PYTHON_EXE -m streamlit run dashboard/app.py"; show_menu ;;
        8) launch_terminal "AuthShield - Attack Simulation" "$PYTHON_EXE scripts/simulate_attacks.py"; show_menu ;;
        9) launch_terminal "AuthShield - Pytest Test Suite" "$PYTHON_EXE -m pytest -v"; show_menu ;;
        10) launch_terminal "AuthShield - Pytest Coverage" "$PYTHON_EXE -m pytest --cov=app tests/"; show_menu ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; sleep 1; show_menu ;;
    esac
}

show_help() {
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo -e "${BOLD}${CYAN}               🛡️  AuthShield Launcher - Help & CLI Usage${RESET}"
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    echo ""
    echo " Usage:"
    echo "   ./run_all.sh [MODE]"
    echo ""
    echo " Available Modes:"
    echo "   ./run_all.sh               Runs all 6 components in recommended order"
    echo "   ./run_all.sh --table       Runs all 6 components in cheat sheet table order"
    echo "   ./run_all.sh --services    Runs only DB init, FastAPI Backend, and Streamlit"
    echo "   ./run_all.sh --tests       Runs only Attack Simulation, Pytest, and Coverage"
    echo "   ./run_all.sh --menu        Opens the interactive selection menu"
    echo "   ./run_all.sh --help        Displays this help guide"
    echo ""
    echo " Web Endpoints:"
    echo "   * FastAPI Swagger UI  : http://127.0.0.1:8000/docs"
    echo "   * FastAPI ReDoc Docs  : http://127.0.0.1:8000/redoc"
    echo "   * FastAPI Health API  : http://127.0.0.1:8000/health"
    echo "   * Streamlit Dashboard : http://localhost:8501"
    echo ""
    echo -e "${BOLD}${CYAN}===============================================================================${RESET}"
    exit 0
}

finish_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}===============================================================================${RESET}"
    echo -e "${BOLD}${GREEN} 🚀 All requested processes have been spawned in dedicated terminal windows!${RESET}"
    echo -e "${BOLD}${GREEN}===============================================================================${RESET}"
    echo ""
    echo " Active Endpoints:"
    echo "   * FastAPI Swagger UI  : http://127.0.0.1:8000/docs"
    echo "   * FastAPI ReDoc Docs  : http://127.0.0.1:8000/redoc"
    echo "   * FastAPI Health API  : http://127.0.0.1:8000/health"
    echo "   * Streamlit SOC UI    : http://localhost:8501"
    echo ""
    echo " Default Seed Credentials:"
    echo "   * Admin User   : admin@authshield.io   / AdminPassword123!"
    echo "   * Analyst User : analyst@authshield.io / AnalystPassword123!"
    echo "   * Normal User  : user@authshield.io    / UserPassword123!"
    echo ""
    echo " Documentation & Guides:"
    echo "   * Execution Guide   : docs/RUN_GUIDE.md"
    echo "   * Life & Logic Flow : docs/life_logical_flow.md"
    echo "   * Business Pipeline : docs/project_business_flow.md"
    echo ""
    echo " Note: To stop FastAPI or Streamlit, switch to their windows and press Ctrl+C."
    echo -e "${BOLD}${GREEN}===============================================================================${RESET}"
}

# -------------------------------------------------------------------------------
#  Main Entry Point
# -------------------------------------------------------------------------------
case "$1" in
    table|--table)         run_table_order ;;
    services|--services)   run_services_only ;;
    tests|--tests)         run_tests_only ;;
    menu|-m|--menu)        show_menu ;;
    help|-h|--help)        show_help ;;
    *)                     run_recommended_order ;;
esac
