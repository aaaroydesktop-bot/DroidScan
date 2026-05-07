#!/data/data/com.termux/files/usr/bin/bash

# =========================================================
# DroidScan v2.0 - Professional Termux Installer
# Developer: Anupom
# =========================================================

set -e

# ================= COLORS =================
GREEN="\e[1;32m"
CYAN="\e[1;36m"
YELLOW="\e[1;33m"
RED="\e[1;31m"
RESET="\e[0m"

# ================= CONFIG =================
INSTALL_DIR="$(pwd)"
BIN_PATH="$PREFIX/bin/droidscan"
PYTHON_FILE="droidscan.py"

# ================= FUNCTIONS =================

banner() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${RESET}           ${GREEN}DroidScan v2.0 - Advanced Installer${RESET}            ${CYAN}║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

update_and_install() {
    echo -e "${YELLOW}[*] Updating Termux packages...${RESET}"
    pkg update -y && pkg upgrade -y

    echo -e "${YELLOW}[*] Installing required packages...${RESET}"
    pkg install python python-pip aapt -y

    echo -e "${YELLOW}[*] Installing Python dependencies...${RESET}"
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt --break-system-packages
    else
        pip install rich tqdm requests --break-system-packages
    fi
}

create_launcher() {
    echo -e "${YELLOW}[*] Creating global command 'droidscan'...${RESET}"

    cat > "$BIN_PATH" << EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$INSTALL_DIR"
python "$PYTHON_FILE" "\$@"
EOF

    chmod +x "$BIN_PATH"
    chmod +x "$INSTALL_DIR/$PYTHON_FILE" 2>/dev/null || true

    echo -e "${GREEN}[+] Launcher created successfully!${RESET}"
}

main() {
    banner

    if [ ! -f "$PYTHON_FILE" ]; then
        echo -e "${RED}[!] Error: $PYTHON_FILE not found in current directory!${RESET}"
        echo -e "${YELLOW}Please save the v2.0 Python code as 'droidscan.py' first.${RESET}"
        exit 1
    fi

    update_and_install
    create_launcher

    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║           INSTALLATION COMPLETE!                           ║${RESET}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo
    echo -e "${CYAN}এখন থেকে যেকোনো জায়গা থেকে এই কমান্ড দিয়ে চালাতে পারবে:${RESET}"
    echo -e "    ${YELLOW}droidscan --help${RESET}"
    echo
    echo -e "${CYAN}উদাহরণ:${RESET}"
    echo -e "    ${YELLOW}droidscan --scan${RESET}"
    echo -e "    ${YELLOW}droidscan --scan --export both${RESET}"
    echo
}

main