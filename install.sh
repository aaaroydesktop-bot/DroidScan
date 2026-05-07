#!/data/data/com.termux/files/usr/bin/bash

# =========================================================
# DroidScan v1.1 - Professional Termux Installer
# Developer: Anupom
# =========================================================

set -e

# ================= COLORS =================
GREEN="\e[1;32m"
CYAN="\e[1;36m"
YELLOW="\e[1;33m"
RESET="\e[0m"

# ================= CONFIG =================
INSTALL_DIR="$(pwd)"
BIN_PATH="$PREFIX/bin/droidscan"

# ================= FUNCTIONS =================

banner() {
    clear
    echo -e "${CYAN}====================================================${RESET}"
    echo -e "${GREEN}        DroidScan v1.1 Installer${RESET}"
    echo -e "${CYAN}====================================================${RESET}"
    echo
}

update_and_install() {
    echo -e "${YELLOW}[*] Updating packages...${RESET}"
    pkg update -y && pkg upgrade -y
    
    echo -e "${YELLOW}[*] Installing dependencies...${RESET}"
    pkg install python python-pip -y
    
    echo -e "${YELLOW}[*] Installing Python modules...${RESET}"
    # Termux restrictions bypass
    pip install -r requirements.txt --break-system-packages
}

create_launcher() {
    echo -e "${YELLOW}[*] Creating global launcher...${RESET}"
    
    # এটি $PREFIX/bin এ একটি স্ক্রিপ্ট তৈরি করবে
    cat > "$BIN_PATH" << EOF
#!/data/data/com.termux/files/usr/bin/bash
python "$INSTALL_DIR/main.py" "\$@"
EOF
    
    # পারমিশন সেট করা
    chmod +x "$BIN_PATH"
    chmod +x "$INSTALL_DIR/main.py"
}

# ================= MAIN =================

main() {
    banner
    update_and_install
    create_launcher
    
    echo
    echo -e "${GREEN}====================================================${RESET}"
    echo -e "${GREEN}        INSTALLATION COMPLETE!${RESET}"
    echo -e "${GREEN}====================================================${RESET}"
    echo -e "${CYAN}এখন থেকে শুধু নিচের কমান্ডটি লিখে এন্টার দিন:${RESET}"
    echo -e "${YELLOW}droidscan${RESET}"
    echo
}

main