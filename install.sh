#!/data/data/com.termux/files/usr/bin/bash

# =========================================================
# DroidScan v1.0 - Termux Installer
# Developer: Anupom
# =========================================================

GREEN="\e[1;32m"
CYAN="\e[1;36m"
RESET="\e[0m"

clear
echo -e "${CYAN}====================================================${RESET}"
echo -e "${GREEN}        DroidScan v1.0 Installer${RESET}"
echo -e "${CYAN}====================================================${RESET}"

echo "[*] Updating packages..."
pkg update -y && pkg upgrade -y

echo "[*] Installing required system packages (Python)..."
pkg install python -y

echo "[*] Upgrading pip..."
pip install --upgrade pip

echo "[*] Installing Python modules from requirements.txt..."
pip install -r requirements.txt

echo "[*] Setting execution permission for main.py..."
chmod +x main.py

echo -e "${GREEN}[+] Setup Completed Successfully!${RESET}"
echo -e "Run the tool using: ${CYAN}python main.py${RESET}"