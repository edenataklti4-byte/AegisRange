#!/bin/bash
# ==============================================================================
# AegisRange - Kali Attacker Node Provisioning Script
# Target Host : aegis-kali (Kali Linux Rolling / 10.10.10.10)
#
# WARNING & DISCLAIMER:
# This script provisions an attacker platform inside an isolated cyber range.
# All tools and artifacts created here are strictly for educational simulations,
# detection rule verification, and authorized cybersecurity training.
# DO NOT utilize these tools against any system without explicit authorization.
# ==============================================================================

set -euo pipefail

echo "[*] Starting AegisRange Kali attacker provisioning..."

# ------------------------------------------------------------------------------
# 1. Package Updates & Attack Toolset Installation
# ------------------------------------------------------------------------------
echo "[+] Updating apt repositories and installing attack simulation tools..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y

# Install attack, compilation, and networking utilities
apt-get install -y --no-install-recommends \
    hydra \
    nmap \
    netcat-traditional \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    gcc \
    mingw-w64 \
    dos2unix

# ------------------------------------------------------------------------------
# 2. Attack Simulation Workspace Directory Structure
# ------------------------------------------------------------------------------
echo "[+] Creating AegisRange attack workspace directories..."
mkdir -p /opt/aegisrange/attacks/scenario1-bruteforce
mkdir -p /opt/aegisrange/attacks/scenario2-malicious-exec
mkdir -p /opt/aegisrange/payloads
mkdir -p /opt/aegisrange/wordlists

# ------------------------------------------------------------------------------
# 3. Benign Payload Compilation (Scenario 2 - Malicious Execution Simulation)
# ------------------------------------------------------------------------------
echo "[+] Creating benign test payload source code..."

# This benign program simulates an adversary payload by printing a banner,
# writing a harmless marker file, and exiting safely.
cat > /opt/aegisrange/payloads/payload.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("====================================================\n");
    printf("[!] AegisRange: Controlled Simulation Payload Executed\n");
    printf("[!] Event ID 1 (Process Creation) & Sysmon Telemetry Triggered\n");
    printf("====================================================\n");
    return 0;
}
EOF

echo "[+] Compiling benign payload binaries..."
# Compile Windows Portable Executable (PE) using cross-compiler
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[+] Compiling 64-bit Windows PE executable (payload.exe)..."
    x86_64-w64-mingw32-gcc /opt/aegisrange/payloads/payload.c -o /opt/aegisrange/payloads/payload.exe
else
    echo "[-] mingw-w64 not found, falling back to native gcc..."
    gcc /opt/aegisrange/payloads/payload.c -o /opt/aegisrange/payloads/payload.exe
fi

# Also compile native Linux ELF binary
gcc /opt/aegisrange/payloads/payload.c -o /opt/aegisrange/payloads/payload.bin
chmod +x /opt/aegisrange/payloads/payload.bin

# ------------------------------------------------------------------------------
# 4. Scenario Helper Wordlists
# ------------------------------------------------------------------------------
echo "[+] Creating curated small wordlists for rapid lab testing..."
cat > /opt/aegisrange/wordlists/usernames.txt << 'EOF'
root
admin
labuser
guest
test
user
service
EOF

cat > /opt/aegisrange/wordlists/passwords.txt << 'EOF'
123456
password
admin2024
labpass123
root123
letmein
qwerty
football
welcome
EOF

# Ensure permissions
chmod -R 755 /opt/aegisrange

echo "[+] AegisRange Kali attacker provisioning complete."
