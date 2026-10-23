#!/bin/bash
# =============================================================================
# AegisRange — Smoke Test: VM Connectivity & Service Availability
# =============================================================================
# Verifies that all 3 VMs are running, reachable, and have expected services.
# Run from the host machine or from any VM within the lab network.
# =============================================================================

set -uo pipefail

# --- Configuration ---
KALI="10.10.10.10"
LINUX="10.10.10.20"
WINDOWS="10.10.10.30"

PASSED=0
FAILED=0
TOTAL=0

# --- Helper functions ---
pass() {
    echo "  ✅ PASS — $1"
    ((PASSED++))
    ((TOTAL++))
}

fail() {
    echo "  ❌ FAIL — $1"
    ((FAILED++))
    ((TOTAL++))
}

test_ping() {
    local name="$1" ip="$2"
    if ping -c 1 -W 3 "${ip}" > /dev/null 2>&1; then
        pass "Ping ${name} (${ip})"
    else
        fail "Ping ${name} (${ip}) — host unreachable"
    fi
}

test_port() {
    local name="$1" ip="$2" port="$3"
    if nc -z -w 3 "${ip}" "${port}" 2>/dev/null; then
        pass "${name} (${ip}:${port})"
    else
        fail "${name} (${ip}:${port}) — port not open"
    fi
}

test_no_internet() {
    local name="$1" ip="$2"
    # Try to reach an external IP from the target
    # This test should be run FROM the target VM, so we skip if running from host
    echo "  ℹ️  SKIP — Internet isolation test for ${name} (run from within the VM)"
}

# =============================================================================
echo "============================================"
echo "  AegisRange — Smoke Test"
echo "  $(date)"
echo "============================================"
echo ""

# --- Ping Tests ---
echo "── Ping Tests ──────────────────────────────"
test_ping "Kali (Attacker)" "${KALI}"
test_ping "Linux (Target)" "${LINUX}"
test_ping "Windows (Target)" "${WINDOWS}"
echo ""

# --- Service Availability ---
echo "── Service Availability ─────────────────────"
test_port "Linux SSH"      "${LINUX}"   22
test_port "Linux FTP"      "${LINUX}"   21
test_port "Windows WinRM"  "${WINDOWS}" 5985
echo ""

# --- Cross-VM Connectivity ---
echo "── Cross-VM Connectivity ─────────────────────"
# Verify Kali can reach both targets (run this section from Kali)
test_port "Kali → Linux SSH"     "${LINUX}"   22
test_port "Kali → Windows WinRM" "${WINDOWS}" 5985
echo ""

# --- Internet Isolation ---
echo "── Internet Isolation ─────────────────────"
echo "  ℹ️  Run the following manually from each target VM:"
echo "     ping -c 1 -W 3 8.8.8.8"
echo "     (Expected: 100% packet loss = PASS)"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================"
echo "  Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
echo "============================================"

if [ "${FAILED}" -eq 0 ]; then
    echo "  🎉 All tests passed! Lab is ready."
    exit 0
else
    echo "  ⚠️  Some tests failed. Check VM status with: vagrant status"
    exit 1
fi
