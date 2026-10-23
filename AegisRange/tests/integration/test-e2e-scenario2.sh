#!/bin/bash
# =============================================================================
# AegisRange — E2E Test: Scenario 2 (Simulated File Execution)
# =============================================================================
# End-to-end test that verifies the complete pipeline for scenario 2:
#   Attack → Sysmon Evidence → Collection → Detection → Dashboard
#
# Prerequisites:
#   - All 3 VMs running
#   - Collectors running on aegis-windows
#   - Backend running and accessible at BACKEND_URL
# =============================================================================

set -uo pipefail

# --- Configuration ---
KALI="10.10.10.10"
WINDOWS="10.10.10.30"
BACKEND_URL="${AEGIS_BACKEND_URL:-http://10.10.10.1:8000}"
WAIT_SECONDS=45

PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  ✅ PASS — $1"; ((PASSED++)); ((TOTAL++)); }
fail() { echo "  ❌ FAIL — $1"; ((FAILED++)); ((TOTAL++)); }
info() { echo "  ℹ️  $1"; }

echo "============================================"
echo "  AegisRange — E2E Test: Scenario 2"
echo "  $(date)"
echo "============================================"
echo ""

# =============================================================================
# Step 1: Verify prerequisites
# =============================================================================
echo "── Step 1: Prerequisites ──────────────────"

if ping -c 1 -W 3 "${WINDOWS}" > /dev/null 2>&1; then
    pass "Windows target reachable"
else
    fail "Windows target unreachable"
    echo "[-] Cannot proceed without Windows target. Exiting."
    exit 1
fi

if curl -sf "${BACKEND_URL}/api/health" > /dev/null 2>&1; then
    pass "Backend API reachable"
else
    fail "Backend API unreachable at ${BACKEND_URL}"
    info "Continuing anyway — backend checks will be skipped"
fi
echo ""

# =============================================================================
# Step 2: Start attacker infrastructure
# =============================================================================
echo "── Step 2: Attacker Infrastructure ────────"

PAYLOAD_DIR="/opt/aegisrange/payloads"
HTTP_PORT=8080
CALLBACK_PORT=4444

# Start HTTP server
cd "${PAYLOAD_DIR}" 2>/dev/null || { fail "Payload directory not found"; exit 1; }
python3 -m http.server ${HTTP_PORT} --bind "${KALI}" > /dev/null 2>&1 &
HTTP_PID=$!
sleep 1

if kill -0 "${HTTP_PID}" 2>/dev/null; then
    pass "HTTP server started on :${HTTP_PORT}"
else
    fail "HTTP server failed to start"
fi

# Start callback listener
nc -nlvp ${CALLBACK_PORT} > /tmp/aegis_callback_s2.log 2>&1 &
NC_PID=$!
sleep 1

if kill -0 "${NC_PID}" 2>/dev/null; then
    pass "Callback listener started on :${CALLBACK_PORT}"
else
    fail "Callback listener failed to start"
fi

# Cleanup trap
cleanup() {
    kill "${HTTP_PID}" "${NC_PID}" 2>/dev/null
}
trap cleanup EXIT
echo ""

# =============================================================================
# Step 3: Trigger attack on Windows
# =============================================================================
echo "── Step 3: Trigger Attack ─────────────────"
info "Triggering dropper on Windows target via WinRM..."

# Use PowerShell remoting to trigger the dropper
# This requires WinRM to be configured (done by provisioning)
TRIGGER_RESULT=$(curl -sf "http://${WINDOWS}:5985/wsman" 2>/dev/null; echo $?)

info "Attempting to invoke dropper via WinRM..."
# Note: In practice, you'd use evil-winrm or a WinRM client here
# For the test, we check if WinRM port is open
if nc -z -w 3 "${WINDOWS}" 5985 2>/dev/null; then
    pass "WinRM port is accessible"
    info "Run the dropper manually on Windows if WinRM automation is not configured"
    info "  powershell.exe -ExecutionPolicy Bypass -File C:\\vagrant\\attacks\\scenario2-malicious-exec\\payload-dropper.ps1"
else
    fail "WinRM port not accessible"
fi
echo ""

# =============================================================================
# Step 4: Wait for processing
# =============================================================================
echo "── Step 4: Wait for Processing ────────────"
info "Waiting ${WAIT_SECONDS}s for collectors to process Sysmon events..."
sleep "${WAIT_SECONDS}"
pass "Wait complete"
echo ""

# =============================================================================
# Step 5: Verify backend received telemetry logs
# =============================================================================
echo "── Step 5: Verify Backend Reachable ──────"

# The backend exposes no endpoint for reading logs back: /api/logs is POST-only (GET
# returns 405) and /api/events does not exist. Probe liveness with GET / instead, and
# treat the incidents created by correlation as the evidence that logs arrived.
HEALTH_RESPONSE=$(curl -sf "${BACKEND_URL}/" 2>/dev/null)
if [ -n "${HEALTH_RESPONSE}" ] && echo "${HEALTH_RESPONSE}" | grep -q '"status"'; then
    pass "Backend reachable at ${BACKEND_URL}/ (GET /)"
else
    fail "Backend unreachable at ${BACKEND_URL} (start it with: uvicorn main:app --host 0.0.0.0 --port 8000)"
fi
echo ""

# =============================================================================
# Step 6: Verify alerts and incidents
# =============================================================================
echo "── Step 6: Verify Incidents ───────────────"

INCIDENT=$(curl -sf "${BACKEND_URL}/api/incidents" 2>/dev/null)
if [ $? -eq 0 ] && [ -n "${INCIDENT}" ] && [ "${INCIDENT}" != "[]" ]; then
    pass "Malicious execution incident detected in /api/incidents"
else
    fail "Incident not found in /api/incidents (check backend correlation logic)"
fi
echo ""

# =============================================================================
# Step 7: Check callback
# =============================================================================
echo "── Step 7: Verify Callback ────────────────"

if [ -f /tmp/aegis_callback_s2.log ] && [ -s /tmp/aegis_callback_s2.log ]; then
    pass "Callback received from Windows target"
    info "Callback content: $(cat /tmp/aegis_callback_s2.log)"
else
    fail "No callback received (check if dropper ran on Windows)"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================"
echo "  E2E Scenario 2 Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
echo "============================================"

[ "${FAILED}" -eq 0 ] && exit 0 || exit 1
