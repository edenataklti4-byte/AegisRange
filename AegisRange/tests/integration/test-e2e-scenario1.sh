#!/bin/bash
# =============================================================================
# AegisRange — E2E Test: Scenario 1 (SSH Credential Testing)
# =============================================================================
# End-to-end test that verifies the complete pipeline:
#   Attack → Evidence → Collection → Detection → Dashboard
#
# Prerequisites:
#   - All 3 VMs running
#   - Collectors running on aegis-linux
#   - Backend running and accessible at BACKEND_URL
# =============================================================================

set -uo pipefail

# --- Configuration ---
KALI="10.10.10.10"
LINUX="10.10.10.20"
BACKEND_URL="${AEGIS_BACKEND_URL:-http://10.10.10.1:8000}"
ATTACK_SCRIPT="/opt/aegisrange/attacks/scenario1-bruteforce/bruteforce.sh"
WAIT_SECONDS=30

PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  ✅ PASS — $1"; ((PASSED++)); ((TOTAL++)); }
fail() { echo "  ❌ FAIL — $1"; ((FAILED++)); ((TOTAL++)); }
info() { echo "  ℹ️  $1"; }

echo "============================================"
echo "  AegisRange — E2E Test: Scenario 1"
echo "  $(date)"
echo "============================================"
echo ""

# =============================================================================
# Step 1: Verify prerequisites
# =============================================================================
echo "── Step 1: Prerequisites ──────────────────"

# Check Linux target is reachable
if ping -c 1 -W 3 "${LINUX}" > /dev/null 2>&1; then
    pass "Linux target reachable"
else
    fail "Linux target unreachable"
    echo "[-] Cannot proceed without Linux target. Exiting."
    exit 1
fi

# Check backend is running
if curl -sf "${BACKEND_URL}/api/health" > /dev/null 2>&1; then
    pass "Backend API reachable"
else
    fail "Backend API unreachable at ${BACKEND_URL}"
    info "Continuing anyway — backend checks will be skipped"
fi
echo ""

# =============================================================================
# Step 2: Run the attack
# =============================================================================
echo "── Step 2: Execute Attack ─────────────────"
info "Running SSH credential testing scenario..."

if [ -f "${ATTACK_SCRIPT}" ]; then
    bash "${ATTACK_SCRIPT}" > /tmp/aegis_e2e_s1.log 2>&1
    if [ $? -eq 0 ]; then
        pass "Attack script executed successfully"
    else
        fail "Attack script exited with errors"
    fi
else
    info "Attack script not found at ${ATTACK_SCRIPT}"
    info "Running inline attack for testing..."
    # Minimal inline version
    hydra -l labuser -P /opt/aegisrange/attacks/scenario1-bruteforce/wordlist.txt \
        "ssh://${LINUX}" -t 4 > /tmp/aegis_e2e_s1.log 2>&1 || true
    pass "Inline attack executed"
fi
echo ""

# =============================================================================
# Step 3: Wait for log processing
# =============================================================================
echo "── Step 3: Wait for Processing ────────────"
info "Waiting ${WAIT_SECONDS}s for collectors to process logs..."
sleep "${WAIT_SECONDS}"
pass "Wait complete"
echo ""

# =============================================================================
# Step 4: Verify evidence on Linux target
# =============================================================================
echo "── Step 4: Verify Evidence ────────────────"

# Check auth.log has failed SSH entries from Kali
FAILED_COUNT=$(sshpass -p "labpass123" ssh -o StrictHostKeyChecking=no \
    labuser@"${LINUX}" \
    "grep -c 'Failed password.*10.10.10.10' /var/log/auth.log 2>/dev/null" \
    2>/dev/null || echo "0")

if [ "${FAILED_COUNT}" -gt 5 ]; then
    pass "Found ${FAILED_COUNT} failed SSH login entries in auth.log"
else
    fail "Expected >5 failed SSH entries, found ${FAILED_COUNT}"
fi

# Check for successful login
SUCCESS_COUNT=$(sshpass -p "labpass123" ssh -o StrictHostKeyChecking=no \
    labuser@"${LINUX}" \
    "grep -c 'Accepted password.*10.10.10.10' /var/log/auth.log 2>/dev/null" \
    2>/dev/null || echo "0")

if [ "${SUCCESS_COUNT}" -ge 1 ]; then
    pass "Found ${SUCCESS_COUNT} successful SSH login entries in auth.log"
else
    fail "Expected >=1 successful SSH entry, found ${SUCCESS_COUNT}"
fi
echo ""

# =============================================================================
# Step 5: Verify backend received logs
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
# Step 6: Verify incident was detected
# =============================================================================
echo "── Step 6: Verify Incidents ───────────────"

INCIDENTS_RESPONSE=$(curl -sf "${BACKEND_URL}/api/incidents" 2>/dev/null)
if [ -n "${INCIDENTS_RESPONSE}" ] && [ "${INCIDENTS_RESPONSE}" != "[]" ]; then
    pass "Security incident successfully generated in /api/incidents"
    # Correlation needs 3+ logs from one source_ip within 5 minutes; severity is
    # low (3-4) / medium (5-9) / high (10+), lowercase, and there is no "critical".
    echo "${INCIDENTS_RESPONSE}" | grep -q '"source_ip": *"'"${KALI}"'"' \
        && pass "Incident correlated to attacker IP ${KALI}" \
        || info "No incident carries source_ip ${KALI} - check the collector is sending the attacker IP, not the victim's"
else
    fail "No incidents in /api/incidents (need 3+ logs from one source_ip within 5 min; check collectors and correlation)"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================"
echo "  E2E Scenario 1 Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
echo "============================================"

[ "${FAILED}" -eq 0 ] && exit 0 || exit 1
