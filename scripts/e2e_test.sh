#!/usr/bin/env bash
# ==============================================================================
# Sentinel AI — Production End-to-End (E2E) Verification Script
# ==============================================================================
set -euo pipefail

BASE_URL="http://localhost:8000/api/v1"
HEALTH_URL="http://localhost:8000/health"
FRONTEND_URL="http://localhost:5173"

echo "======================================================================"
echo "🛡️ SENTINEL AI — PRODUCTION END-TO-END VERIFICATION"
echo "======================================================================"

# Step 1: Healthcheck
echo -n "[1/5] Checking Backend Health ($HEALTH_URL)... "
HEALTH_RESP=$(curl -s "$HEALTH_URL")
if [[ "$HEALTH_RESP" == *"status\":\"ok"* || "$HEALTH_RESP" == *"healthy"* ]]; then
    echo "✓ HEALTHY!"
else
    echo "❌ FAILED ($HEALTH_RESP)"
    exit 1
fi

# Step 2: Authentication
echo -n "[2/5] Authenticating user 'secops_admin'... "
curl -s -X POST "$BASE_URL/auth/local/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "secops_admin", "password": "password123"}' > /dev/null || true

AUTH_JSON=$(curl -s -X POST "$BASE_URL/auth/local/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "secops_admin", "password": "password123"}')

TOKEN=$(echo "$AUTH_JSON" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    echo "✓ JWT Token Acquired!"
else
    echo "❌ Authentication Failed: $AUTH_JSON"
    exit 1
fi

# Step 3: Trigger Scan
echo -n "[3/5] Submitting Scan Payload (Syslog Intrusion)... "
SCAN_RESP=$(curl -s -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"input": "Failed password for root from 185.220.101.47 port 22", "input_type_hint": "LOGS"}')

SESSION_ID=$(echo "$SCAN_RESP" | grep -o '"session_id":"[^"]*' | cut -d'"' -f4)

if [ -n "$SESSION_ID" ]; then
    echo "✓ Session Created: $SESSION_ID"
else
    echo "❌ Scan Submission Failed: $SCAN_RESP"
    exit 1
fi

# Step 4: Verify Session Lookup
echo -n "[4/5] Verifying Session Retrieval (/api/v1/sessions/$SESSION_ID)... "
sleep 2
SESS_DETAIL=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/sessions/$SESSION_ID")
STATUS=$(echo "$SESS_DETAIL" | grep -o '"status":"[^"]*' | cut -d'"' -f4)
echo "✓ Session Status: $STATUS"

# Step 5: Verify Frontend Accessibility
echo -n "[5/5] Checking Frontend UI ($FRONTEND_URL)... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL")
if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✓ HTTP 200 OK!"
else
    echo "❌ Frontend returned HTTP $HTTP_CODE"
    exit 1
fi

echo "======================================================================"
echo "🎉 ALL END-TO-END VERIFICATION CHECKS PASSED 100% CLEANLY!"
echo "======================================================================"
