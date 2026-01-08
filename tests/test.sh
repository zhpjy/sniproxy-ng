#!/usr/bin/env bash
set -euo pipefail

FAILED=0

TEST_HOST=ifconfig.me
PROXY_HOST=127.0.0.1
HTTP_PORT=8080
HTTPS_PORT=8443
TIMEOUT=10

run_test() {
    local name="$1"
    local url="$2"
    local args="${3:-}"

    echo "[TEST] $name"
    if output=$(curl -sS --max-time "$TIMEOUT" $args "$url" 2>&1); then
        echo "[PASS] $name → IP: $output"
        return 0
    else
        echo "[FAIL] $name"
        echo "$output"
        return 1
    fi
}

echo "==========================================="
echo "  sniproxy-ng Proxy Test"
echo "==========================================="
echo

echo "[TEST] Local IP (no proxy)"
if local_ip=$(curl -sS --max-time "$TIMEOUT" "$TEST_HOST" 2>&1); then
    echo "[PASS] Local IP: $local_ip"
else
    echo "[FAIL] Failed to get local IP"
    ((FAILED++))
fi
echo

run_test "HTTP/3 via proxy" \
    "https://$TEST_HOST" \
    "--http3 --connect-to $TEST_HOST:443:$PROXY_HOST:$HTTPS_PORT" || ((FAILED++))
echo

run_test "HTTPS via proxy" \
    "https://$TEST_HOST" \
    "--connect-to $TEST_HOST:443:$PROXY_HOST:$HTTPS_PORT" || ((FAILED++))
echo

run_test "HTTP via proxy" \
    "http://$TEST_HOST" \
    "--connect-to $TEST_HOST:80:$PROXY_HOST:$HTTP_PORT" || ((FAILED++))
echo

echo "==========================================="
if [[ $FAILED -eq 0 ]]; then
    echo "All tests passed!"
    exit 0
else
    echo "$FAILED test(s) failed"
    exit 1
fi
