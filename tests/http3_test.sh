#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/target/release/sniproxy-ng"
CONFIG="$ROOT_DIR/config.toml"

LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8443}"
UPSTREAM_HOST="${UPSTREAM_HOST:-quic.nginx.org}"
UPSTREAM_URL="${UPSTREAM_URL:-https://quic.nginx.org/}"
MAX_TIME="${MAX_TIME:-15}"

OUT_DIR="${OUT_DIR:-$ROOT_DIR/tests/.out}"
mkdir -p "$OUT_DIR"
SERVER_LOG="$OUT_DIR/sniproxy-ng.http3_google.log"
CURL_LOG="$OUT_DIR/curl.http3_google.log"

die() {
  echo "[FAIL] $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_cmd cargo
require_cmd curl

if [[ ! -f "$CONFIG" ]]; then
  die "missing $CONFIG (你说会准备好). 需要包含 listen_https_addr=127.0.0.1:8443 + socks5.addr"
fi

if ! curl --version 2>/dev/null | grep -q "HTTP3"; then
  die "curl does not support HTTP/3 (curl --version does not include HTTP3)"
fi

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release
fi

if [[ ! -x "$BIN" ]]; then
  die "binary not found/executable: $BIN (try: cargo build --release)"
fi

rm -f "$SERVER_LOG" "$CURL_LOG"

(
  cd "$ROOT_DIR"
  # 如果本机 DNS 被污染，QUIC 侧需要一个“可信 DNS”来把 SNI 解析成真实 ip:443
  # 可覆盖：SNIPROXY_DNS_SERVER=8.8.8.8:53
  SNIPROXY_DNS_SERVER="${SNIPROXY_DNS_SERVER:-1.1.1.1:53}" \
  RUST_LOG="${RUST_LOG:-info}" "$BIN"
) >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

# Wait until server binds UDP socket (log-based readiness, avoids ss/netstat deps)
deadline=$((SECONDS + 10))
until grep -q "UDP socket bound to" "$SERVER_LOG"; do
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "==== sniproxy-ng log ====" >&2
    sed -n '1,200p' "$SERVER_LOG" >&2 || true
    die "sniproxy-ng exited early"
  fi
  if (( SECONDS > deadline )); then
    echo "==== sniproxy-ng log (tail) ====" >&2
    sed -n '1,200p' "$SERVER_LOG" >&2 || true
    die "sniproxy-ng not ready after 10s (did not log UDP bind)"
  fi
  sleep 0.1
done

echo "[RUN] curl -vi --http3-only $UPSTREAM_URL --connect-to $UPSTREAM_HOST:443:${LISTEN_ADDR}"
set +e
curl -vi \
  --http3-only \
  --no-progress-meter \
  --max-time "$MAX_TIME" \
  --connect-to "$UPSTREAM_HOST:443:${LISTEN_ADDR}" \
  "$UPSTREAM_URL" >"$CURL_LOG" 2>&1
curl_rc=$?
set -e

if [[ $curl_rc -ne 0 ]]; then
  echo "==== curl output ====" >&2
  sed -n '1,200p' "$CURL_LOG" >&2 || true
  echo "==== sniproxy-ng log ====" >&2
  sed -n '1,200p' "$SERVER_LOG" >&2 || true
  die "curl failed (exit=$curl_rc)"
fi

# Assert actually negotiated/used HTTP/3 (output varies by curl build)
if ! tr -d '\r' <"$CURL_LOG" | grep -Ei '^\* (Using HTTP3|Using HTTP/3|ALPN: h3)' >/dev/null 2>&1; then
  echo "==== curl output ====" >&2
  sed -n '1,200p' "$CURL_LOG" >&2 || true
  die "curl output does not show HTTP/3 usage (expected '* Using HTTP3' or '* ALPN: h3')"
fi

# Assert HTTP/3 response status line exists
if ! tr -d '\r' <"$CURL_LOG" | grep -E '^< HTTP/3 (2|3)[0-9]{2}' >/dev/null 2>&1; then
  echo "==== curl output ====" >&2
  sed -n '1,200p' "$CURL_LOG" >&2 || true
  die "missing HTTP/3 2xx/3xx response line ('< HTTP/3 2xx/3xx')"
fi

echo "[PASS] got HTTP/3 response via sniproxy-ng"
