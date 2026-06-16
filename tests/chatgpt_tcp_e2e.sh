#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/target/release/sniproxy-ng"

LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8443}"
UPSTREAM_HOST="${UPSTREAM_HOST:-example.com}"
UPSTREAM_URL="${UPSTREAM_URL:-https://example.com/}"
SOCKS5_ADDR="${SOCKS5_ADDR:-127.0.0.1:10800}"
MAX_TIME="${MAX_TIME:-20}"

OUT_DIR="${OUT_DIR:-$ROOT_DIR/tests/.out/chatgpt_tcp_e2e}"
SERVER_LOG="$OUT_DIR/sniproxy-ng.log"
PRECHECK_LOG="$OUT_DIR/curl.socks5-precheck.log"
CURL_LOG="$OUT_DIR/curl.sniproxy.log"
CONFIG_DIR="$OUT_DIR/runtime"
CONFIG="$CONFIG_DIR/config.toml"

die() {
  echo "[FAIL] $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

require_cmd cargo
require_cmd curl

mkdir -p "$OUT_DIR" "$CONFIG_DIR"
rm -f "$SERVER_LOG" "$PRECHECK_LOG" "$CURL_LOG"

echo "[RUN] precheck SOCKS5 backend: curl --socks5-hostname $SOCKS5_ADDR $UPSTREAM_URL"
set +e
curl -sSL \
  --socks5-hostname "$SOCKS5_ADDR" \
  --no-progress-meter \
  --max-time "$MAX_TIME" \
  -o /dev/null \
  -w '%{http_code}\n' \
  "$UPSTREAM_URL" >"$PRECHECK_LOG" 2>&1
precheck_rc=$?
set -e

if [[ $precheck_rc -ne 0 ]]; then
  echo "==== SOCKS5 precheck output ====" >&2
  sed -n '1,200p' "$PRECHECK_LOG" >&2 || true
  die "SOCKS5 backend is not usable (exit=$precheck_rc): socks5h://$SOCKS5_ADDR"
fi

if [[ "$(tail -n 1 "$PRECHECK_LOG" | tr -d '\r')" != "200" ]]; then
  echo "==== SOCKS5 precheck output ====" >&2
  sed -n '1,200p' "$PRECHECK_LOG" >&2 || true
  die "SOCKS5 backend did not return HTTP 200"
fi

cat >"$CONFIG" <<EOF
[server]
listen_https_addr = "$LISTEN_ADDR"
log_level = "debug"
log_format = "pretty"

[socks5]
addr = "$SOCKS5_ADDR"
timeout = $MAX_TIME
max_connections = 100

[rules]
allow = ["$UPSTREAM_HOST"]
EOF

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release
fi

[[ -x "$BIN" ]] || die "binary not found/executable: $BIN"

(
  cd "$CONFIG_DIR"
  RUST_LOG="${RUST_LOG:-debug}" "$BIN"
) >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

deadline=$((SECONDS + 10))
until grep -q "TCP proxy server listening on $LISTEN_ADDR" "$SERVER_LOG"; do
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "==== sniproxy-ng log ====" >&2
    sed -n '1,240p' "$SERVER_LOG" >&2 || true
    die "sniproxy-ng exited early"
  fi
  if (( SECONDS > deadline )); then
    echo "==== sniproxy-ng log ====" >&2
    sed -n '1,240p' "$SERVER_LOG" >&2 || true
    die "sniproxy-ng not ready after 10s"
  fi
  sleep 0.1
done

echo "[RUN] curl --connect-to $UPSTREAM_HOST:443:$LISTEN_ADDR $UPSTREAM_URL"
set +e
curl -vi \
  --connect-to "$UPSTREAM_HOST:443:$LISTEN_ADDR" \
  --no-progress-meter \
  --max-time "$MAX_TIME" \
  -o /dev/null \
  "$UPSTREAM_URL" >"$CURL_LOG" 2>&1
curl_rc=$?
set -e

if [[ $curl_rc -ne 0 ]]; then
  echo "==== curl output ====" >&2
  sed -n '1,240p' "$CURL_LOG" >&2 || true
  echo "==== sniproxy-ng log ====" >&2
  sed -n '1,240p' "$SERVER_LOG" >&2 || true
  die "curl via sniproxy-ng failed (exit=$curl_rc)"
fi

if ! tr -d '\r' <"$CURL_LOG" | grep -E '^< HTTP/[0-9.]+ 200' >/dev/null; then
  echo "==== curl output ====" >&2
  sed -n '1,240p' "$CURL_LOG" >&2 || true
  die "missing HTTP 200 response line"
fi

if ! grep -q "Extracted SNI: $UPSTREAM_HOST" "$SERVER_LOG"; then
  echo "==== sniproxy-ng log ====" >&2
  sed -n '1,240p' "$SERVER_LOG" >&2 || true
  die "sniproxy-ng did not log extracted SNI: $UPSTREAM_HOST"
fi

echo "[PASS] fetched $UPSTREAM_URL via sniproxy-ng TCP SNI proxy on $LISTEN_ADDR"
