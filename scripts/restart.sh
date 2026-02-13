#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${CODEREMOTEAPP_LOG:-/tmp/codex_remoteapp.log}"
PORT="18888"

if [[ -f "$ROOT_DIR/server/.env" ]]; then
  ENV_PORT="$(awk -F= '$1=="PORT" { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); if ($2 ~ /^[0-9]+$/) print $2; exit }' "$ROOT_DIR/server/.env")"
  if [[ -n "$ENV_PORT" ]]; then
    PORT="$ENV_PORT"
  fi
fi

if ! command -v lsof >/dev/null 2>&1; then
  echo "lsof is required for restart script" >&2
  exit 1
fi

PIDS="$(lsof -tiTCP:${PORT} -sTCP:LISTEN -P -n || true)"
if [[ -n "${PIDS}" ]]; then
  echo "Stopping existing process(es) on :${PORT}: ${PIDS}"
  kill ${PIDS} || true
  sleep 1
  PIDS_REMAIN="$(lsof -tiTCP:${PORT} -sTCP:LISTEN -P -n || true)"
  if [[ -n "${PIDS_REMAIN}" ]]; then
    kill -9 ${PIDS_REMAIN} || true
  fi
else
  echo "No process found on :${PORT}"
fi

(
  cd "$ROOT_DIR"
  setsid npm start >"$LOG_FILE" 2>&1 < /dev/null &
  APP_PID=$!
  echo "$APP_PID" > "$ROOT_DIR/.codex_remoteapp.pid"
  echo "Started codex-remoteapp in background (PID: $APP_PID)"
  echo "Log file: $LOG_FILE"
  echo "Open: http://127.0.0.1:${PORT}"
)
