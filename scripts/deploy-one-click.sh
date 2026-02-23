#!/usr/bin/env bash
set -euo pipefail

# One-command wrapper around deploy-remote.sh.
# Usage:
#   bash scripts/deploy-one-click.sh [domain] [port]
#   bash scripts/deploy-one-click.sh --port <number> [--skip-nginx]
# Examples:
#   bash scripts/deploy-one-click.sh
#   bash scripts/deploy-one-click.sh www.example.com
#   bash scripts/deploy-one-click.sh --port 18890 --skip-nginx

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

APP_DIR="${APP_DIR:-/opt/remote-codexapp}"
DOMAIN="${DOMAIN:-}"
NGINX_PATH="${NGINX_PATH:-/codex}"
APP_PORT="${APP_PORT:-18888}"
APP_HOST="${APP_HOST:-}"
HTTP_PROXY_VAL="${HTTP_PROXY_VAL:-${HTTP_PROXY:-}}"
HTTPS_PROXY_VAL="${HTTPS_PROXY_VAL:-${HTTPS_PROXY:-}}"
SOCKS5_PROXY_VAL="${SOCKS5_PROXY_VAL:-${SOCKS5_PROXY:-}}"
ALL_PROXY_VAL="${ALL_PROXY_VAL:-${ALL_PROXY:-}}"
NO_PROXY_VAL="${NO_PROXY_VAL:-${NO_PROXY:-}}"
REPO_URL="${REPO_URL:-git@github.com:JasonShui716/remote-codexapp.git}"
GIT_BRANCH="${GIT_BRANCH:-}"
APP_USER="${APP_USER:-${SUDO_USER:-$(id -un)}}"
SKIP_NGINX="${SKIP_NGINX:-0}"
SKIP_SERVICE="${SKIP_SERVICE:-0}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [domain] [port] [options]

Options:
  --domain <name>    Set domain explicitly
  --host <addr>      Set backend bind host (APP_HOST), e.g. 0.0.0.0
  --port <number>    Set backend port (APP_PORT)
  --http-proxy <url> Set HTTP proxy
  --https-proxy <url> Set HTTPS proxy
  --socks5-proxy <url> Set SOCKS5 proxy
  --sock5-proxy <url>  Alias of --socks5-proxy
  --all-proxy <url>  Set ALL_PROXY
  --no-proxy <list>  Set NO_PROXY
  --skip-nginx       Skip nginx config/reload (for no-domain direct port access)
  --skip-service     Skip systemd service install/restart
  -h, --help         Show help

Examples:
  bash scripts/deploy-one-click.sh
  bash scripts/deploy-one-click.sh your.domain.com
  bash scripts/deploy-one-click.sh your.domain.com 18890
  bash scripts/deploy-one-click.sh --host 0.0.0.0 --port 18890 --skip-nginx
EOF
}

POSITIONALS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --port)
      APP_PORT="$2"
      shift 2
      ;;
    --host)
      APP_HOST="$2"
      shift 2
      ;;
    --skip-nginx)
      SKIP_NGINX=1
      shift
      ;;
    --http-proxy)
      HTTP_PROXY_VAL="$2"
      shift 2
      ;;
    --https-proxy)
      HTTPS_PROXY_VAL="$2"
      shift 2
      ;;
    --socks5-proxy|--sock5-proxy)
      SOCKS5_PROXY_VAL="$2"
      shift 2
      ;;
    --all-proxy)
      ALL_PROXY_VAL="$2"
      shift 2
      ;;
    --no-proxy)
      NO_PROXY_VAL="$2"
      shift 2
      ;;
    --skip-service)
      SKIP_SERVICE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      POSITIONALS+=("$1")
      shift
      ;;
  esac
done

if [[ "${#POSITIONALS[@]}" -gt 2 ]]; then
  echo "Too many positional arguments." >&2
  usage
  exit 1
fi

if [[ "${#POSITIONALS[@]}" -ge 1 ]]; then
  if [[ -z "${DOMAIN}" && ! "${POSITIONALS[0]}" =~ ^[0-9]+$ ]]; then
    DOMAIN="${POSITIONALS[0]}"
  else
    APP_PORT="${POSITIONALS[0]}"
  fi
fi

if [[ "${#POSITIONALS[@]}" -eq 2 ]]; then
  APP_PORT="${POSITIONALS[1]}"
fi

if [[ ! "${APP_PORT}" =~ ^[0-9]+$ ]]; then
  echo "APP_PORT must be numeric: ${APP_PORT}" >&2
  exit 1
fi

echo "[deploy-one-click] APP_DIR=${APP_DIR}"
echo "[deploy-one-click] DOMAIN=${DOMAIN:-<interactive>}"
echo "[deploy-one-click] NGINX_PATH=${NGINX_PATH}"
echo "[deploy-one-click] APP_HOST=${APP_HOST:-<default>}"
echo "[deploy-one-click] APP_PORT=${APP_PORT}"
echo "[deploy-one-click] HTTP_PROXY=${HTTP_PROXY_VAL:+<set>} HTTPS_PROXY=${HTTPS_PROXY_VAL:+<set>} SOCKS5_PROXY=${SOCKS5_PROXY_VAL:+<set>} ALL_PROXY=${ALL_PROXY_VAL:+<set>} NO_PROXY=${NO_PROXY_VAL:+<set>}"
echo "[deploy-one-click] GIT_BRANCH=${GIT_BRANCH:-<auto>}"
echo "[deploy-one-click] APP_USER=${APP_USER}"
echo "[deploy-one-click] SKIP_NGINX=${SKIP_NGINX} SKIP_SERVICE=${SKIP_SERVICE}"

run_deploy() {
  env \
    APP_DIR="${APP_DIR}" \
    DOMAIN="${DOMAIN}" \
    NGINX_PATH="${NGINX_PATH}" \
    APP_HOST="${APP_HOST}" \
    APP_PORT="${APP_PORT}" \
    HTTP_PROXY_VAL="${HTTP_PROXY_VAL}" \
    HTTPS_PROXY_VAL="${HTTPS_PROXY_VAL}" \
    SOCKS5_PROXY_VAL="${SOCKS5_PROXY_VAL}" \
    ALL_PROXY_VAL="${ALL_PROXY_VAL}" \
    NO_PROXY_VAL="${NO_PROXY_VAL}" \
    REPO_URL="${REPO_URL}" \
    GIT_BRANCH="${GIT_BRANCH}" \
    APP_USER="${APP_USER}" \
    SKIP_NGINX="${SKIP_NGINX}" \
    SKIP_SERVICE="${SKIP_SERVICE}" \
    bash "${ROOT_DIR}/scripts/deploy-remote.sh"
}

run_deploy
