#!/usr/bin/env bash
set -euo pipefail

REPO_URL_DEFAULT="git@github.com:JasonShui716/remote-codexapp.git"
REPO_URL="${REPO_URL_DEFAULT}"
GIT_BRANCH="${GIT_BRANCH:-}"
APP_DIR="${APP_DIR:-/opt/remote-codexapp}"
NGINX_PATH="${NGINX_PATH:-/codex}"
DOMAIN="${DOMAIN:-}"
APP_PORT="${APP_PORT:-18888}"
SERVICE_NAME="${SERVICE_NAME:-codex-remoteapp}"
APP_USER="${APP_USER:-${SUDO_USER:-$(id -un)}}"
APP_GROUP="${APP_GROUP:-${APP_USER}}"
SKIP_NGINX="${SKIP_NGINX:-0}"
SKIP_SERVICE="${SKIP_SERVICE:-0}"
ENSURE_ENV_ONLY="${ENSURE_ENV_ONLY:-0}"

SCRIPT_NAME="$(basename "$0")"

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Quick deploy + install:
  --repo <url>       Git repo URL (default: ${REPO_URL_DEFAULT})
  --dir <path>       App install directory (default: ${APP_DIR})
  --branch <name>    Git branch/tag (default: auto-detect remote HEAD, fallback: master)
  --domain <name>    Nginx server_name (default: prompt in interactive mode, _ for wildcard)
  --path <nginx>     Public app path, e.g. /codex (default: ${NGINX_PATH})
  --port <number>    Backend port (default: ${APP_PORT})
  --user <name>      Service run user (default: ${APP_USER})
  --skip-nginx       Skip nginx config/reload
  --skip-service     Skip systemd service install/restart
  --ensure-env-only  Only ensure server/.env values (generate TOTP_SECRET if missing), then exit
  -h, --help         Show help

Examples:
  $SCRIPT_NAME --repo ${REPO_URL_DEFAULT} --dir /opt/remote-codexapp --domain example.com
EOF
}

log() {
  echo "[deploy] $*"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command not found: $cmd" >&2
    exit 1
  fi
}

ensure_root_cmd() {
  if [[ "${EUID}" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      echo "please run as root, or install sudo for root-required steps" >&2
      exit 1
    fi
    SUDO="sudo"
  else
    SUDO=""
  fi
}

run_as_app_user() {
  if [[ "$(id -un)" == "${APP_USER}" ]]; then
    "$@"
    return
  fi

  if command -v sudo >/dev/null 2>&1; then
    sudo -u "${APP_USER}" -H "$@"
    return
  fi

  if command -v runuser >/dev/null 2>&1; then
    runuser -u "${APP_USER}" -- "$@"
    return
  fi

  su -s /bin/bash "${APP_USER}" -c "$(printf '%q ' "$@")"
}

detect_remote_default_branch() {
  local repo_url="$1"
  local head_ref
  head_ref="$(run_as_app_user git ls-remote --symref "$repo_url" HEAD 2>/dev/null | awk '/^ref:/ {print $2; exit}')"
  head_ref="${head_ref#refs/heads/}"
  if [[ -n "$head_ref" ]]; then
    printf '%s\n' "$head_ref"
    return 0
  fi
  return 1
}

ensure_env_value() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  if grep -q "^${key}=" "$env_file" 2>/dev/null; then
    sed -i "s|^${key}=.*$|${key}=${value}|" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$env_file"
  fi
}

read_env_value() {
  local env_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1==key {print substr($0, index($0, "=")+1); exit}' "$env_file" 2>/dev/null || true
}

generate_base32_secret() {
  # With `set -o pipefail`, `tr` can exit 141 (SIGPIPE) after `head` closes the pipe.
  # Disable pipefail for this pipeline so secret generation is reliable.
  (set +o pipefail; tr -dc 'A-Z2-7' </dev/urandom | head -c 32)
}

ensure_totp_secret_if_needed() {
  local env_file="$1"

  local secret
  secret="$(read_env_value "$env_file" "TOTP_SECRET")"
  if [[ -n "$secret" ]]; then
    return
  fi

  local generated
  generated="$(generate_base32_secret)"
  ensure_env_value "$env_file" "TOTP_SECRET" "$generated"
  log "Generated TOTP_SECRET (was missing/empty)."

  local marker_rel
  marker_rel="$(read_env_value "$env_file" "TOTP_PROVISION_FILE")"
  marker_rel="${marker_rel:-.totp_provisioned}"
  local marker_path
  if [[ "$marker_rel" = /* ]]; then
    marker_path="$marker_rel"
  else
    marker_path="$(cd "$(dirname "$env_file")" && pwd)/${marker_rel}"
  fi
  rm -f "$marker_path"
}

free_listeners_on_port() {
  local port="$1"
  if ! command -v lsof >/dev/null 2>&1; then
    return
  fi

  local pids
  pids="$(lsof -tiTCP:${port} -sTCP:LISTEN -P -n 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    return
  fi

  log "Stopping existing listener(s) on :${port}: ${pids}"
  kill ${pids} || true
  sleep 1
  local remain
  remain="$(lsof -tiTCP:${port} -sTCP:LISTEN -P -n 2>/dev/null || true)"
  if [[ -n "$remain" ]]; then
    kill -9 ${remain} || true
  fi
}

remove_existing_nginx_codex_bindings() {
  local dir="$1"
  local target="$2"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local current_conf

  if [[ ! -d "$dir" ]]; then
    return
  fi

  while IFS= read -r current_conf; do
    [[ -f "$current_conf" ]] || continue
    if grep -Fq "location ${target}" "$current_conf" ; then
      if [[ "$current_conf" == *"${SERVICE_NAME}.conf" ]]; then
        continue;
      fi
      log "Removing existing ${target} path binding in ${current_conf} (backup created)."
      ${SUDO:-} cp "$current_conf" "${current_conf}.bak.${ts}"
      ${SUDO:-} rm -f "$current_conf"
    fi
  done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null || true)
}

write_file_if_changed() {
  local dest="$1"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"

  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi

  ${SUDO:-} mkdir -p "$(dirname "$dest")"
  ${SUDO:-} tee "$dest" >/dev/null <"$tmp"
  rm -f "$tmp"
}

render_nginx_conf() {
  local host="$1"
  local path="$2"
  local port="$3"
  local timestamp
  timestamp="$(date +%Y%m%d_%H%M%S)"
  cat <<EOF
map \$http_upgrade \$connection_upgrade {
  default upgrade;
  '' close;
}

server {
  listen 80;
  server_name ${host};
  client_max_body_size 32m;

  location = ${path} {
    return 301 ${path}/;
  }

  location ${path}/ {
    rewrite ^${path}/(.*)$ /\$1 break;
    proxy_pass http://127.0.0.1:${port};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
  }
}

# Generated by scripts/deploy-remote.sh at ${timestamp}
EOF
}

render_systemd_unit() {
  local app_user="$1"
  local app_group="$2"
  local app_dir="$3"
  local env_file="$4"
  local service_path="$5"
  local npm_bin="$6"
  cat <<EOF
[Unit]
Description=Codex Remote App
After=network.target

[Service]
Type=simple
User=${app_user}
Group=${app_group}
WorkingDirectory=${app_dir}
EnvironmentFile=${env_file}
Environment=PATH=${service_path}
Restart=always
RestartSec=3
ExecStart=${npm_bin} start
StandardOutput=append:/var/log/${SERVICE_NAME}.log
StandardError=append:/var/log/${SERVICE_NAME}.error.log

[Install]
WantedBy=multi-user.target
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_URL="$2"
      shift 2
      ;;
    --dir)
      APP_DIR="$2"
      shift 2
      ;;
    --branch)
      GIT_BRANCH="$2"
      shift 2
      ;;
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --path)
      NGINX_PATH="$2"
      shift 2
      ;;
    --port)
      APP_PORT="$2"
      shift 2
      ;;
    --user)
      APP_USER="$2"
      APP_GROUP="$2"
      shift 2
      ;;
    --skip-nginx)
      SKIP_NGINX=1
      shift
      ;;
    --skip-service)
      SKIP_SERVICE=1
      shift
      ;;
    --ensure-env-only)
      ENSURE_ENV_ONLY=1
      SKIP_NGINX=1
      SKIP_SERVICE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! "${APP_PORT}" =~ ^[0-9]+$ ]]; then
  echo "port must be numeric: ${APP_PORT}" >&2
  exit 1
fi

if [[ "$SKIP_NGINX" != "1" && -z "${DOMAIN}" ]]; then
  if [[ -t 0 && -t 1 ]]; then
    read -r -p "Enter domain for nginx server_name (or blank for _): " domain_input
    DOMAIN="${domain_input:-_}"
  else
    echo "DOMAIN is required unless SKIP_NGINX=1" >&2
    exit 1
  fi
fi

if [[ "$ENSURE_ENV_ONLY" != "1" ]]; then
  require_cmd git
fi
if [[ "$SKIP_SERVICE" != "1" ]]; then
  require_cmd systemctl
fi
if [[ "$SKIP_NGINX" != "1" ]]; then
  require_cmd nginx
  require_cmd systemctl
fi

APP_DIR="${APP_DIR%/}"
ENV_FILE="${APP_DIR}/server/.env"

if [[ "$ENSURE_ENV_ONLY" == "1" ]]; then
  if [[ ! -f "${APP_DIR}/server/.env.example" ]]; then
    echo "Missing ${APP_DIR}/server/.env.example (APP_DIR must point at an existing checkout for --ensure-env-only)" >&2
    exit 1
  fi

  if [[ ! -f "$ENV_FILE" ]]; then
    cp "${APP_DIR}/server/.env.example" "$ENV_FILE"
  fi

  ensure_env_value "$ENV_FILE" "HOST" "127.0.0.1"
  ensure_env_value "$ENV_FILE" "PORT" "$APP_PORT"
  ensure_env_value "$ENV_FILE" "CODEX_CWD" "$APP_DIR"
  ensure_totp_secret_if_needed "$ENV_FILE"

  log "Ensured env file: $ENV_FILE"
  log "Done (ensure-env-only)."
  exit 0
fi

if ! id "${APP_USER}" >/dev/null 2>&1; then
  echo "Service/build user not found: ${APP_USER}" >&2
  exit 1
fi

if ! run_as_app_user bash -lc 'command -v npm >/dev/null 2>&1'; then
  echo "npm not found for user ${APP_USER}" >&2
  exit 1
fi

if [[ -z "${GIT_BRANCH}" ]]; then
  if GIT_BRANCH="$(detect_remote_default_branch "${REPO_URL}")"; then
    log "Detected remote default branch: ${GIT_BRANCH}"
  else
    GIT_BRANCH="master"
    log "Could not detect remote default branch; falling back to: ${GIT_BRANCH}"
  fi
fi

if [[ ! -d "${APP_DIR}" ]]; then
  ensure_root_cmd
  require_cmd install
  # Create with correct owner at creation time (avoid chown).
  ${SUDO:-} install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}"
fi

if [[ -d "${APP_DIR}/.git" ]]; then
  log "Updating existing checkout: $APP_DIR"
  run_as_app_user git -C "$APP_DIR" fetch --all --prune
  run_as_app_user git -C "$APP_DIR" checkout "$GIT_BRANCH"
  if run_as_app_user git -C "$APP_DIR" rev-parse --verify "origin/${GIT_BRANCH}" >/dev/null 2>&1; then
    run_as_app_user git -C "$APP_DIR" pull --ff-only "origin" "$GIT_BRANCH"
  fi
else
  log "Cloning ${REPO_URL} to ${APP_DIR}"
  if [[ -n "$(find "${APP_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null || true)" ]]; then
    echo "target app dir is not empty and is not a git checkout: ${APP_DIR}" >&2
    exit 1
  fi
  run_as_app_user git clone --depth 1 --branch "$GIT_BRANCH" "$REPO_URL" "$APP_DIR"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$APP_DIR/server/.env.example" "$ENV_FILE"
fi

ensure_env_value "$ENV_FILE" "HOST" "127.0.0.1"
ensure_env_value "$ENV_FILE" "PORT" "$APP_PORT"
ensure_env_value "$ENV_FILE" "CODEX_CWD" "$APP_DIR"
ensure_totp_secret_if_needed "$ENV_FILE"

log "Installing dependencies and building web bundle"
run_as_app_user bash -lc "cd '$APP_DIR' && npm install && npm run build"

if [[ "$SKIP_SERVICE" != "1" ]]; then
  ensure_root_cmd
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  NPM_BIN="$(run_as_app_user bash -lc 'command -v npm')"
  NODE_BIN="$(run_as_app_user bash -lc 'command -v node')"
  NODE_BIN_DIR="$(dirname "${NODE_BIN}")"
  SERVICE_PATH="${NODE_BIN_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  if [[ -z "${NPM_BIN}" ]]; then
    echo "npm not found for user ${APP_USER}" >&2
    exit 1
  fi
  if [[ -z "${NODE_BIN}" ]]; then
    echo "node not found for user ${APP_USER}" >&2
    exit 1
  fi
  write_file_if_changed "$SERVICE_FILE" < <(render_systemd_unit "${APP_USER}" "${APP_GROUP}" "${APP_DIR}" "${ENV_FILE}" "${SERVICE_PATH}" "${NPM_BIN}")
  ${SUDO:-} systemctl daemon-reload
  ${SUDO:-} systemctl enable "${SERVICE_NAME}"
  free_listeners_on_port "${APP_PORT}"
  ${SUDO:-} systemctl restart "${SERVICE_NAME}"
  log "Service ${SERVICE_NAME} restarted."
fi

if [[ "$SKIP_NGINX" != "1" ]]; then
  ensure_root_cmd
  TARGET_DIR=""
  if [[ -d /etc/nginx/sites-enabled ]]; then
    remove_existing_nginx_codex_bindings "/etc/nginx/sites-enabled" "$NGINX_PATH"
    remove_existing_nginx_codex_bindings "/etc/nginx/sites-available" "$NGINX_PATH"
    TARGET_DIR="/etc/nginx/sites-available"
    CONF_PATH="${TARGET_DIR}/${SERVICE_NAME}.conf"
    write_file_if_changed "$CONF_PATH" < <(render_nginx_conf "$DOMAIN" "$NGINX_PATH" "$APP_PORT")
    if [[ ! -L /etc/nginx/sites-enabled/${SERVICE_NAME}.conf ]]; then
      ${SUDO:-} ln -sfn "${CONF_PATH}" "/etc/nginx/sites-enabled/${SERVICE_NAME}.conf"
    else
      ${SUDO:-} ln -sfn "${CONF_PATH}" "/etc/nginx/sites-enabled/${SERVICE_NAME}.conf"
    fi
  elif [[ -d /etc/nginx/conf.d ]]; then
    remove_existing_nginx_codex_bindings "/etc/nginx/conf.d" "$NGINX_PATH"
    TARGET_DIR="/etc/nginx/conf.d"
    CONF_PATH="${TARGET_DIR}/${SERVICE_NAME}.conf"
    write_file_if_changed "$CONF_PATH" < <(render_nginx_conf "$DOMAIN" "$NGINX_PATH" "$APP_PORT")
  else
    echo "Could not locate nginx config directory." >&2
    exit 1
  fi

  if ${SUDO:-} nginx -t; then
    ${SUDO:-} systemctl reload nginx
  else
    echo "nginx config check failed." >&2
    exit 1
  fi
  log "Nginx configured at ${NGINX_PATH} and reloaded."
fi

log "Done."
if [[ "$SKIP_NGINX" != "1" ]]; then
  log "Visit: http://${DOMAIN}${NGINX_PATH}"
fi
