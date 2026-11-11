#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root or with sudo: sudo bash install.sh" >&2
  exit 1
fi

. /etc/os-release || true
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" ]]; then
  echo "Warning: This installer is tested on Ubuntu 22.04/24.04 & Debian 12. Continuing anyway..." >&2
fi

SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/northstar-it"

if [[ -f "$INSTALL_DIR/.env" ]]; then
  echo "Existing Northstar installation found at $INSTALL_DIR."
  echo "Running update.sh to preserve your existing database, .env, uploads, and backups..."
  exec bash "$SOURCE_DIR/update.sh"
fi

echo "==> [1/6] Updating system packages & installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl openssl python3 tar

echo "==> [2/6] Installing Docker Engine & Docker Compose..."
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  if ! apt-get install -y docker.io docker-compose-v2; then
    echo "Fallback: installing Docker from official get.docker.com script..."
    curl -fsSL https://get.docker.com | sh
  fi
fi
systemctl enable --now docker

echo "==> [3/6] Copying Northstar application files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" \
    --exclude='./.git' \
    --exclude='./.env' \
    --exclude='./secrets' \
    --exclude='./uploads' \
    --exclude='./backups' \
    --exclude='./__pycache__' \
    --exclude='./*.zip' \
    --exclude='./*.bak*' \
    -cf - . | tar -C "$INSTALL_DIR" -xf -
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
APP_FQDN="${APP_FQDN:-$SERVER_IP}"
HTTP_PORT="${HTTP_PORT:-8898}"
HTTPS_PORT="${HTTPS_PORT:-8899}"
DB_PASSWORD="$(openssl rand -hex 32)"
APP_SECRET="$(openssl rand -hex 48)"
export APP_FQDN HTTP_PORT HTTPS_PORT DB_PASSWORD APP_SECRET

echo "==> [4/6] Generating secure configuration (.env) & SSL certificates..."
python3 - "$INSTALL_DIR/.env" <<'PYENV'
import os, sys
keys = ("APP_FQDN", "HTTP_PORT", "HTTPS_PORT", "DB_PASSWORD", "APP_SECRET")
def q(v):
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for k in keys:
        f.write(f"{k}={q(os.environ[k])}\n")
    f.write("COOKIE_SECURE='true'\n")
    f.write("BACKUP_DIR='/backups'\n")
    f.write("UPLOAD_DIR='/app/uploads'\n")
    f.write("TZ='Asia/Kolkata'\n")
PYENV

chmod 600 "$INSTALL_DIR/.env"
chown -R 10001:10001 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups"
chmod 700 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"

if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]]; then
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/nginx.key" \
    -out "$INSTALL_DIR/secrets/nginx.crt" \
    -subj "/CN=$APP_FQDN" \
    -addext "subjectAltName=DNS:$APP_FQDN,DNS:localhost,IP:$SERVER_IP,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:TRUE"
fi
chmod 600 "$INSTALL_DIR/secrets/nginx.key"
chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
chmod +x "$INSTALL_DIR/backup.sh" "$INSTALL_DIR/restore.sh" "$INSTALL_DIR/update.sh" "$INSTALL_DIR/install.sh" || true

echo "==> [5/6] Configuring firewall ports (if UFW is active) & building containers..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow 8555/tcp >/dev/null 2>&1 || true
  ufw allow 8555/udp >/dev/null 2>&1 || true
  echo "Opened UFW ports: ${HTTP_PORT}/tcp, ${HTTPS_PORT}/tcp, 8555/tcp+udp"
fi

cd "$INSTALL_DIR"
docker compose build app scanner
docker compose up -d

echo "==> [6/6] Installing automatic daily/weekly/monthly backup schedule..."
if [[ -d "$INSTALL_DIR/systemd" ]]; then
  install -m 0644 "$INSTALL_DIR/systemd/northstar-backup@.service" /etc/systemd/system/northstar-backup@.service
  for kind in daily weekly monthly; do
    install -m 0644 "$INSTALL_DIR/systemd/northstar-backup-$kind.timer" "/etc/systemd/system/northstar-backup-$kind.timer"
  done
  systemctl daemon-reload
  systemctl enable --now northstar-backup-daily.timer northstar-backup-weekly.timer northstar-backup-monthly.timer
fi

echo
echo "======================================================================"
echo "  Northstar IT Asset Intelligence is installed and running!"
echo "======================================================================"
echo "  Admin / IT Portal URL : https://$APP_FQDN:$HTTPS_PORT"
echo "  Public Helpdesk URL   : https://$APP_FQDN:$HTTPS_PORT/portal"
echo "  Install Directory     : $INSTALL_DIR"
echo
echo "  Open the Admin URL in Chrome/Edge, accept the self-signed HTTPS"
echo "  certificate warning, and complete the first-time Admin setup wizard."
echo "======================================================================"
docker compose ps
