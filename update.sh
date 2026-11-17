#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Run with: sudo bash update.sh" >&2; exit 1; fi
SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/northstar-it"
[[ -f "$INSTALL_DIR/.env" ]] || { echo "No installed Northstar configuration was found." >&2; exit 1; }
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" --exclude='./.git' --exclude='./.env' --exclude='./secrets' --exclude='./uploads' --exclude='./backups' --exclude='./__pycache__' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
if [[ -d "$SOURCE_DIR/.git" ]]; then
  echo "$SOURCE_DIR" > "$INSTALL_DIR/.source-repo"
  git config --system --add safe.directory "$SOURCE_DIR" 2>/dev/null || git config --global --add safe.directory "$SOURCE_DIR" 2>/dev/null || true
fi
mkdir -p /run/northstar-updater
chmod +x "$INSTALL_DIR"/*.sh "$INSTALL_DIR/northstar-updater.py" 2>/dev/null || true
if [[ -f "$INSTALL_DIR/systemd/northstar-updater.service" ]]; then
  install -m 0644 "$INSTALL_DIR/systemd/northstar-updater.service" /etc/systemd/system/northstar-updater.service
  systemctl daemon-reload
  systemctl enable northstar-updater.service >/dev/null 2>&1 || true
  systemctl restart northstar-updater.service || true
fi
cd "$INSTALL_DIR"
set -a
. "$INSTALL_DIR/.env"
set +a
SERVER_IP="$(hostname -I | awk '{print $1}')"
ALL_IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | sort -u || true)"
SITE_NAME="${SITE_NAME:-swarnshilp.local}"
SAN_LIST="DNS:${APP_FQDN:-localhost},DNS:localhost,IP:127.0.0.1"
if [[ -n "$SITE_NAME" ]]; then
  case ",$SAN_LIST," in *,"DNS:${SITE_NAME}",*) ;; *) SAN_LIST="${SAN_LIST},DNS:$SITE_NAME,DNS:${SITE_NAME%.local}.local,DNS:${SITE_NAME%.local}" ;; esac
fi
for _ip in $ALL_IPS; do
  case ",$SAN_LIST," in *,"IP:${_ip}",*) ;; *) SAN_LIST="${SAN_LIST},IP:${_ip}" ;; esac
done

if command -v apt-get >/dev/null 2>&1; then
  if ! command -v avahi-daemon >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y avahi-daemon avahi-utils >/dev/null 2>&1 || true
  fi
  systemctl enable --now avahi-daemon >/dev/null 2>&1 || true
fi
if [[ -n "$SITE_NAME" ]] && ! grep -q "$SITE_NAME" /etc/hosts 2>/dev/null; then
  echo "$SERVER_IP $SITE_NAME ${SITE_NAME%.local}" >> /etc/hosts 2>/dev/null || true
fi

if [[ ! -s "$INSTALL_DIR/secrets/ca.crt" || ! -s "$INSTALL_DIR/secrets/ca.key" ]]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/ca.key" -out "$INSTALL_DIR/secrets/ca.crt" \
    -subj "/CN=Shree Root CA/O=Shree IT Asset Intelligence" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
  chmod 600 "$INSTALL_DIR/secrets/ca.key"
  chmod 644 "$INSTALL_DIR/secrets/ca.crt"
fi

NEEDS_LEAF=0
if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]]; then
  NEEDS_LEAF=1
elif ! openssl verify -CAfile "$INSTALL_DIR/secrets/ca.crt" "$INSTALL_DIR/secrets/nginx.crt" >/dev/null 2>&1; then
  NEEDS_LEAF=1
fi
if [[ "$NEEDS_LEAF" -eq 1 ]]; then
  TMP_CERT_DIR="$(mktemp -d)"
  openssl genrsa -out "$INSTALL_DIR/secrets/nginx.key" 2048
  openssl req -new -key "$INSTALL_DIR/secrets/nginx.key" -out "$TMP_CERT_DIR/server.csr" -subj "/CN=${APP_FQDN:-$SERVER_IP}/O=Shree IT"
  cat > "$TMP_CERT_DIR/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$SAN_LIST
EOF
  openssl x509 -req -in "$TMP_CERT_DIR/server.csr" \
    -CA "$INSTALL_DIR/secrets/ca.crt" -CAkey "$INSTALL_DIR/secrets/ca.key" -CAcreateserial \
    -out "$TMP_CERT_DIR/leaf.crt" -days 365 -sha256 -extfile "$TMP_CERT_DIR/leaf.ext"
  cat "$TMP_CERT_DIR/leaf.crt" "$INSTALL_DIR/secrets/ca.crt" > "$INSTALL_DIR/secrets/nginx.crt"
  rm -rf "$TMP_CERT_DIR" "$INSTALL_DIR/secrets/ca.srl"
  chmod 600 "$INSTALL_DIR/secrets/nginx.key"
  chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
fi
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow 5353/udp >/dev/null 2>&1 || true
  ufw allow 5355/udp >/dev/null 2>&1 || true
  ufw allow 137/udp >/dev/null 2>&1 || true
  ufw allow "${HTTP_PORT:-8848}/tcp" >/dev/null 2>&1 || true
  ufw allow "${HTTPS_PORT:-8849}/tcp" >/dev/null 2>&1 || true
  ufw allow 8848/tcp >/dev/null 2>&1 || true
  ufw allow 8849/tcp >/dev/null 2>&1 || true
fi
docker compose build app scanner
bash ./backup.sh manual
docker compose pull web
docker compose up -d
docker compose up -d --force-recreate web
python3 - "$SITE_NAME" "${HTTP_PORT:-8848}" <<'PYNET' || true
import importlib.util, sys
spec = importlib.util.spec_from_file_location("updater", "/opt/northstar-it/northstar-updater.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
tokens, mdns_hosts, short_names = mod._parse_site_tokens(sys.argv[1])
if tokens:
    mod._sync_avahi_and_etc_hosts(tokens, mdns_hosts, short_names)
    mod._configure_host_nginx(tokens, mdns_hosts, short_names, int(sys.argv[2]))
PYNET
echo "Update complete. Existing .env, database, uploads, and backups were preserved."
