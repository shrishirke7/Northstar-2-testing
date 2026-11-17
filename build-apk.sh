#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
APP_SRC="$SCRIPT_DIR/android-app"
IMAGE_TAG="shree-it-apk-builder:latest"

if [[ ! -d "$APP_SRC" ]]; then
  echo "android-app directory not found at $APP_SRC" >&2
  exit 1
fi

echo "==> [1/3] Building native Android APK inside isolated Docker container..."
docker build -f "$APP_SRC/Dockerfile.apk" -t "$IMAGE_TAG" "$APP_SRC"

echo "==> [2/3] Extracting signed APK..."
CID="$(docker create "$IMAGE_TAG")"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

mkdir -p "$SCRIPT_DIR/static/downloads" "$SCRIPT_DIR/uploads"
docker cp "$CID:/out/shree-it.apk" "$SCRIPT_DIR/static/downloads/shree-it.apk"
cp "$SCRIPT_DIR/static/downloads/shree-it.apk" "$SCRIPT_DIR/uploads/shree-it.apk"
chmod 644 "$SCRIPT_DIR/static/downloads/shree-it.apk" "$SCRIPT_DIR/uploads/shree-it.apk"
chown 10001:10001 "$SCRIPT_DIR/uploads/shree-it.apk" 2>/dev/null || true

if [[ -d "/opt/northstar-it/uploads" && "$SCRIPT_DIR" != "/opt/northstar-it" ]]; then
  mkdir -p "/opt/northstar-it/static/downloads"
  cp "$SCRIPT_DIR/static/downloads/shree-it.apk" "/opt/northstar-it/static/downloads/shree-it.apk"
  cp "$SCRIPT_DIR/static/downloads/shree-it.apk" "/opt/northstar-it/uploads/shree-it.apk"
  chmod 644 "/opt/northstar-it/static/downloads/shree-it.apk" "/opt/northstar-it/uploads/shree-it.apk"
  chown 10001:10001 "/opt/northstar-it/uploads/shree-it.apk" 2>/dev/null || true
fi

echo "==> [3/3] Done! Native Android APK saved:"
ls -lh "$SCRIPT_DIR/static/downloads/shree-it.apk"
echo "Employees can now download it from your server at: /download/shree-it.apk"
