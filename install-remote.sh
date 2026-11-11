#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run with sudo: curl -fsSL ... | sudo bash -s OWNER/REPO [branch]" >&2
  exit 1
fi

REPOSITORY="${1:-}"
BRANCH="${2:-main}"
if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Usage: sudo bash install-remote.sh OWNER/REPO [branch]" >&2
  exit 2
fi
if [[ ! "$BRANCH" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "Branch may contain only letters, digits, dots, underscores, and hyphens." >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y git ca-certificates curl
fi

TMP_DIR="$(mktemp -d /tmp/northstar-install.XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Downloading Northstar source from GitHub ($REPOSITORY · branch: $BRANCH)..."
git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPOSITORY.git" "$TMP_DIR/source"
bash "$TMP_DIR/source/install.sh"
