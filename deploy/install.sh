#!/usr/bin/env bash
# Install pisentry as a hardened systemd service on Raspberry Pi OS, Ubuntu,
# Debian or RHEL-family hosts (arm64, armv7, amd64).
#
# Usage:
#   sudo ./deploy/install.sh                       # download latest release
#   sudo ./deploy/install.sh --version v0.1.0      # download a specific release
#   sudo ./deploy/install.sh --binary ./dist/pisentry-linux-arm64   # local build
set -euo pipefail

REPO="MrGuato/pisentry"
VERSION="latest"
BINARY=""
HERE="$(cd "$(dirname "$0")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --binary)  BINARY="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv8l) ARCH=armv7 ;;
  x86_64)        ARCH=amd64 ;;
  armv6l) echo "armv6 (Pi Zero/1) is not a supported target" >&2; exit 1 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ -z "$BINARY" ]]; then
  if [[ "$VERSION" == "latest" ]]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
  echo "downloading pisentry-linux-$ARCH from $BASE"
  curl -fsSL -o "$TMP/pisentry-linux-$ARCH" "$BASE/pisentry-linux-$ARCH"
  curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
  (cd "$TMP" && grep " pisentry-linux-$ARCH\$" SHA256SUMS | sha256sum -c -)
  BINARY="$TMP/pisentry-linux-$ARCH"
fi

install -m 0755 -o root -g root "$BINARY" /usr/local/bin/pisentry
install -d -m 0755 /etc/pisentry
if [[ ! -f /etc/pisentry/config.json ]]; then
  install -m 0644 "$HERE/config.example.json" /etc/pisentry/config.json
  echo "wrote /etc/pisentry/config.json"
else
  echo "keeping existing /etc/pisentry/config.json"
fi
if [[ ! -f /etc/pisentry/pisentry.env ]]; then
  umask 077
  cat > /etc/pisentry/pisentry.env <<'EOF'
# Webhook secrets. Set alerts.type in config.json to enable.
# PISENTRY_WEBHOOK_URL=https://ntfy.sh/your-private-topic
# PISENTRY_WEBHOOK_TOKEN=
EOF
fi
chmod 0600 /etc/pisentry/pisentry.env

install -m 0644 "$HERE/systemd/pisentry.service" /etc/systemd/system/pisentry.service
systemctl daemon-reload
systemctl enable --now pisentry

echo
/usr/local/bin/pisentry version
echo "service: $(systemctl is-active pisentry)"
echo
echo "Learning baselines for the next 10 minutes. Then try:"
echo "  sudo pisentry report"
echo "  sudo pisentry audit"
echo "  journalctl -u pisentry -f"
