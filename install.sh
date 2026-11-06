#!/bin/sh
# Installs the latest tunnelkeeper release on Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/JustMrKoala/tunnelkeeper/main/install.sh | sh
#
# It downloads one static binary, checks its SHA256, and copies it to
# /usr/local/bin. Set VERSION=v0.1.0 to install a specific release.
set -eu

REPO="JustMrKoala/tunnelkeeper"
TARGET="/usr/local/bin/tunnelkeeper"

case "$(uname -s)" in
  Linux) ;;
  *) echo "This script is for Linux. See the README for Windows." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ASSET="tunnelkeeper-linux-x86_64" ;;
  aarch64 | arm64) ASSET="tunnelkeeper-linux-aarch64" ;;
  *) echo "No release for $(uname -m). See the README to build from source." >&2; exit 1 ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q "$1" -O "$2"; }
else
  echo "Install curl or wget first." >&2
  exit 1
fi

if [ -n "${VERSION:-}" ]; then
  BASE="https://github.com/$REPO/releases/download/$VERSION"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Downloading $ASSET"
fetch "$BASE/$ASSET" "$DIR/$ASSET"
fetch "$BASE/SHA256SUMS" "$DIR/SHA256SUMS"

(cd "$DIR" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null) || {
  echo "Checksum mismatch, nothing was installed." >&2
  exit 1
}
echo "Checksum verified"

if [ "$(id -u)" -eq 0 ]; then
  install -m 0755 "$DIR/$ASSET" "$TARGET"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "$DIR/$ASSET" "$TARGET"
else
  echo "Run this as root, or install sudo, to write to $TARGET." >&2
  exit 1
fi

echo "Installed $("$TARGET" --version) at $TARGET"
echo "Next: tunnelkeeper auth login --zone example.com"
