#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="${1:-}"

case "$TARGET" in
  darwin-x64|darwin-arm64) ;;
  *) echo "Usage: $0 darwin-x64|darwin-arm64" >&2; exit 2 ;;
esac

BACKEND_BINARY="$REPO_ROOT/backend/dist-macos/${TARGET#darwin-}/codeshield-backend"
VSCE="$SCRIPT_DIR/node_modules/.bin/vsce"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS VSIX packaging must run on macOS so the bundled backend is native." >&2
  exit 1
fi
if [[ ! -x "$BACKEND_BINARY" ]]; then
  echo "Build the macOS backend first: backend/build-macos.sh" >&2
  exit 1
fi
if [[ ! -x "$VSCE" ]]; then
  echo "Install extension dependencies first: npm ci --prefix extension" >&2
  exit 1
fi

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  arm64|aarch64) HOST_ARCH="arm64" ;;
  x86_64) HOST_ARCH="x64" ;;
esac
TARGET_ARCH="${TARGET#darwin-}"
if [[ "$HOST_ARCH" != "$TARGET_ARCH" ]]; then
  echo "Target $TARGET requires a native $TARGET_ARCH Mac build; this host is $HOST_ARCH." >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/codeshield-vsix.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

rsync -a \
  --exclude='node_modules/' \
  --exclude='*.vsix' \
  --exclude='/server/codeshield-backend.exe' \
  "$SCRIPT_DIR/" "$STAGE/"
mkdir -p "$STAGE/server"
cp "$BACKEND_BINARY" "$STAGE/server/codeshield-backend-macos"
chmod 755 "$STAGE/server/codeshield-backend-macos"

VERSION="$(node -e 'console.log(require(process.argv[1]).version)' "$SCRIPT_DIR/package.json")"
OUTPUT="$SCRIPT_DIR/secure-coding-assistant-${TARGET}-${VERSION}.vsix"
cd "$STAGE"
"$VSCE" package --no-dependencies --target "$TARGET" --out "$OUTPUT"
echo "Packaged $OUTPUT"
