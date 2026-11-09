#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ARCH="$(uname -m)"

case "$BUILD_ARCH" in
  arm64|aarch64) BUILD_ARCH="arm64" ;;
  x86_64) BUILD_ARCH="x64" ;;
  *) echo "Unsupported macOS architecture: $BUILD_ARCH" >&2; exit 1 ;;
esac

if [[ -n "${CODESHIELD_EXPECTED_ARCH:-}" && "$BUILD_ARCH" != "$CODESHIELD_EXPECTED_ARCH" ]]; then
  echo "Expected $CODESHIELD_EXPECTED_ARCH runner, but this host is $BUILD_ARCH." >&2
  exit 1
fi

BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/codeshield-backend-build.XXXXXX")"
BUILD_DIR="$BUILD_ROOT/backend"
BUILD_ENV="$BUILD_ROOT/venv"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT

mkdir -p "$BUILD_DIR/app" "$BUILD_DIR/js-ast"
rsync -a --exclude='__pycache__/' --exclude='*.pyc' "$SCRIPT_DIR/app/" "$BUILD_DIR/app/"
cp "$SCRIPT_DIR/requirements.txt" "$BUILD_DIR/requirements.txt"
cp "$SCRIPT_DIR/codeshield-backend.spec" "$BUILD_DIR/codeshield-backend.spec"
cp "$SCRIPT_DIR/js-ast/scan.js" "$SCRIPT_DIR/js-ast/worker.js" \
  "$SCRIPT_DIR/js-ast/package.json" "$SCRIPT_DIR/js-ast/package-lock.json" "$BUILD_DIR/js-ast/"

python3 -m venv "$BUILD_ENV"
PYTHON="$BUILD_ENV/bin/python"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$BUILD_DIR/requirements.txt" pyinstaller
npm ci --prefix "$BUILD_DIR/js-ast"

cd "$BUILD_DIR"
"$PYTHON" -m PyInstaller codeshield-backend.spec --noconfirm --clean \
  --distpath "$BUILD_ROOT/dist" --workpath "$BUILD_ROOT/work"

BACKEND_BINARY="$BUILD_ROOT/dist/codeshield-backend"
if [[ ! -f "$BACKEND_BINARY" ]]; then
  echo "PyInstaller did not produce $BACKEND_BINARY" >&2
  exit 1
fi

OUTPUT_DIR="$SCRIPT_DIR/dist-macos/$BUILD_ARCH"
mkdir -p "$OUTPUT_DIR"
cp "$BACKEND_BINARY" "$OUTPUT_DIR/codeshield-backend"
chmod 755 "$OUTPUT_DIR/codeshield-backend"
file "$OUTPUT_DIR/codeshield-backend"
echo "Built macOS $BUILD_ARCH backend at backend/dist-macos/$BUILD_ARCH/codeshield-backend"
