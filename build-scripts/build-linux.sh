#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ARCH="${1:-amd64}"
case "$ARCH" in
  amd64|arm64) ;;
  *)
    echo "Usage: $0 [amd64|arm64]" >&2
    exit 2
    ;;
esac

OUT_DIR="${ROOT_DIR}/build/out/linux-${ARCH}"
mkdir -p "${OUT_DIR}"

echo "Building Linux (${ARCH}) shared library..."

# For CGO cross-compilation (e.g. linux/arm64 on an amd64 host) we must point CC to the correct cross-compiler.
# On Ubuntu, install it with: sudo apt-get install gcc-aarch64-linux-gnu
CC_ENV=()
if [[ "$ARCH" == "arm64" ]]; then
  if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    CC_ENV=(CC=aarch64-linux-gnu-gcc)
  else
    echo "Error: aarch64-linux-gnu-gcc not found. Install gcc-aarch64-linux-gnu to build linux/arm64 with CGO." >&2
    exit 1
  fi
fi

CGO_ENABLED=1 GOOS=linux GOARCH="$ARCH" "${CC_ENV[@]}" \
  go build -buildmode=c-shared -o "${OUT_DIR}/libgitleaks.so" "${ROOT_DIR}/cgo"

cp -f "${ROOT_DIR}/cgo/cgo.h" "${OUT_DIR}/cgo.h"

echo "OK: ${OUT_DIR}"


