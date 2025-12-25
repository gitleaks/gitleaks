#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-amd64}" # amd64 or arm64

OUT_DIR="${ROOT_DIR}/build/out/darwin-${ARCH}"
mkdir -p "${OUT_DIR}"

echo "Building macOS (${ARCH}) shared library..."
CGO_ENABLED=1 GOOS=darwin GOARCH="${ARCH}" \
  go build -buildmode=c-shared -o "${OUT_DIR}/libgitleaks.dylib" "${ROOT_DIR}/cgo"

cp -f "${ROOT_DIR}/cgo/cgo.h" "${OUT_DIR}/cgo.h"

echo "OK: ${OUT_DIR}"


