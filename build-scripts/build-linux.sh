#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/build/out/linux-amd64"

mkdir -p "${OUT_DIR}"

echo "Building Linux (amd64) shared library..."
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -buildmode=c-shared -o "${OUT_DIR}/libgitleaks.so" "${ROOT_DIR}/cgo"

cp -f "${ROOT_DIR}/cgo/cgo.h" "${OUT_DIR}/cgo.h"

echo "OK: ${OUT_DIR}"


