#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Building all targets..."

"${ROOT_DIR}/build-scripts/build-windows.sh" amd64
"${ROOT_DIR}/build-scripts/build-windows.sh" arm64
"${ROOT_DIR}/build-scripts/build-linux.sh" amd64
"${ROOT_DIR}/build-scripts/build-linux.sh" arm64
"${ROOT_DIR}/build-scripts/build-darwin.sh" amd64
"${ROOT_DIR}/build-scripts/build-darwin.sh" arm64

echo "Done."


