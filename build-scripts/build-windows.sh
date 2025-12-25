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

OUT_DIR="${ROOT_DIR}/build/out/windows-${ARCH}"

mkdir -p "${OUT_DIR}"

echo "Building Windows (${ARCH}) shared library..."

# Try to find the correct MinGW compiler
# Go automatically adds -mthreads flag for Windows, but not all gcc versions support it
# We need to either use the correct MinGW compiler or override CGO_CFLAGS

CC="${CC:-}"
CGO_CFLAGS_OVERRIDE=""

if [ -z "$CC" ]; then
    if [[ "$ARCH" == "amd64" ]]; then
        # Try to find MinGW-w64 compiler (supports -mthreads)
        if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
            CC=x86_64-w64-mingw32-gcc
            echo "Using MinGW-w64 compiler: $CC"
        elif command -v gcc &> /dev/null; then
            CC=gcc
            echo "Using gcc compiler: $CC"
            # Check if this gcc supports -mthreads
            if ! "$CC" -mthreads -E -x c - -o /dev/null 2>/dev/null <<< "" 2>&1; then
                echo "Warning: gcc does not support -mthreads, overriding CGO_CFLAGS"
                # Override CGO_CFLAGS to remove -mthreads (Go adds it automatically for Windows)
                # We keep other standard flags but remove -mthreads
                CGO_CFLAGS_OVERRIDE="-O2 -g"
            fi
        else
            echo "Error: No C compiler found. Please install MinGW-w64 or set CC environment variable."
            exit 1
        fi
    else
        # windows/arm64 cross-compilation requires a dedicated MinGW toolchain.
        # On Ubuntu, install it with: sudo apt-get install gcc-mingw-w64-aarch64
        if command -v aarch64-w64-mingw32-gcc &> /dev/null; then
            CC=aarch64-w64-mingw32-gcc
            echo "Using MinGW-w64 ARM64 compiler: $CC"
        else
            echo "Error: aarch64-w64-mingw32-gcc not found. Install gcc-mingw-w64-aarch64 to build windows/arm64 with CGO." >&2
            exit 1
        fi
    fi
fi

# Build with explicit CC and CGO settings
# If CGO_CFLAGS_OVERRIDE is set, use it to override Go's automatic -mthreads flag
if [ -n "$CGO_CFLAGS_OVERRIDE" ]; then
    CGO_ENABLED=1 GOOS=windows GOARCH="$ARCH" CC="$CC" CGO_CFLAGS="$CGO_CFLAGS_OVERRIDE" \
      go build -buildmode=c-shared -o "${OUT_DIR}/libgitleaks.dll" "${ROOT_DIR}/cgo"
else
    CGO_ENABLED=1 GOOS=windows GOARCH="$ARCH" CC="$CC" \
      go build -buildmode=c-shared -o "${OUT_DIR}/libgitleaks.dll" "${ROOT_DIR}/cgo"
fi

# Go generates libgitleaks.h next to the library output.
# We also copy our stable header for interop convenience.
cp -f "${ROOT_DIR}/cgo/cgo.h" "${OUT_DIR}/cgo.h"

echo "OK: ${OUT_DIR}"


