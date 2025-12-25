#!/usr/bin/env bash
set -euo pipefail

# Script to check if all dependencies are installed for building the Go library

echo "Checking build dependencies..."
echo ""

ERRORS=0

# Check Go
echo -n "Checking Go... "
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo "OK ($GO_VERSION)"
    
    # Check CGO support
    # Note: CGO may be disabled if no C compiler is found, but build scripts enable it explicitly
    CGO_STATUS=$(go env CGO_ENABLED)
    if [ "$CGO_STATUS" = "1" ]; then
        echo "  ✓ CGO is enabled"
    else
        echo "  ⚠ CGO is disabled (will be enabled by build scripts if C compiler is available)"
        # Don't count this as an error - build scripts set CGO_ENABLED=1 explicitly
    fi
else
    echo "✗ NOT FOUND"
    echo "  Please install Go 1.24+ from https://go.dev/"
    ERRORS=$((ERRORS + 1))
fi

# Check C compiler
echo -n "Checking C compiler... "
CC_FOUND=0

# Check for gcc (MinGW-w64 on Windows, gcc on Linux)
if command -v gcc &> /dev/null; then
    GCC_VERSION=$(gcc --version | head -n1)
    echo "OK (gcc: $GCC_VERSION)"
    CC_FOUND=1
# Check for clang (macOS, some Linux)
elif command -v clang &> /dev/null; then
    CLANG_VERSION=$(clang --version | head -n1)
    echo "OK (clang: $CLANG_VERSION)"
    CC_FOUND=1
# Check for MSVC cl.exe (Windows)
elif command -v cl &> /dev/null; then
    echo "OK (MSVC cl.exe)"
    CC_FOUND=1
else
    echo "✗ NOT FOUND"
    ERRORS=$((ERRORS + 1))
    
    # Platform-specific instructions
    OS_NAME=$(uname -s 2>/dev/null || echo "Unknown")
    if [[ "$OS_NAME" == *"MINGW"* ]] || [[ "$OS_NAME" == *"MSYS"* ]] || [[ -n "${WINDIR:-}" ]]; then
        echo ""
        echo "  Windows installation options:"
        echo "  1. Install MinGW-w64 via MSYS2:"
        echo "     - Download MSYS2 from https://www.msys2.org/"
        echo "     - Run: pacman -S mingw-w64-x86_64-gcc"
        echo "  2. Install TDM-GCC from https://jmeubank.github.io/tdm-gcc/"
        echo "  3. Install Visual Studio Build Tools (includes MSVC)"
    elif [[ "$OS_NAME" == "Linux" ]]; then
        echo ""
        echo "  Linux installation:"
        echo "    sudo apt-get install gcc        # Ubuntu/Debian"
        echo "    sudo yum install gcc           # CentOS/RHEL"
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        echo ""
        echo "  macOS installation:"
        echo "    xcode-select --install"
    fi
fi

echo ""

# Summary
if [ $ERRORS -eq 0 ]; then
    echo "✓ All dependencies are installed. You can build the library."
    echo ""
    echo "To build for your platform:"
    OS_NAME=$(uname -s 2>/dev/null || echo "Unknown")
    if [[ "$OS_NAME" == *"MINGW"* ]] || [[ "$OS_NAME" == *"MSYS"* ]] || [[ -n "${WINDIR:-}" ]]; then
        echo "  bash build-scripts/build-windows.sh"
    elif [[ "$OS_NAME" == "Linux" ]]; then
        echo "  bash build-scripts/build-linux.sh"
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        echo "  bash build-scripts/build-darwin.sh amd64   # Intel"
        echo "  bash build-scripts/build-darwin.sh arm64   # Apple Silicon"
    fi
    exit 0
else
    echo "✗ Missing $ERRORS dependency/dependencies. Please install them before building."
    exit 1
fi


