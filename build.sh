#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

echo ""
echo " ============================================="
echo "  KeyBase Builder | Build Tool"
echo " ============================================="
echo ""
echo "  Select target:"
echo ""
echo "   [1]  Linux    (native, TUI)"
echo "   [2]  Windows  (cross-compile, GUI — requires mingw-w64)"
echo "   [3]  Both"
echo ""
read -rp "  Choice (1/2/3): " CHOICE
echo ""

mkdir -p dist

build_linux() {
    echo " [Linux] Building release (TUI)..."
    pushd Builder > /dev/null
    cargo build --release
    popd > /dev/null
    cp -f Builder/target/release/keybase-builder dist/keybase-builder-linux
    chmod +x dist/keybase-builder-linux
    echo " [OK] dist/keybase-builder-linux"
}

build_windows() {
    echo " [Windows] Building release (GUI, x86_64-pc-windows-gnu)..."
    if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
        echo " [ERROR] mingw-w64 not found."
        echo "  Install: sudo apt install mingw-w64  (Debian/Ubuntu)"
        echo "           sudo pacman -S mingw-w64-gcc (Arch)"
        return 1
    fi
    rustup target add x86_64-pc-windows-gnu &>/dev/null
    pushd Builder > /dev/null
    cargo build --release --target x86_64-pc-windows-gnu
    popd > /dev/null
    cp -f Builder/target/x86_64-pc-windows-gnu/release/keybase-builder.exe \
          dist/keybase-builder-windows.exe
    echo " [OK] dist/keybase-builder-windows.exe"
}

case "$CHOICE" in
    1) build_linux ;;
    2) build_windows ;;
    3) build_linux; build_windows ;;
    *) echo " Invalid choice."; exit 1 ;;
esac

echo ""
echo " ─────────────────────────────────────────────"
echo "  Build complete! Binaries in dist/"
echo " ─────────────────────────────────────────────"
echo ""
[ -f dist/keybase-builder-linux ]       && echo "   keybase-builder-linux        (Linux TUI)"
[ -f dist/keybase-builder-windows.exe ] && echo "   keybase-builder-windows.exe  (Windows GUI)"
echo ""
