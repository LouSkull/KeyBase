#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# ── colours ──────────────────────────────────────────────────────────────────
R=$'\e[0m'
BOLD=$'\e[1m'
DIM=$'\e[2m'
RED=$'\e[91m'
GREEN=$'\e[92m'
YELLOW=$'\e[93m'
CYAN=$'\e[96m'
WHITE=$'\e[97m'

# ── helpers ───────────────────────────────────────────────────────────────────
now_s() { date +%s; }

fmt_time() {
    local secs=$1
    if (( secs >= 60 )); then
        printf "%dm %ds" $((secs/60)) $((secs%60))
    else
        printf "%ds" "$secs"
    fi
}

fmt_size() {
    local path="$1"
    local bytes
    bytes=$(stat -c%s "$path" 2>/dev/null || stat -f%z "$path" 2>/dev/null || echo 0)
    if (( bytes >= 1048576 )); then
        awk "BEGIN{printf \"%.1f MB\", $bytes/1048576}"
    elif (( bytes >= 1024 )); then
        awk "BEGIN{printf \"%.0f KB\", $bytes/1024}"
    else
        echo "${bytes} B"
    fi
}

# pipe cargo output through this to prefix lines with the box border
prefix_log() {
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf "${DIM}  │  %s${R}\n" "$line"
    done
}

# ── state ─────────────────────────────────────────────────────────────────────
WIN_OK=0; LIN_OK=0
WIN_TIME="?"; LIN_TIME="?"
WIN_SIZE="?"; LIN_SIZE="?"

mkdir -p dist
T_GLOBAL_START=$(now_s)

# ── header ────────────────────────────────────────────────────────────────────
echo
echo "${CYAN}${BOLD}  ╔══════════════════════════════════════════╗${R}"
echo "${CYAN}${BOLD}  ║     KeyBase Builder  —  Build Tool       ║${R}"
echo "${CYAN}${BOLD}  ╚══════════════════════════════════════════╝${R}"
echo
echo "${DIM}  Select targets:${R}"
echo
echo "   ${CYAN}[1]${R}  Linux only    (native TUI)"
echo "   ${CYAN}[2]${R}  Windows only  (cross-compile GUI, requires mingw-w64)"
echo "   ${CYAN}[3]${R}  Both"
echo
read -rp "  ${BOLD}Choice (1/2/3):${R} " CHOICE
echo

# ════════════════════════════════════════════════════════════════════════════
# BUILD  LINUX
# ════════════════════════════════════════════════════════════════════════════
build_linux() {
    echo "${YELLOW}${BOLD}  ┌─[ Linux ]  x86_64  native  TUI${R}"
    echo "${DIM}  │${R}"

    local t0; t0=$(now_s)
    set +e
    (cd Builder && cargo build --release 2>&1) | prefix_log
    local ec=${PIPESTATUS[0]}
    set -e
    local elapsed; elapsed=$(fmt_time $(( $(now_s) - t0 )))

    echo "${DIM}  │${R}"
    if [[ $ec -ne 0 ]]; then
        echo "${RED}${BOLD}  └─ ✗  FAILED  in ${elapsed}${R}"
        echo
        LIN_TIME="$elapsed"
        return
    fi

    cp -f Builder/target/release/keybase-builder dist/keybase-builder-linux
    chmod +x dist/keybase-builder-linux
    LIN_OK=1
    LIN_TIME="$elapsed"
    LIN_SIZE=$(fmt_size dist/keybase-builder-linux)
    echo "${GREEN}${BOLD}  └─ ✓  Done in ${elapsed}   ${DIM}[${LIN_SIZE}]${R}"
    echo
}

# ════════════════════════════════════════════════════════════════════════════
# BUILD  WINDOWS
# ════════════════════════════════════════════════════════════════════════════
build_windows() {
    echo "${YELLOW}${BOLD}  ┌─[ Windows ]  x86_64-pc-windows-gnu  GUI${R}"
    echo "${DIM}  │${R}"

    if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
        echo "${RED}${BOLD}  └─ ✗  mingw-w64 not found${R}"
        echo
        echo "${DIM}     Install:  sudo apt install mingw-w64        (Debian/Ubuntu)${R}"
        echo "${DIM}               sudo pacman -S mingw-w64-gcc      (Arch)${R}"
        echo
        WIN_TIME="—"
        return
    fi

    rustup target add x86_64-pc-windows-gnu &>/dev/null

    local t0; t0=$(now_s)
    set +e
    (cd Builder && cargo build --release --target x86_64-pc-windows-gnu 2>&1) | prefix_log
    local ec=${PIPESTATUS[0]}
    set -e
    local elapsed; elapsed=$(fmt_time $(( $(now_s) - t0 )))

    echo "${DIM}  │${R}"
    if [[ $ec -ne 0 ]]; then
        echo "${RED}${BOLD}  └─ ✗  FAILED  in ${elapsed}${R}"
        echo
        WIN_TIME="$elapsed"
        return
    fi

    cp -f Builder/target/x86_64-pc-windows-gnu/release/keybase-builder.exe \
          dist/keybase-builder-windows.exe
    WIN_OK=1
    WIN_TIME="$elapsed"
    WIN_SIZE=$(fmt_size dist/keybase-builder-windows.exe)
    echo "${GREEN}${BOLD}  └─ ✓  Done in ${elapsed}   ${DIM}[${WIN_SIZE}]${R}"
    echo
}

# ── dispatch ──────────────────────────────────────────────────────────────────
case "$CHOICE" in
    1) build_linux ;;
    2) build_windows ;;
    3) build_linux; build_windows ;;
    *) echo "${RED}  Invalid choice.${R}"; exit 1 ;;
esac

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════
TOTAL=$(fmt_time $(( $(now_s) - T_GLOBAL_START )))
ALL_OK=$(( WIN_OK + LIN_OK ))

echo
echo "${CYAN}${BOLD}  ╔══════════════════════════════════════════════════════════╗${R}"
echo "${CYAN}${BOLD}  ║                    Build  Summary                        ║${R}"
echo "${CYAN}${BOLD}  ╠══════════════════════════════════════════════════════════╣${R}"

if [[ $CHOICE == "2" || $CHOICE == "3" ]]; then
    if [[ $WIN_OK -eq 1 ]]; then
        printf "${CYAN}  ║${R}  ${GREEN}✓${R}  Windows  GUI   ${GREEN}%-8s${R}  dist/keybase-builder-windows.exe  ${DIM}[%s]${R}\n" "$WIN_TIME" "$WIN_SIZE"
    else
        printf "${CYAN}  ║${R}  ${RED}✗${R}  Windows  GUI   ${RED}FAILED (%s)${R}\n" "$WIN_TIME"
    fi
fi

if [[ $CHOICE == "1" || $CHOICE == "3" ]]; then
    if [[ $LIN_OK -eq 1 ]]; then
        printf "${CYAN}  ║${R}  ${GREEN}✓${R}  Linux   TUI   ${GREEN}%-8s${R}  dist/keybase-builder-linux          ${DIM}[%s]${R}\n" "$LIN_TIME" "$LIN_SIZE"
    else
        printf "${CYAN}  ║${R}  ${RED}✗${R}  Linux   TUI   ${RED}FAILED (%s)${R}\n" "$LIN_TIME"
    fi
fi

echo "${CYAN}${BOLD}  ╠══════════════════════════════════════════════════════════╣${R}"
echo "${CYAN}  ║${R}  Total time:  ${BOLD}${WHITE}${TOTAL}${R}"
echo "${CYAN}${BOLD}  ╚══════════════════════════════════════════════════════════╝${R}"
echo

if (( ALL_OK > 0 )); then
    echo "${GREEN}${BOLD}  Binaries ready in dist/${R}"
else
    echo "${RED}${BOLD}  Build failed — check output above.${R}"
fi
echo
