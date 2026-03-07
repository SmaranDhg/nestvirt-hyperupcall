#!/usr/bin/env bash
# scripts/build_hyperupcalls.sh — Build all hyperupcall guest programs.
#
# Run this INSIDE the L1 (or L2) VM after the hyperturtle kernel is booted,
# because the eBPF programs need kernel headers from the running kernel version.
#
# Prerequisites (inside L1):
#   - hyperturtle-linux kernel running (uname -r)
#   - libbpf installed (from ./setup.sh libbpf, or apt install libbpf-dev)
#   - clang + llvm + linux-headers for the running kernel:
#       sudo apt install -y clang llvm linux-headers-$(uname -r)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUC="$REPO_ROOT/hyperupcalls"

log() { echo "[build_hyperupcalls] $*"; }

# ─── Verify we're running the right kernel ────────────────────────────────────
if ! uname -r | grep -q hyperturtle 2>/dev/null; then
    log "WARNING: 'uname -r' does not mention 'hyperturtle'."
    log "Make sure you have booted the hyperturtle kernel before building eBPF programs."
fi

# ─── Install clang/llvm if missing ────────────────────────────────────────────
if ! command -v clang &>/dev/null; then
    log "clang not found — installing..."
    sudo apt-get install -y clang llvm linux-headers-"$(uname -r)"
fi

# ─── Build each hyperupcall program (only those needed for benchmarks) ────────
build_target() {
    local dir="$1"
    log "Building $dir ..."
    make -C "$HUC/$dir" V=1
}

build_target "network/pass"
build_target "tracing"

log ""
log "All hyperupcall programs built in $HUC"
log ""
log "To attach a program from L2, use the hyperupcall library:"
log "  #include \"hyperupcall.h\""
log "  int slot = load_hyperupcall(\"network/pass/pass.bpf.o\");"
log "  link_hyperupcall(slot, \"xdp_pass\", MAJORID_XDP, <ifindex>);"
