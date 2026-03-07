#!/usr/bin/env bash
# scripts/run_benchmarks.sh — Build and run the four kernel-module benchmarks.
#
# Usage:
#   sudo ./scripts/run_benchmarks.sh [all|hypercall|devnotify|sendipi|program_timer]
#   sudo ITERS=10000 ./scripts/run_benchmarks.sh all
#   sudo TARGET_CPU=2 ./scripts/run_benchmarks.sh sendipi
#   sudo MMIO_BASE=0xFEBD4000 ./scripts/run_benchmarks.sh devnotify

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KBENCH="$REPO_ROOT/kernel_benchmarks"

ITERS="${ITERS:-1000}"
TARGET_CPU="${TARGET_CPU:-1}"
PERIOD_NS="${PERIOD_NS:-1000000}"
MMIO_BASE="${MMIO_BASE:-}"
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results/$(date +%Y%m%d_%H%M%S)}"
BENCH="${1:-all}"

mkdir -p "$RESULTS_DIR"

log() { echo "[bench] $*"; }

# ─── Build a kernel module ───────────────────────────────────────────────────
build_module() {
    local dir="$1"
    log "Building $dir ..."
    make -C "$KBENCH/$dir" 2>&1 | tail -1
}

# ─── Load module, grab dmesg output, unload ─────────────────────────────────
run_module() {
    local dir="$1" ko="$2"
    shift 2
    local mod_path="$KBENCH/$dir/$ko"
    local mod_name="${ko%.ko}"

    [[ -f "$mod_path" ]] || { log "ERROR: $mod_path not found"; return 1; }

    rmmod "$mod_name" 2>/dev/null || true

    local marker="__bench_${mod_name}_$$"
    echo "$marker" > /dev/kmsg

    insmod "$mod_path" "$@" || { log "ERROR: insmod failed"; return 1; }
    rmmod "$mod_name" 2>/dev/null || true

    dmesg | sed -n "/$marker/,\$p" | grep "${mod_name}:" | grep -v "module removed"
}

# ─── Benchmarks ──────────────────────────────────────────────────────────────
bench_hypercall() {
    log "=== hypercall ($ITERS iterations) ==="
    build_module "hypercall_bench"
    run_module "hypercall_bench" "hypercall_bench.ko" \
        "iters=$ITERS" "nr=11" \
        | tee "$RESULTS_DIR/hypercall.txt"
}

bench_devnotify() {
    if [[ -z "$MMIO_BASE" ]]; then
        log "ERROR: MMIO_BASE is required for devnotify."
        log "  Find one with: lspci -v | grep 'Memory at'"
        log "  Example: sudo MMIO_BASE=0xFEBD4000 $0 devnotify"
        return 1
    fi
    log "=== devnotify ($ITERS iterations, mmio_base=$MMIO_BASE) ==="
    build_module "devnotify_bench"
    run_module "devnotify_bench" "devnotify_bench.ko" \
        "iters=$ITERS" "mmio_base=$MMIO_BASE" \
        | tee "$RESULTS_DIR/devnotify.txt"
}

bench_sendipi() {
    log "=== sendipi ($ITERS iterations, target_cpu=$TARGET_CPU) ==="
    build_module "ipi_bench"
    run_module "ipi_bench" "ipi_bench.ko" \
        "iters=$ITERS" "target_cpu=$TARGET_CPU" \
        | tee "$RESULTS_DIR/sendipi.txt"
}

bench_program_timer() {
    log "=== program_timer ($ITERS iterations, period_ns=$PERIOD_NS) ==="
    build_module "timer_bench"
    run_module "timer_bench" "timer_bench.ko" \
        "iters=$ITERS" "period_ns=$PERIOD_NS" \
        | tee "$RESULTS_DIR/program_timer.txt"
}

# ─── Dispatch ────────────────────────────────────────────────────────────────
log "Results directory: $RESULTS_DIR"

case "$BENCH" in
    program_timer|programtimer|ProgramTimer) BENCH="program_timer" ;;
esac

case "$BENCH" in
    hypercall)     bench_hypercall ;;
    devnotify)     bench_devnotify ;;
    sendipi)       bench_sendipi ;;
    program_timer) bench_program_timer ;;
    all)
        bench_hypercall
        bench_devnotify
        bench_sendipi
        bench_program_timer
        log ""
        log "All benchmarks complete. Results in: $RESULTS_DIR"
        ;;
    *)
        echo "Usage: $0 [all|hypercall|devnotify|sendipi|program_timer]"
        echo "  ITERS=$ITERS  TARGET_CPU=$TARGET_CPU  PERIOD_NS=$PERIOD_NS  MMIO_BASE=0x..."
        exit 1
        ;;
esac
