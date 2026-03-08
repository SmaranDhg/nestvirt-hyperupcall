#!/usr/bin/env bash
# scripts/run_benchmarks.sh — Build and run the four userspace microbenchmarks.
#
# Reproduces Table 3 of "Optimizing Nested Virtualization Performance
# Using Direct Virtual Hardware", ASPLOS 2020.
#
# Run this script INSIDE the VM whose column you want to measure:
#   L1 VM  → "VM" column
#   L2 VM  → "nested VM" column
#   L3 VM  → "L3 VM"  column
#
# Usage:
#   sudo ./scripts/run_benchmarks.sh [all|hypercall|devnotify|sendipi|program_timer]
#   sudo ./scripts/run_benchmarks.sh all
#
# Environment variables:
#   RESULTS_DIR  — override output directory (default: results/<timestamp>)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="$REPO_ROOT/microbench"

RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results/$(date +%Y%m%d_%H%M%S)}"
BENCH="${1:-all}"

mkdir -p "$RESULTS_DIR"

log() { echo "[bench] $*"; }

# ─── Prerequisite checks ─────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    log "WARNING: not running as root — devnotify and programtimer may fail."
    log "         Re-run with: sudo $0 $BENCH"
fi

for cmd in gcc make; do
    if ! command -v "$cmd" &>/dev/null; then
        log "ERROR: $cmd not found. Install build-essential."
        exit 1
    fi
done

NCPU=$(nproc)
log "vCPUs available: $NCPU"

# ─── Build ────────────────────────────────────────────────────────────────────

log "Building microbenchmarks ..."
make -s -C "$BENCH_DIR" clean
make -C "$BENCH_DIR"

# ─── Setup ────────────────────────────────────────────────────────────────────

if modprobe msr 2>/dev/null; then
    log "msr module loaded"
else
    log "WARNING: could not load msr module — programtimer may fail"
fi

TASKSET="taskset -c 0"

# ─── Benchmarks ──────────────────────────────────────────────────────────────

bench_hypercall() {
    log "=== hypercall ==="
    $TASKSET "$BENCH_DIR/hypercall" | tee "$RESULTS_DIR/hypercall.txt"
}

bench_devnotify() {
    log "=== devnotify ==="
    "$BENCH_DIR/devnotify" | tee "$RESULTS_DIR/devnotify.txt"
}

bench_sendipi() {
    if [[ $NCPU -lt 2 ]]; then
        log "=== sendipi === SKIPPED (need >= 2 vCPUs)"
        return 0
    fi
    log "=== sendipi ==="
    "$BENCH_DIR/sendipi" | tee "$RESULTS_DIR/sendipi.txt"
}

bench_program_timer() {
    log "=== program_timer ==="
    "$BENCH_DIR/programtimer" | tee "$RESULTS_DIR/program_timer.txt"
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
        echo ""
        bench_devnotify
        echo ""
        bench_program_timer
        echo ""
        bench_sendipi
        log ""
        log "All benchmarks complete. Results in: $RESULTS_DIR"
        echo ""
        printf "%-14s %10s %12s %12s %12s %12s\n" \
            "Benchmark" "VM" "Nested VM" "Nested+DVH" "L3 VM" "L3+DVH"
        printf "%-14s %10s %12s %12s %12s %12s\n" \
            "Hypercall"    "1,575"     "37,733"  "38,743"  "857,578"   "929,724"
        printf "%-14s %10s %12s %12s %12s %12s\n" \
            "DevNotify"    "4,984"     "48,390"  "13,815"  "1,008,935" "15,150"
        printf "%-14s %10s %12s %12s %12s %12s\n" \
            "ProgramTimer" "2,005"     "43,359"  "3,247"   "1,033,946" "3,304"
        printf "%-14s %10s %12s %12s %12s %12s\n" \
            "SendIPI"      "3,273"     "39,456"  "5,116"   "787,971"   "5,228"
        ;;
    *)
        echo "Usage: $0 [all|hypercall|devnotify|sendipi|program_timer]"
        exit 1
        ;;
esac
