#!/usr/bin/env bash
# scripts/run_benchmarks.sh — Run the four L2→L0 hyperupcall micro-benchmarks.
#
# Benchmarks (from TODO.md):
#   1. hypercall      – raw vmcall round-trip latency (load + unload an empty BPF object)
#   2. devnotify      – device-notification latency via XDP hyperupcall
#   3. sendipi        – inter-processor interrupt delivery latency via perf-event hyperupcall
#   4. ProgramTimer   – periodic timer hyperupcall via profiling (perf) event
#
# Run this INSIDE the L2 guest after the hyperupcall programs are loaded.
# The hyperupcall.h library must be compiled and linked into each benchmark.
#
# Usage:
#   ./scripts/run_benchmarks.sh [all|hypercall|devnotify|sendipi|ProgramTimer]
#   ITERS=10000 NETDEV=2 ./scripts/run_benchmarks.sh all

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUC="$REPO_ROOT/hyperupcalls"

# ─── Parameters (override via environment) ────────────────────────────────────
ITERS="${ITERS:-1000}"          # number of iterations per benchmark
NETDEV="${NETDEV:-2}"           # guest virtio-net interface index for XDP/TC
SAMPLE_FREQ="${SAMPLE_FREQ:-1000}"  # Hz for ProgramTimer / profiling benchmark
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results/$(date +%Y%m%d_%H%M%S)}"

BENCH="${1:-all}"

log()  { echo "[bench] $*"; }
mkdir -p "$RESULTS_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark helpers — each compiles a small C driver that uses hyperupcall.h
# ─────────────────────────────────────────────────────────────────────────────

compile_driver() {
    local name="$1"
    local src="$RESULTS_DIR/${name}_driver.c"
    local bin="$RESULTS_DIR/${name}_driver"
    cat > "$src" << EOF
$2
EOF
    gcc -O2 -o "$bin" "$src" \
        -I"$HUC" \
        "$HUC/hyperupcall.c" \
        -lpthread
    echo "$bin"
}

# ─── 1. hypercall: raw vmcall round-trip latency ─────────────────────────────
bench_hypercall() {
    log "=== hypercall: vmcall round-trip latency ($ITERS iterations) ==="

    local BPF_OBJ="$HUC/network/pass/pass.bpf.o"
    [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }

    local bin
    bin=$(compile_driver "hypercall" "
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include \"hyperupcall.h\"

#define ITERS $ITERS

int main(void) {
    struct timespec t0, t1;
    long long total_ns = 0;
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        long slot = load_hyperupcall(\"$BPF_OBJ\");
        if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }
        unload_hyperupcall(slot);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total_ns += (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
    }
    printf(\"hypercall (load+unload) avg latency: %lld ns\\n\", total_ns / ITERS);
    return 0;
}
")
    "$bin" | tee "$RESULTS_DIR/hypercall.txt"
    log "Results saved to $RESULTS_DIR/hypercall.txt"
}

# ─── 2. devnotify: XDP attach → device notification latency ──────────────────
bench_devnotify() {
    log "=== devnotify: XDP hyperupcall device-notification latency ($ITERS iterations) ==="

    local BPF_OBJ="$HUC/network/pass/pass.bpf.o"
    [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }

    local bin
    bin=$(compile_driver "devnotify" "
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include \"hyperupcall.h\"

#define ITERS   $ITERS
#define NETDEV  $NETDEV

int main(void) {
    struct timespec t0, t1;
    long long total_ns = 0;
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        long prog = link_hyperupcall(slot, \"xdp_pass\", HYPERUPCALL_MAJORID_XDP, NETDEV);
        if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }
        unlink_hyperupcall(slot, prog);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total_ns += (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
    }
    unload_hyperupcall(slot);
    printf(\"devnotify (XDP attach+detach) avg latency: %lld ns\\n\", total_ns / ITERS);
    return 0;
}
")
    "$bin" | tee "$RESULTS_DIR/devnotify.txt"
    log "Results saved to $RESULTS_DIR/devnotify.txt"
}

# ─── 3. sendipi: perf-event hyperupcall → IPI delivery latency ───────────────
bench_sendipi() {
    log "=== sendipi: perf-event hyperupcall IPI latency ($ITERS iterations) ==="

    local BPF_OBJ="$HUC/tracing/perf_top.bpf.o"
    [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }

    local bin
    bin=$(compile_driver "sendipi" "
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include \"hyperupcall.h\"

#define ITERS $ITERS
#define FREQ  1   /* 1 Hz — minimal perf event; adjust for IPI measurement */

int main(void) {
    struct timespec t0, t1;
    long long total_ns = 0;
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        long prog = link_hyperupcall(slot, \"perf_top\", HYPERUPCALL_MAJORID_PROFILING, FREQ);
        if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }
        unlink_hyperupcall(slot, prog);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total_ns += (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
    }
    unload_hyperupcall(slot);
    printf(\"sendipi (perf attach+detach) avg latency: %lld ns\\n\", total_ns / ITERS);
    return 0;
}
")
    "$bin" | tee "$RESULTS_DIR/sendipi.txt"
    log "Results saved to $RESULTS_DIR/sendipi.txt"
}

# ─── 4. ProgramTimer: periodic profiling hyperupcall timer overhead ───────────
bench_program_timer() {
    log "=== ProgramTimer: periodic profiling hyperupcall @ ${SAMPLE_FREQ}Hz ==="

    local BPF_OBJ="$HUC/tracing/perf_top.bpf.o"
    [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }

    local bin
    bin=$(compile_driver "program_timer" "
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include \"hyperupcall.h\"

#define SAMPLE_FREQ $SAMPLE_FREQ
#define DURATION_S  5   /* measure for 5 seconds */

int main(void) {
    struct timespec t0, t1;
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    long prog = link_hyperupcall(slot, \"perf_top\",
                                 HYPERUPCALL_MAJORID_PROFILING, SAMPLE_FREQ);
    if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    printf(\"ProgramTimer: profiling hyperupcall running @ %d Hz for %d seconds...\\n\",
           SAMPLE_FREQ, DURATION_S);
    sleep(DURATION_S);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    unlink_hyperupcall(slot, prog);
    unload_hyperupcall(slot);

    long long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000LL
                         + (t1.tv_nsec - t0.tv_nsec) / 1000000LL;
    long long expected_events = (long long)SAMPLE_FREQ * DURATION_S;
    printf(\"ProgramTimer: ran %lld ms, expected ~%lld BPF invocations\\n\",
           elapsed_ms, expected_events);
    return 0;
}
")
    "$bin" | tee "$RESULTS_DIR/program_timer.txt"
    log "Results saved to $RESULTS_DIR/program_timer.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────
log "Results directory: $RESULTS_DIR"

case "$BENCH" in
    hypercall)    bench_hypercall ;;
    devnotify)    bench_devnotify ;;
    sendipi)      bench_sendipi ;;
    ProgramTimer) bench_program_timer ;;
    all)
        bench_hypercall
        bench_devnotify
        bench_sendipi
        bench_program_timer
        log ""
        log "All benchmarks complete. Results in: $RESULTS_DIR"
        ;;
    *)
        echo "Usage: $0 [all|hypercall|devnotify|sendipi|ProgramTimer]"
        echo "  ITERS=$ITERS  NETDEV=$NETDEV  SAMPLE_FREQ=$SAMPLE_FREQ"
        exit 1
        ;;
esac
