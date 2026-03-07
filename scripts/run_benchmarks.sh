#!/usr/bin/env bash
# scripts/run_benchmarks.sh — Run the four L2→L0 hyperupcall micro-benchmarks.
#
# Benchmarks (from TODO.md):
#   1. hypercall      – raw vmcall round-trip latency (load + unload an empty BPF object)
#   2. devnotify      – device-notification latency via XDP hyperupcall
#   3. sendipi        – inter-processor interrupt delivery latency via perf-event hyperupcall
#   4. ProgramTimer   – periodic timer hyperupcall via profiling (perf) event
#
# Modes:
#   baseline   – no hyperupcalls; uses syscalls (getpid, socket/close) for same timing structure.
#   hyperupcall – requires hyperturtle kernel + BPF objects; uses load/link hyperupcalls.
#
# Target: x86 only. Latency is reported in CPU cycles (RDTSC).
#
# Usage:
#   ./scripts/run_benchmarks.sh [all|hypercall|devnotify|sendipi|ProgramTimer]
#   MODE=baseline ./scripts/run_benchmarks.sh all    # run baseline first to verify script
#   MODE=hyperupcall ./scripts/run_benchmarks.sh all
#   ITERS=10000 NETDEV=2 ./scripts/run_benchmarks.sh all

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUC="$REPO_ROOT/hyperupcalls"

# ─── Parameters (override via environment) ────────────────────────────────────
ITERS="${ITERS:-1000}"          # number of iterations per benchmark
NETDEV="${NETDEV:-2}"           # guest virtio-net interface index for XDP/TC
SAMPLE_FREQ="${SAMPLE_FREQ:-1000}"  # Hz for ProgramTimer / profiling benchmark
MODE="${MODE:-baseline}"        # baseline | hyperupcall
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results/$(date +%Y%m%d_%H%M%S)_$MODE}"

BENCH="${1:-all}"

log()  { echo "[bench] $*"; }
mkdir -p "$RESULTS_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark helpers
# ─────────────────────────────────────────────────────────────────────────────

# Hyperupcall mode: compile driver that links hyperupcall.c
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

# Baseline mode: compile standalone C (no hyperupcall lib or BPF)
compile_driver_baseline() {
    local name="$1"
    local src="$RESULTS_DIR/${name}_driver.c"
    local bin="$RESULTS_DIR/${name}_driver"
    cat > "$src" << EOF
$2
EOF
    gcc -O2 -o "$bin" "$src"
    echo "$bin"
}

# x86 only: RDTSC cycle counter + vmcall helper for baseline measurements.
# vmcall causes a real VM exit — exactly what the paper's "VM baseline" measures.
RDTSC_SNIPPET='
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}

/* Issue a single vmcall with hypercall number nr and up to 3 arguments.
   On stock KVM/QEMU this causes a VM exit; the return value may be -ENOSYS
   (unknown hypercall) — that is fine, we only care about the round-trip cost. */
static inline long do_vmcall(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ __volatile__ ("vmcall"
        : "=a" (ret)
        : "a" (nr), "b" (a1), "c" (a2), "d" (a3)
        : "memory");
    return ret;
}
'

# ─── 1. hypercall: raw vmcall round-trip latency ─────────────────────────────
bench_hypercall() {
    if [[ "$MODE" == "baseline" ]]; then
        log "=== hypercall [baseline]: vmcall#13 (load) VM-exit round-trip ($ITERS iterations) ==="
        local bin
        bin=$(compile_driver_baseline "hypercall" "
#include <stdio.h>
#include <stdint.h>

$RDTSC_SNIPPET

#define ITERS $ITERS

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        do_vmcall(13, 0, 0, 0);   /* hyperupcall load vmcall — VM exit to QEMU */
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf(\"hypercall [baseline] avg latency: %llu cycles\\n\", (unsigned long long)(total_cycles / ITERS));
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/hypercall.txt"
    else
        log "=== hypercall [hyperupcall]: vmcall round-trip latency ($ITERS iterations) ==="
        local BPF_OBJ="$HUC/network/pass/pass.bpf.o"
        [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }
        local bin
        bin=$(compile_driver "hypercall" "
#include <stdio.h>
#include <stdint.h>
#include \"hyperupcall.h\"

$RDTSC_SNIPPET

#define ITERS $ITERS

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        long slot = load_hyperupcall(\"$BPF_OBJ\");
        if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }
        unload_hyperupcall(slot);
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf(\"hypercall [hyperupcall] avg latency: %llu %s\\n\", (unsigned long long)(total_cycles / ITERS), \"cycles\");
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/hypercall.txt"
    fi
    log "Results saved to $RESULTS_DIR/hypercall.txt"
}

# ─── 2. devnotify: XDP attach → device notification latency ──────────────────
bench_devnotify() {
    if [[ "$MODE" == "baseline" ]]; then
        log "=== devnotify [baseline]: vmcall#15 (link/XDP) VM-exit round-trip ($ITERS iterations) ==="
        local bin
        bin=$(compile_driver_baseline "devnotify" "
#include <stdio.h>
#include <stdint.h>

$RDTSC_SNIPPET

#define ITERS   $ITERS
#define NETDEV  $NETDEV

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        do_vmcall(15, 0, 0, NETDEV);  /* hyperupcall link vmcall (XDP) — VM exit to QEMU */
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf(\"devnotify [baseline] avg latency: %llu cycles\\n\", (unsigned long long)(total_cycles / ITERS));
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/devnotify.txt"
    else
        log "=== devnotify [hyperupcall]: XDP device-notification latency ($ITERS iterations) ==="
        local BPF_OBJ="$HUC/network/pass/pass.bpf.o"
        [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }
        local bin
        bin=$(compile_driver "devnotify" "
#include <stdio.h>
#include <stdint.h>
#include \"hyperupcall.h\"

$RDTSC_SNIPPET

#define ITERS   $ITERS
#define NETDEV  $NETDEV

int main(void) {
    unsigned long long total_cycles = 0;
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        long prog = link_hyperupcall(slot, \"xdp_pass\", HYPERUPCALL_MAJORID_XDP, NETDEV);
        if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }
        unlink_hyperupcall(slot, prog);
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    unload_hyperupcall(slot);
    printf(\"devnotify [hyperupcall] avg latency: %llu %s\\n\", (unsigned long long)(total_cycles / ITERS), \"cycles\");
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/devnotify.txt"
    fi
    log "Results saved to $RESULTS_DIR/devnotify.txt"
}

# ─── 3. sendipi: perf-event hyperupcall → IPI delivery latency ───────────────
bench_sendipi() {
    if [[ "$MODE" == "baseline" ]]; then
        log "=== sendipi [baseline]: vmcall#15 (link/perf) VM-exit round-trip ($ITERS iterations) ==="
        local bin
        bin=$(compile_driver_baseline "sendipi" "
#include <stdio.h>
#include <stdint.h>

$RDTSC_SNIPPET

#define ITERS $ITERS

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        do_vmcall(15, 0, 1, 1);   /* hyperupcall link vmcall (perf/profiling) — VM exit to QEMU */
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf(\"sendipi [baseline] avg latency: %llu cycles\\n\", (unsigned long long)(total_cycles / ITERS));
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/sendipi.txt"
    else
        log "=== sendipi [hyperupcall]: perf-event IPI latency ($ITERS iterations) ==="
        local BPF_OBJ="$HUC/tracing/perf_top.bpf.o"
        [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }
        local bin
        bin=$(compile_driver "sendipi" "
#include <stdio.h>
#include <stdint.h>
#include \"hyperupcall.h\"

$RDTSC_SNIPPET

#define ITERS $ITERS
#define FREQ  1

int main(void) {
    unsigned long long total_cycles = 0;
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        long prog = link_hyperupcall(slot, \"perf_top\", HYPERUPCALL_MAJORID_PROFILING, FREQ);
        if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }
        unlink_hyperupcall(slot, prog);
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    unload_hyperupcall(slot);
    printf(\"sendipi [hyperupcall] avg latency: %llu %s\\n\", (unsigned long long)(total_cycles / ITERS), \"cycles\");
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/sendipi.txt"
    fi
    log "Results saved to $RESULTS_DIR/sendipi.txt"
}

# ─── 4. ProgramTimer: periodic profiling hyperupcall timer overhead ───────────
bench_program_timer() {
    if [[ "$MODE" == "baseline" ]]; then
        log "=== ProgramTimer [baseline]: getpid() at ${SAMPLE_FREQ}Hz for 5s ==="
        local bin
        bin=$(compile_driver_baseline "program_timer" "
#include <stdio.h>
#include <stdint.h>

$RDTSC_SNIPPET

#define SAMPLE_FREQ $SAMPLE_FREQ
#define DURATION_S  5

int main(void) {
    long long n = (long long)SAMPLE_FREQ * DURATION_S;
    printf(\"ProgramTimer [baseline]: %lld vmcall#19 (timer) VM-exits (equiv %d Hz * %ds)...\\n\",
           (long long)n, SAMPLE_FREQ, DURATION_S);
    unsigned long long sum_cycles = 0;
    unsigned long long t_start = rdtsc();
    for (long long i = 0; i < n; i++) {
        unsigned long long t0 = rdtsc();
        do_vmcall(19, 0, SAMPLE_FREQ, 0);  /* hyperupcall map vmcall (timer/profiling) */
        unsigned long long t1 = rdtsc();
        sum_cycles += (t1 - t0);
    }
    unsigned long long total_cycles = rdtsc() - t_start;
    printf(\"ProgramTimer [baseline]: total %llu cycles, avg %llu cycles/call\\n\",
           (unsigned long long)total_cycles, (unsigned long long)(sum_cycles / n));
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/program_timer.txt"
    else
        log "=== ProgramTimer [hyperupcall]: profiling hyperupcall @ ${SAMPLE_FREQ}Hz ==="
        local BPF_OBJ="$HUC/tracing/perf_top.bpf.o"
        [[ -f "$BPF_OBJ" ]] || { log "ERROR: $BPF_OBJ not found. Run build_hyperupcalls.sh first."; return 1; }
        local bin
        bin=$(compile_driver "program_timer" "
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include \"hyperupcall.h\"

$RDTSC_SNIPPET

#define SAMPLE_FREQ $SAMPLE_FREQ
#define DURATION_S  5

int main(void) {
    long slot = load_hyperupcall(\"$BPF_OBJ\");
    if (slot < 0) { fprintf(stderr, \"load failed\\n\"); return 1; }

    long prog = link_hyperupcall(slot, \"perf_top\",
                                 HYPERUPCALL_MAJORID_PROFILING, SAMPLE_FREQ);
    if (prog < 0) { fprintf(stderr, \"link failed\\n\"); return 1; }

    unsigned long long t_start = rdtsc();
    printf(\"ProgramTimer [hyperupcall]: running @ %d Hz for %d seconds...\\n\",
           SAMPLE_FREQ, DURATION_S);
    sleep(DURATION_S);
    unsigned long long t_end = rdtsc();

    unlink_hyperupcall(slot, prog);
    unload_hyperupcall(slot);

    unsigned long long total_cycles = t_end - t_start;
    long long expected_events = (long long)SAMPLE_FREQ * DURATION_S;
    printf(\"ProgramTimer [hyperupcall]: total %llu %s, expected ~%lld BPF invocations\\n\",
           (unsigned long long)total_cycles, \"cycles\", expected_events);
    return 0;
}
")
        "$bin" | tee "$RESULTS_DIR/program_timer.txt"
    fi
    log "Results saved to $RESULTS_DIR/program_timer.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────
log "Mode: $MODE — Results directory: $RESULTS_DIR"

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
        log "All benchmarks complete [$MODE]. Results in: $RESULTS_DIR"
        ;;
    *)
        echo "Usage: $0 [all|hypercall|devnotify|sendipi|ProgramTimer]"
        echo "  MODE=baseline|hyperupcall  (default: baseline)"
        echo "  ITERS=$ITERS  NETDEV=$NETDEV  SAMPLE_FREQ=$SAMPLE_FREQ"
        exit 1
        ;;
esac
