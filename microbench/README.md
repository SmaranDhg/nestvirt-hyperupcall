# Microbenchmarks

Userspace microbenchmarks reproducing Table 3 of the DVH ASPLOS'20 paper.
Run inside the target VM (L1, L2, or L3) to measure VM-exit costs in CPU cycles.

| Benchmark | What it measures |
|-----------|-----------------|
| `hypercall` | VMCALL round-trip latency |
| `devnotify` | Virtio device notification (MMIO write to notify register) |
| `programtimer` | LAPIC TSC-deadline timer programming (MSR write) |
| `sendipi` | Cross-CPU IPI send + receive (via futex wakeup) |

## Usage

```bash
# Run all benchmarks (recommended)
sudo ./scripts/run_benchmarks.sh all

# Run individual benchmarks
sudo ./scripts/run_benchmarks.sh hypercall
sudo ./scripts/run_benchmarks.sh devnotify
sudo ./scripts/run_benchmarks.sh sendipi
sudo ./scripts/run_benchmarks.sh program_timer
```

Results are saved to `results/<timestamp>/`.

## Requirements

- `gcc`, `make`
- Root (for devnotify PCI mmap and programtimer MSR access)
- `msr` kernel module (loaded automatically by the run script)
- At least 2 vCPUs for `sendipi`

## Building manually

```bash
cd microbench
make          # builds all four binaries
make clean    # removes binaries
```
