# IPI benchmark (kernel module)

Measures **request-IPI** latency (send + handle) in CPU cycles using `smp_call_function_single()`. Same privileged operation as the userspace **sendipi** benchmark; this is the in-kernel / bare-metal implementation.

**Build and run on Linux** (e.g. L1 VM or bare-metal host); requires kernel headers for the running kernel.

## Build

```bash
make
# Or against a specific kernel tree:
make KDIR=/path/to/linux
```

## Run

```bash
sudo insmod ipi_bench.ko
dmesg | tail
```

Optional parameters:

- `target_cpu=N` — target CPU (default 1)
- `iters=N` — iterations (default 1000)

```bash
sudo insmod ipi_bench.ko target_cpu=1 iters=10000
dmesg | tail
```

## Unload

```bash
sudo rmmod ipi_bench
```

## Output

Example:

```
ipi_bench: request-IPI latency, CPU 0 -> CPU 1, 1000 iterations
ipi_bench: avg latency 2847 cycles (send+handle)
```

Compare with userspace benchmarks (same operation, different implementation):

- **sendipi [baseline]** — vmcall path (e.g. in a VM)
- **sendipi [hyperupcall]** — eBPF hyperupcall path
- **This module** — native kernel IPI on bare metal
