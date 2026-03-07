# Kernel Benchmarks

```bash
sudo ./scripts/run_benchmarks.sh all                          # hypercall, sendipi, program_timer
sudo MMIO_BASE=0xFEBD4000 ./scripts/run_benchmarks.sh devnotify  # needs device MMIO address
sudo ITERS=10000 TARGET_CPU=2 ./scripts/run_benchmarks.sh all    # override defaults
```

Find `MMIO_BASE` with: `lspci -v | grep "Memory at"`

Results go to `results/<timestamp>/`.
