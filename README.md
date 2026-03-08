# nestvirt-hyperupcall

Extension of [HyperTurtle](https://github.com/OriBenZur/hyperturtle-linux) (USENIX ATC '25)
to support **nested-virtualization hyperupcalls**: L2 guests can load eBPF
programs that execute at L0 (host kernel) privilege by proxying their vmcalls
through L1 QEMU.

See [SPEC.md](SPEC.md) for the full design specification.

---

## Quick Start (Ubuntu 20.04, CloudLab or bare metal)

```bash
# 1. Clone with submodules (downloads full kernel + QEMU source — ~3 GB)
git clone --recurse-submodules https://github.com/SmaranDhg/nestvirt-hyperupcall
cd nestvirt-hyperupcall

# 2. Build kernel, libbpf, and QEMU in one step
./setup.sh

# 3. Reboot into the new kernel
sudo reboot

# 4. Create an L1 disk image (if you don't have one yet)
qemu-img create -f qcow2 ~/l1.qcow2 60G
# Install Ubuntu 20.04 into it, boot once, install the same hyperturtle kernel inside

# 5. Launch L1 VM
./scripts/launch_l1.sh

# 6. Inside L1 — build hyperupcall programs
./scripts/build_hyperupcalls.sh

# 7. Inside L2 — run the four micro-benchmarks (userspace)
sudo ./scripts/run_benchmarks.sh all
```

Individual benchmark:

```bash
sudo ./scripts/run_benchmarks.sh hypercall       # vmcall round-trip latency
sudo ./scripts/run_benchmarks.sh devnotify        # virtio MMIO notification latency
sudo ./scripts/run_benchmarks.sh sendipi          # cross-CPU IPI latency
sudo ./scripts/run_benchmarks.sh program_timer    # LAPIC TSC-deadline timer latency
```

---

## Repository Structure

```
nestvirt-hyperupcall/
├── setup.sh                            # one-shot build script
├── SPEC.md                             # nested-virt hyperupcall design spec
├── README.md
│
├── microbench/                         # userspace microbenchmarks (Table 3, DVH ASPLOS'20)
│   ├── hypercall.c                     # vmcall round-trip latency
│   ├── devnotify.c                     # virtio MMIO notification latency
│   ├── programtimer.c                  # LAPIC TSC-deadline timer latency
│   ├── sendipi.c                       # cross-CPU IPI latency
│   └── Makefile
│
├── scripts/
│   ├── launch_l1.sh                    # start L1 VM (parameterised QEMU command)
│   ├── build_hyperupcalls.sh           # build eBPF programs for benchmarks (run in L1)
│   └── run_benchmarks.sh               # build & run microbenchmarks (run in L1/L2/L3)
│
├── hyperupcalls/                       # guest-side library (unchanged from HyperTurtle)
│   ├── hyperupcall.c / hyperupcall.h   # vmcall ABI — used by L1 and L2 identically
│   ├── network/pass/                   # XDP/TC pass-through (for hypercall, devnotify benchmarks)
│   └── tracing/                        # perf_top (for sendipi, ProgramTimer benchmarks)
│
├── hyperturtle-linux/                  # kernel modifications (patch files)
│   ├── src/                            # ← full kernel tree (git submodule)
│   ├── arch/x86/kvm/x86.c             # sets args[4]=is_guest_mode() for cases 13-19
│   ├── arch/x86/kvm/vmx/nested.c      # unchanged
│   └── include/linux/kvm_host.h       # unchanged
│
└── hyperturtle-qemu/                   # QEMU modifications (patch files)
    ├── src/                            # ← full QEMU tree (git submodule)
    └── accel/kvm/kvm-all.c             # L2 proxy infrastructure
```

`setup.sh` initialises the submodules and copies our modified files into `src/`
before building, so you always get the patched versions.

---

## Key Changes

### `hyperturtle-linux/arch/x86/kvm/x86.c`

Sets `vcpu->run->hypercall.args[4] = is_guest_mode(vcpu)` for hyperupcall
cases 13–19. When non-zero, L1 QEMU knows the vmcall came from an L2 nested
guest and routes it through the proxy instead of handling it locally.

### `hyperturtle-qemu/accel/kvm/kvm-all.c`

Adds the full L2 proxy layer:

| Function | Purpose |
|----------|---------|
| `handle_l2_hypercall()` | dispatcher: detects `is_nested==1`, routes to proxy |
| `proxy_load_hyperupcall_to_l0()` | reads BPF ELF from L2 GPA, pins in L1, re-issues vmcall(13) to L0 |
| `proxy_link_hyperupcall_to_l0()` | copies prog name from L2 GPA, forwards vmcall(15) |
| `proxy_map_hyperupcall_map_to_l0()` | forwards vmcall(17) |
| `proxy_map_elem_to_l0()` | forwards vmcall(19) |
| `hyperupcall_l2_teardown()` | called on VM destroy — unloads all L2 BPF objects from L0 |
| `l2_slot_to_l0_slot[]` | maps L2-local slot numbers to L0 slot numbers |

### `hyperupcalls/` — unchanged

L2 guests use the exact same vmcall ABI as L1. The `hyperupcall.c` library
and all programs are unmodified.

---

## Architecture

```
L2 guest  →  vmcall(13-19)  [same hyperupcall.h ABI]
               │
          L1 KVM: reflects vmcall exit to L1 QEMU
               │
          L1 QEMU: handle_l2_hypercall()
               ├─ address_space_read() from L2 GPA
               ├─ mmap(MAP_POPULATE) + /proc/self/pagemap  (pin in L1 phys)
               └─ inline asm vmcall → L0 KVM
                                        │
                                   L0 QEMU: load_hyperupcall()
                                        │
                                   eBPF @ L0 kernel privilege
```

Because L1 QEMU is a process running inside the L1 VM (VMX non-root mode),
its inline `vmcall` exits directly to L0's KVM — no kernel module needed.

---

## Hardware Requirements

Two servers (e.g. CloudLab `c8220` nodes):

| Node | Role | Requirements |
|------|------|-------------|
| L0   | Bare-metal hypervisor | Ubuntu 20.04, VT-x + EPT, nested-virt capable |
| Loadgen | Load generator | Ubuntu 20.04, experiment-network cable to L0 |

Recommended: 2× Xeon 16-core, 256 GiB RAM, SMT off. See the
[HyperTurtle paper](https://www.usenix.org/conference/atc25/presentation/zur)
for exact CloudLab profile settings.

---

## Configuration

All runtime parameters are environment variables:

```bash
# launch_l1.sh
DISK_IMG=~/l1.qcow2  CPUS=12  MEM=64G  SSH_PORT=2222  TAP_IFACE=tap0

# run_benchmarks.sh
RESULTS_DIR=./results/run1
```

---

## Origin

Based on:
> Ori Ben Zur, Jakob Krebs, Shai Aviram Bergman, Mark Silberstein.
> *Accelerating Nested Virtualization with HyperTurtle.*
> USENIX ATC 2025. Pages 987–1002.
> https://www.usenix.org/conference/atc25/presentation/zur
