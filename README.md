# nestvirt-hyperupcall

Extension of [HyperTurtle](https://github.com/OriBenZur/hyperturtle-linux) (USENIX ATC '25)
to support nested-virtualization hyperupcalls: L2 guests can load eBPF
programs that run at L0 (host kernel) privilege by proxying their vmcalls
through L1 QEMU.

See [SPEC.md](SPEC.md) for the full design specification.

## Repository Structure

```
nestvirt-hyperupcall/
├── SPEC.md                             # proposed specification
├── README.md
├── hyperupcalls/                       # guest-side library (unchanged from HyperTurtle)
│   ├── hyperupcall.c / hyperupcall.h
│   ├── ept_fault/
│   ├── network/
│   └── tracing/
├── hyperturtle-linux/                  # modified kernel files
│   ├── arch/x86/kvm/x86.c             # adds args[4]=is_guest_mode() flag
│   └── arch/x86/kvm/vmx/
│       └── nested.c                   # unchanged (default behaviour correct)
└── hyperturtle-qemu/                   # modified QEMU files
    └── accel/kvm/
        └── kvm-all.c                  # L2 proxy infrastructure
```

## Key Changes

### `hyperturtle-linux/arch/x86/kvm/x86.c`
Sets `vcpu->run->hypercall.args[4] = is_guest_mode(vcpu)` for hyperupcall
cases 13–19. This tells L1 QEMU whether the vmcall originated from an L2
nested guest.

### `hyperturtle-qemu/accel/kvm/kvm-all.c`
Adds the full L2 proxy layer:
- **`handle_l2_hypercall()`** — dispatcher for L2 hyperupcalls
- **`proxy_load_hyperupcall_to_l0()`** — copies BPF ELF from L2 GPA into
  pinned L1 pages, forwards vmcall(13) to L0
- **`proxy_link_hyperupcall_to_l0()`** — copies prog name, forwards vmcall(15)
- **`proxy_map_hyperupcall_map_to_l0()`** — forwards vmcall(17)
- **`proxy_map_elem_to_l0()`** — forwards vmcall(19)
- **`hyperupcall_l2_teardown()`** — called on VM destroy to clean up L0 BPF objects
- **`l2_slot_to_l0_slot[]`** — maps L2-local slots to L0 slots

## Architecture

```
L2 guest  →  vmcall(13-19)
               │
          L1 KVM reflects to L1 QEMU
               │
          L1 QEMU: handle_l2_hypercall()
               ├─ address_space_read() from L2 GPA
               ├─ mmap(MAP_POPULATE) + /proc/self/pagemap
               └─ inline asm vmcall → L0 KVM
                                         │
                                    L0 QEMU: load_hyperupcall()
                                         │
                                    eBPF @ L0 privilege
```

## Build

This repo contains only the modified source files.  To build:

1. Apply `hyperturtle-linux/` files on top of
   [OriBenZur/hyperturtle-linux](https://github.com/OriBenZur/hyperturtle-linux)
   (branch `nestedVirt-HUC`).
2. Apply `hyperturtle-qemu/` files on top of
   [OriBenZur/hyperturtle-qemu](https://github.com/OriBenZur/hyperturtle-qemu).
3. Follow the build instructions in the original
   [hyperturtle readme](https://github.com/OriBenZur/hyperturtle-linux).

## Origin

Based on:
> Ori Ben Zur, Jakob Krebs, Shai Aviram Bergman, Mark Silberstein.
> *Accelerating Nested Virtualization with HyperTurtle.*
> USENIX ATC 2025.
