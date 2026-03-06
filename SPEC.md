# Specification: Nested-Virtualization Hyperupcall Privilege Extension

**Based on:** HyperTurtle (USENIX ATC '25)  
**Repo:** [SmaranDhg/nestvirt-hyperupcall](https://github.com/SmaranDhg/nestvirt-hyperupcall)

---

## 1. Motivation

The original HyperTurtle system allows an **L1 guest** (a VM running directly
under the host QEMU) to load eBPF programs that execute at **L0 privilege**
(the host kernel) via vmcall-based *hyperupcalls*.  This gives the L1 guest
low-latency access to network, tracing, and memory-management primitives that
normally require expensive VM exits.

The research goal (from `TODO.md`) is to extend this so that **L2 guests**
(nested VMs running inside L1's own KVM) can also load eBPF programs that
run at L0 privilege, enabling the full three-level stack to share a common
eBPF execution environment:

```
L0 (host kernel + KVM)   ←  eBPF programs run here
L1 (QEMU + nested KVM)   ←  hyperupcall proxy runs here
L2 (workload VM)         ←  benchmark code runs here; issues vmcalls
```

This is required to measure the four micro-benchmarks
(`hypercall`, `devnotify`, `sendipi`, `ProgramTimer`) from L2 workloads
without requiring the L2 guest to have any special kernel privileges.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| L0   | Physical host kernel (`hyperturtle-linux`) + L0 KVM |
| L1   | QEMU process (`hyperturtle-qemu`) running on L0, managing L2 VMs |
| L2   | Nested VM guest issuing hyperupcalls |
| GPA  | Guest Physical Address (from the perspective of the issuing guest) |
| HVA  | Host Virtual Address (L1 QEMU userspace pointer) |

---

## 3. Current Architecture (L1 → L0 only)

```
L1 guest
  └─ hyperupcall.c: vmcall(13, ptr_array_gpa, size)
        │ VM exit (EXIT_REASON_VMCALL)
        ▼
L0 KVM  arch/x86/kvm/x86.c  kvm_emulate_hypercall()
        │ KVM_EXIT_HYPERCALL → QEMU
        ▼
L0 QEMU accel/kvm/kvm-all.c  handle_hypercall()
        │ load_hyperupcall(): address_space_read() from L1 GPA
        │ bpf_object__open_mem() + bpf_object__load()
        ▼
eBPF program running at L0 kernel privilege
```

L2 guests currently **cannot** issue hyperupcalls.  Any vmcall from L2 is
reflected to L1 QEMU by `nested_vmx_reflect_vmexit()` (`nested.c`), but L1
QEMU has no forwarding path and returns an error.

---

## 4. Target Architecture (L2 → L1 proxy → L0)

```
L2 guest
  └─ hyperupcall.c: vmcall(13, l2_ptr_array_gpa, size)   [unchanged ABI]
        │ VM exit → L1 KVM reflects to L1 QEMU
        ▼
L1 QEMU accel/kvm/kvm-all.c  handle_hypercall()
        │ detects is_nested == 1  (args[4], set by x86.c)
        │ calls handle_l2_hypercall()
        │   ├─ address_space_read(cpu->as, l2_gpa, ...)   ← read from L2
        │   ├─ mmap(MAP_POPULATE) + get_l1_phys()         ← pin in L1
        │   └─ inline asm vmcall(13, l1_ptr_array_phys, size)
        │                    │
        │        (L1 QEMU is in VMX non-root mode; vmcall exits to L0 KVM)
        ▼
L0 KVM  arch/x86/kvm/x86.c  kvm_emulate_hypercall()
        │ KVM_EXIT_HYPERCALL → L0 QEMU   (is_nested = 0, normal L1 path)
        ▼
L0 QEMU accel/kvm/kvm-all.c  handle_hypercall() → load_hyperupcall()
        │ bpf_object__load() into L0 kernel
        ▼
eBPF program running at L0 kernel privilege on behalf of L2
```

**Key insight:** L1 QEMU is a userspace process running *inside* the L1 VM,
which is itself a guest of L0.  The x86 `vmcall` instruction issued by L1
QEMU therefore causes a hardware VM exit to L0's KVM, not to L1's own KVM.
No kernel module or special privilege is needed in L1.

---

## 5. ABI Contract

### From the L2 guest's perspective

The vmcall ABI is **identical** to L1's.  `hyperupcall.c` (and
`hyperupcall.h`) are unchanged.  L2 guests use the same vmcall numbers and
register conventions.

```
vmcall nr | Guest sets                        | Returns
----------|-----------------------------------|--------
13        | RBX=ptr_array_gpa, RCX=size       | L2-local slot ≥ 0 or -1
14        | RBX=l2_slot                       | 0 or -1
15        | RBX=l2_slot, RCX=prog_name_gpa,   | program_slot or -1
          | RDX=major_id, RSI=minor_id        |
16        | RBX=l2_slot, RCX=prog_slot        | 0 or -1
17        | RBX=l2_slot, RCX=map_name_gpa     | map_slot or -1
18        | RBX=l2_slot, RCX=map_slot         | 0 or -1
19        | RBX=l2_slot, RCX=attr_gpa         | 0 or -1
```

**Slot semantics:** The slot returned by vmcall 13 is an **L2-local** slot
(index into `l2_slot_to_l0_slot[]` in L1 QEMU).  It is **not** the same as
the L0 slot.  Subsequent calls (link, unload, map) pass this L2-local slot.
L1 QEMU translates it to the corresponding L0 slot before forwarding.

### L0 KVM → L1 QEMU: the `is_nested` flag

`arch/x86/kvm/x86.c` sets `vcpu->run->hypercall.args[4]` to `1` when the
vmcall originates from an L2 guest (`is_guest_mode(vcpu) == true`) and `0`
otherwise.  L1 QEMU reads this as the `is_nested` argument to
`handle_hypercall()`.

---

## 6. Implementation Details

### 6.1  `hyperturtle-linux/arch/x86/kvm/x86.c`

**File:** `arch/x86/kvm/x86.c`  
**Function:** `kvm_emulate_hypercall()`

Add one line per case 13–19:

```c
vcpu->run->hypercall.args[4] = is_guest_mode(vcpu) ? 1 : 0;
```

`args[4]` was previously unused and is zero-initialized by the kernel.
No ABI breakage for existing L1 callers (they ignore this field).

### 6.2  `hyperturtle-qemu/accel/kvm/kvm-all.c`

#### New global state

```c
#define MAX_L2_HYPERUPCALL_OBJS  16

static long  l2_slot_to_l0_slot[MAX_L2_HYPERUPCALL_OBJS]; /* L2→L0 slot map */
static bool  l2_slot_used[MAX_L2_HYPERUPCALL_OBJS];
static pthread_mutex_t l2_hyperupcalls_lock;
```

#### New helper functions

| Function | Purpose |
|----------|---------|
| `hyperupcall_proxy_get_l1_phys(vaddr)` | Read `/proc/self/pagemap` to get L1 physical address of a pinned userspace page |
| `hyperupcall_proxy_alloc_pinned(size)` | `mmap(MAP_ANONYMOUS\|MAP_POPULATE)` — forces physical page allocation |
| `proxy_vmcall1/2/4(nr, ...)` | Inline-asm vmcall with 1/2/4 arguments (same convention as `hyperupcall.c`) |
| `proxy_load_hyperupcall_to_l0(cpu, attrs, l2_ptr_array_gpa, len)` | vmcall 13 proxy |
| `proxy_link_hyperupcall_to_l0(cpu, l0_slot, prog_name_gpa, major, minor)` | vmcall 15 proxy |
| `proxy_map_hyperupcall_map_to_l0(cpu, l0_slot, map_name_gpa)` | vmcall 17 proxy |
| `proxy_map_elem_to_l0(cpu, l0_slot, attr_gpa)` | vmcall 19 proxy |
| `handle_l2_hypercall(cpu, attrs, nr, a0..a3)` | Main L2 dispatcher |
| `hyperupcall_l2_teardown()` | Unload all L2-proxied objects from L0 |

#### `handle_hypercall()` signature change

```c
/* Before */
static int handle_hypercall(CPUState *cpu, MemTxAttrs attrs,
    unsigned long nr, unsigned long a0, unsigned long a1,
    unsigned long a2, unsigned long a3);

/* After */
static int handle_hypercall(CPUState *cpu, MemTxAttrs attrs,
    unsigned long nr, unsigned long a0, unsigned long a1,
    unsigned long a2, unsigned long a3,
    unsigned long is_nested);   /* NEW: set by x86.c args[4] */
```

When `is_nested != 0` and `nr` ∈ {13..19}, the call is delegated to
`handle_l2_hypercall()` instead of the local handlers.

#### `kvm_cpu_exec()` call-site change

```c
/* Before */
run->hypercall.ret = handle_hypercall(cpu, attrs,
    run->hypercall.nr,
    run->hypercall.args[0], run->hypercall.args[1],
    run->hypercall.args[2], run->hypercall.args[3]);

/* After */
run->hypercall.ret = handle_hypercall(cpu, attrs,
    run->hypercall.nr,
    run->hypercall.args[0], run->hypercall.args[1],
    run->hypercall.args[2], run->hypercall.args[3],
    run->hypercall.args[4]);   /* is_nested */
```

#### Teardown hook

`kvm_destroy_vcpu()` calls `hyperupcall_l2_teardown()` on CPU 0 destruction,
which iterates `l2_slot_used[]` and issues `proxy_vmcall1(14, l0_slot)` for
each active slot.

### 6.3  `hyperturtle-linux/arch/x86/kvm/vmx/nested.c`

**No changes required.**

`nested_vmx_reflect_vmexit()` already reflects `EXIT_REASON_VMCALL` exits
from L2 to L1 QEMU (it is not in `nested_vmx_l0_wants_exit()`'s allow-list).
This is the desired behaviour: L1 QEMU receives the exit and runs the proxy.

A future optimisation (direct L0 interception, skipping L1) would add:

```c
case EXIT_REASON_VMCALL: {
    unsigned long nr = kvm_rax_read(vcpu);
    if (nr >= 13 && nr <= 23)
        return true;   /* L0 handles directly */
    break;
}
```

### 6.4  `hyperupcalls/hyperupcall.c` — unchanged

L2 guests use the same library and the same vmcall numbers as L1.

---

## 7. GPA Translation

When L1 QEMU forwards vmcall 13, it must translate L2 GPAs into L1 physical
addresses suitable for passing to L0.  The steps are:

1. **`address_space_read(cpu->as, l2_gpa, ...)`** — reads from L2's address
   space.  `cpu->as` for an L2 vCPU points to L2's physical memory, which L1
   QEMU manages directly.

2. **`mmap(MAP_ANONYMOUS | MAP_POPULATE)`** — allocates a pinned L1 userspace
   buffer.  `MAP_POPULATE` forces all physical pages to be faulted in before
   the pagemap lookup.

3. **`/proc/self/pagemap`** — translates L1 virtual address → L1 physical
   frame number.  This is identical to `getPhysicalAddress()` in
   `hyperupcall.c`.

4. The resulting L1 physical addresses are passed to L0's vmcall 13, which
   then calls `address_space_read(cpu->as, l1_gpa, ...)` using L1's address
   space — the same path as for a direct L1 hyperupcall.

---

## 8. Lifecycle

```
L2 start
  │
  ├─ vmcall(13) → L1 proxy → l2_slot_to_l0_slot[l2_s] = l0_s   (load)
  ├─ vmcall(15) → L1 proxy → forward with l0_s                  (link)
  │    ...
  ├─ vmcall(16) → L1 proxy → forward with l0_s                  (unlink)
  └─ vmcall(14) → L1 proxy → l2_free_slot(l2_s)                 (unload)

L2 abnormal exit (crash, killed)
  └─ kvm_destroy_vcpu(cpu=0) → hyperupcall_l2_teardown()
       └─ for each l2_slot_used[i]: proxy_vmcall1(14, l0_slot[i])
```

---

## 9. Files Changed Summary

| File | Change |
|------|--------|
| `hyperturtle-linux/arch/x86/kvm/x86.c` | Add `args[4] = is_guest_mode(vcpu)` for cases 13–19 |
| `hyperturtle-qemu/accel/kvm/kvm-all.c` | Add L2 proxy infrastructure (~350 lines), update `handle_hypercall()` signature and `kvm_destroy_vcpu()` teardown |
| `hyperturtle-linux/arch/x86/kvm/vmx/nested.c` | No change (default behaviour is correct) |
| `hyperupcalls/hyperupcall.c` | No change |

---

## 10. Testing

To verify the extension:

1. Build `hyperturtle-linux` and install it on the L0 host.
2. Start L1 VM via `hyperturtle-qemu`.
3. Start L1's own KVM + QEMU inside the L1 VM (nested).
4. Run `hyperupcalls/network/pass` or any benchmark from L2.
5. Observe that the eBPF program is loaded in L0's kernel:
   ```
   sudo bpftool prog list   # run on L0
   ```
6. Confirm L1 QEMU logs show `proxy_load: L0 slot = N`.
7. Confirm teardown: after L2 exits, slot N no longer appears in `bpftool`.
