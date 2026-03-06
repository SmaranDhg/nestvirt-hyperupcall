/*
 * QEMU KVM support
 *
 * Copyright IBM, Corp. 2008
 *           Red Hat, Inc. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Glauber Costa     <gcosta@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>
#include <linux/kvm.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <net/if.h>

#include "monitor/qdev.h"
#include "monitor/hmp.h"
#include "monitor/monitor.h"
#include "vdpa-helpers.h"

#include "qemu/atomic.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/s390x/adapter.h"
#include "exec/gdbstub.h"
#include "sysemu/kvm_int.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "qemu/bswap.h"
#include "exec/memory.h"
#include "exec/ram_addr.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"
#include "qemu/typedefs.h"
#include "net/vhost_net.h"
#include "net/vhost-vdpa.h"
#include "net/clients.h"
#include "net/net.h"
#include "net/hub.h"
#include "net/tap.h"
#include "trace.h"
#include "hw/irq.h"
#include "qapi/visitor.h"
#include "qapi/qapi-types-common.h"
#include "qapi/qapi-visit-common.h"
#include "sysemu/reset.h"
#include "qemu/guest-random.h"
#include "sysemu/hw_accel.h"
#include "kvm-cpus.h"
#include "sysemu/dirtylimit.h"
#include "net/tap_int.h"

#include "hw/boards.h"
#include "monitor/stats.h"

#include "qapi/qmp/qdict.h"
#include "include/hw/qdev-core.h"
#include "include/qom/object_interfaces.h"

struct Error
{
    char *msg;
    ErrorClass err_class;
    const char *src, *func;
    int line;
    GString *hint;
};

/* This check must be after config-host.h is included */
#ifdef CONFIG_EVENTFD
#include <sys/eventfd.h>
#endif

/* KVM uses PAGE_SIZE in its definition of KVM_COALESCED_MMIO_MAX. We
 * need to use the real host PAGE_SIZE, as that's what KVM will use.
 */
#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif
#define PAGE_SIZE qemu_real_host_page_size()

#ifndef KVM_GUESTDBG_BLOCKIRQ
#define KVM_GUESTDBG_BLOCKIRQ 0
#endif

//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

struct KVMParkedVcpu {
    unsigned long vcpu_id;
    int kvm_fd;
    QLIST_ENTRY(KVMParkedVcpu) node;
};

KVMState *kvm_state;
bool kvm_kernel_irqchip;
bool kvm_split_irqchip;
bool kvm_async_interrupts_allowed;
bool kvm_halt_in_kernel_allowed;
bool kvm_eventfds_allowed;
bool kvm_irqfds_allowed;
bool kvm_resamplefds_allowed;
bool kvm_msi_via_irqfd_allowed;
bool kvm_gsi_routing_allowed;
bool kvm_gsi_direct_mapping;
bool kvm_allowed;
bool kvm_readonly_mem_allowed;
bool kvm_vm_attributes_allowed;
bool kvm_direct_msi_allowed;
bool kvm_ioeventfd_any_length_allowed;
bool kvm_msi_use_devid;
bool kvm_has_guest_debug;
static int kvm_sstep_flags;
static bool kvm_immediate_exit;
static hwaddr kvm_max_slot_size = ~0;

static const KVMCapabilityInfo kvm_required_capabilites[] = {
    KVM_CAP_INFO(USER_MEMORY),
    KVM_CAP_INFO(DESTROY_MEMORY_REGION_WORKS),
    KVM_CAP_INFO(JOIN_MEMORY_REGIONS_WORKS),
    KVM_CAP_LAST_INFO
};

static NotifierList kvm_irqchip_change_notifiers =
    NOTIFIER_LIST_INITIALIZER(kvm_irqchip_change_notifiers);

struct KVMResampleFd {
    int gsi;
    EventNotifier *resample_event;
    QLIST_ENTRY(KVMResampleFd) node;
};
typedef struct KVMResampleFd KVMResampleFd;

/*
 * Only used with split irqchip where we need to do the resample fd
 * kick for the kernel from userspace.
 */
static QLIST_HEAD(, KVMResampleFd) kvm_resample_fd_list =
    QLIST_HEAD_INITIALIZER(kvm_resample_fd_list);

static QemuMutex kml_slots_lock;

#define kvm_slots_lock()    qemu_mutex_lock(&kml_slots_lock)
#define kvm_slots_unlock()  qemu_mutex_unlock(&kml_slots_lock)

static void kvm_slot_init_dirty_bitmap(KVMSlot *mem);


#define MAX_NUM_HYPERUPCALL_OBJS 16
#define HYPERUPCALL_N_PROGRAM_SLOTS 8
#define HYPERUPCALL_N_MAP_SLOTS 8
#define HYPERUPCALL_PROG_NAME_LEN 1024
#define HYPERUPCALL_MAX_N_MEMSLOTS 128


enum {
    HYPERUPCALL_MAJORID_XDP = 0,
    HYPERUPCALL_MAJORID_PAGEFAULT,
    HYPERUPCALL_MAJORID_TC_EGRESS,
    HYPERUPCALL_MAJORID_DIRECT_EXE,
    HYPERUPCALL_MAJORID_TC_INGRESS,
    HYPERUPCALL_MAJORID_PROFILING,
    HYPERUPCALL_MAJORID_MAX,
};


/**
 * Struct to hold hyperupcall information. Temporarily holds one link.
 * 
 * @obj: BPF object.
 * @nr_attachments: number of BPF programs.
 * @links: array of BPF link ptrs.
 * @hooks: array of BPF hook ptrs. either links or hooks are used for a specific program, not both.
 * @progs: array of BPF program ptrs. progs[i] holds the program for links[i]. Duplicates may occur.
 * @major_ids: array of major IDs.
 * @minor_ids: array of minor IDs.
 * 
 * @lock: lock to protect hyperupcall struct. Currently not in use - use global hyperupcalls_lock instead.
*/
struct HyperUpCall {
    struct bpf_object *obj;
	struct bpf_link *links[HYPERUPCALL_N_PROGRAM_SLOTS];
    struct bpf_tc_hook hooks[HYPERUPCALL_N_PROGRAM_SLOTS];
    struct bpf_program *progs[HYPERUPCALL_N_PROGRAM_SLOTS];
    int major_ids[HYPERUPCALL_N_PROGRAM_SLOTS];
    int minor_ids[HYPERUPCALL_N_PROGRAM_SLOTS];
    void *mmaped_map_ptrs[HYPERUPCALL_N_MAP_SLOTS];
    struct bpf_map *maps[HYPERUPCALL_N_MAP_SLOTS];
    

    pthread_mutex_t lock;
};

static const char * const memory_backend_ids[HYPERUPCALL_N_MAP_SLOTS] = {"hp0", "hp1", "hp2", "hp3", "hp4", "hp5", "hp6", "hp7"};
static const char * const memory_backend_names[HYPERUPCALL_N_MAP_SLOTS] = {"bpf_map_obj0", "bpf_map_obj1", "bpf_map_obj2", "bpf_map_obj3", "bpf_map_obj4", "bpf_map_obj5", "bpf_map_obj6", "bpf_map_obj7"};
static const char * const memory_devices_names[HYPERUPCALL_N_MAP_SLOTS] = {"bpf_map_dev0", "bpf_map_dev1", "bpf_map_dev2", "bpf_map_dev3", "bpf_map_dev4", "bpf_map_dev5", "bpf_map_dev6", "bpf_map_dev7"};
static unsigned short used_memslots;
static unsigned long long memslot_base_gfns_local[HYPERUPCALL_MAX_N_MEMSLOTS];
static unsigned long long memslot_npages_local[HYPERUPCALL_MAX_N_MEMSLOTS];
static unsigned long long memslot_userptrs_local[HYPERUPCALL_MAX_N_MEMSLOTS];
static unsigned int memslot_as_id[HYPERUPCALL_MAX_N_MEMSLOTS];

static const char *memory_backend_bh = NULL;

struct HyperUpCall hyperupcalls[MAX_NUM_HYPERUPCALL_OBJS] = {0};
pthread_mutex_t hyperupcalls_lock;

/*
 * L2 nested-VM hyperupcall proxy support.
 *
 * When an L2 guest (running inside L1's nested KVM) issues a vmcall 13-19,
 * L1's KVM reflects the exit to L1 QEMU.  L1 QEMU detects the call came
 * from an L2 vCPU (args[4] == 1, set by x86.c when is_guest_mode(vcpu)),
 * reads the relevant data from L2's address space, copies it into pinned
 * L1 userspace pages, and re-issues the vmcall to L0 KVM using inline asm.
 * Because L1 QEMU runs inside the L1 VM (VMX non-root mode), its vmcall
 * exits directly to L0's KVM — no kernel forwarding module required.
 *
 * l2_slot_to_l0_slot[i] tracks which L0 hyperupcall slot corresponds to
 * L2-requested slot i.  This mapping is needed so that when L2 calls
 * unload(slot=X), L1 QEMU knows which L0 slot to forward the unload to.
 */
#define MAX_L2_HYPERUPCALL_OBJS 16

static long  l2_slot_to_l0_slot[MAX_L2_HYPERUPCALL_OBJS];
static bool  l2_slot_used[MAX_L2_HYPERUPCALL_OBJS];
static pthread_mutex_t l2_hyperupcalls_lock;
static int   l2_hyperupcalls_initialized = 0;

/* ------------------------------------------------------------------ */
/* Helpers: L1 physical address lookup via /proc/self/pagemap          */
/* ------------------------------------------------------------------ */

static int l1_pagemap_fd = -1;

static uintptr_t hyperupcall_proxy_get_l1_phys(void *vaddr)
{
    uint64_t pfn;
    off_t offset = (off_t)((uintptr_t)vaddr / PAGE_SIZE) * sizeof(uint64_t);

    if (l1_pagemap_fd < 0) {
        l1_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
        if (l1_pagemap_fd < 0) {
            perror("hyperupcall_proxy: open pagemap");
            return 0;
        }
    }
    if (pread(l1_pagemap_fd, &pfn, sizeof(pfn), offset) != sizeof(pfn))
        return 0;
    if (!(pfn & (1ULL << 63)))   /* page not present */
        return 0;
    pfn &= 0x7FFFFFFFFFFFFFULL;
    return (pfn << PAGE_SHIFT) | ((uintptr_t)vaddr & (PAGE_SIZE - 1));
}

/* Allocate a pinned anonymous page (MAP_POPULATE forces physical backing). */
static void *hyperupcall_proxy_alloc_pinned(size_t size)
{
    return mmap(NULL, ROUND_UP(size, PAGE_SIZE),
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                -1, 0);
}

/* ------------------------------------------------------------------ */
/* L2 slot allocator                                                   */
/* ------------------------------------------------------------------ */

static int l2_alloc_slot(void)
{
    for (int i = 0; i < MAX_L2_HYPERUPCALL_OBJS; i++) {
        if (!l2_slot_used[i]) {
            l2_slot_used[i] = true;
            return i;
        }
    }
    return -1;
}

static void l2_free_slot(int slot)
{
    if (slot >= 0 && slot < MAX_L2_HYPERUPCALL_OBJS) {
        l2_slot_used[slot] = false;
        l2_slot_to_l0_slot[slot] = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Inline-asm vmcall helpers (same ABI as hyperupcall.c)               */
/* ------------------------------------------------------------------ */

static long proxy_vmcall1(unsigned long nr, unsigned long a0)
{
    long ret;
    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(ret)
        : "r"(nr), "r"(a0)
        : "%rax", "%rbx");
    return ret;
}

static long proxy_vmcall2(unsigned long nr, unsigned long a0,
                          unsigned long a1)
{
    long ret;
    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(ret)
        : "r"(nr), "r"(a0), "r"(a1)
        : "%rax", "%rbx", "%rcx");
    return ret;
}

static long proxy_vmcall4(unsigned long nr, unsigned long a0,
                          unsigned long a1, unsigned long a2,
                          unsigned long a3)
{
    long ret;
    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "movq %4, %%rdx;"
        "movq %5, %%rsi;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(ret)
        : "r"(nr), "r"(a0), "r"(a1), "r"(a2), "r"(a3)
        : "%rax", "%rbx", "%rcx", "%rdx", "%rsi");
    return ret;
}

/* ------------------------------------------------------------------ */
/* vmcall 13 proxy: load BPF ELF from L2 GPA → copy → forward to L0  */
/* ------------------------------------------------------------------ */

static long proxy_load_hyperupcall_to_l0(CPUState *cpu, MemTxAttrs attrs,
                                          unsigned long l2_ptr_array_gpa,
                                          unsigned long program_len)
{
    int program_pages = DIV_ROUND_UP(program_len, PAGE_SIZE);
    hwaddr l2_gptrs[PAGE_SIZE / sizeof(hwaddr)];
    char *binary = NULL;
    uintptr_t *l1_ptr_array = NULL;
    uintptr_t ptr_array_phys;
    long l0_slot;
    MemTxResult mtr;

    if (program_pages > (int)(PAGE_SIZE / sizeof(hwaddr))) {
        fprintf(stderr, "proxy_load: program too large (%lu bytes)\n",
                program_len);
        return -1;
    }

    /* Step 1: read L2's ptr_array (array of L2 GPAs, one per page) */
    mtr = address_space_read(cpu->as, l2_ptr_array_gpa,
                             MEMTXATTRS_UNSPECIFIED,
                             l2_gptrs,
                             program_pages * sizeof(hwaddr));
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "proxy_load: read L2 ptr_array failed %d\n", mtr);
        return -1;
    }

    /* Step 2: allocate a pinned L1 buffer and copy BPF pages from L2 */
    binary = hyperupcall_proxy_alloc_pinned(program_len);
    if (binary == MAP_FAILED) {
        perror("proxy_load: mmap binary");
        return -1;
    }

    for (int i = 0; i < program_pages; i++) {
        mtr = address_space_read(cpu->as, l2_gptrs[i], attrs,
                                 binary + i * PAGE_SIZE, PAGE_SIZE);
        if (mtr != MEMTX_OK) {
            fprintf(stderr, "proxy_load: read L2 page %d failed %d\n",
                    i, mtr);
            munmap(binary, ROUND_UP(program_len, PAGE_SIZE));
            return -1;
        }
    }

    /* Step 3: allocate a pinned page for the new L1 ptr_array */
    l1_ptr_array = hyperupcall_proxy_alloc_pinned(PAGE_SIZE);
    if (l1_ptr_array == MAP_FAILED) {
        perror("proxy_load: mmap ptr_array");
        munmap(binary, ROUND_UP(program_len, PAGE_SIZE));
        return -1;
    }

    /* Step 4: fill in L1 physical addresses of each BPF page */
    for (int i = 0; i < program_pages; i++) {
        l1_ptr_array[i] = hyperupcall_proxy_get_l1_phys(
                               binary + i * PAGE_SIZE);
        if (l1_ptr_array[i] == 0) {
            fprintf(stderr, "proxy_load: get_l1_phys page %d failed\n", i);
            munmap(binary, ROUND_UP(program_len, PAGE_SIZE));
            munmap(l1_ptr_array, PAGE_SIZE);
            return -1;
        }
    }

    /* Step 5: get L1 physical address of the ptr_array page */
    ptr_array_phys = hyperupcall_proxy_get_l1_phys(l1_ptr_array);
    if (ptr_array_phys == 0) {
        fprintf(stderr, "proxy_load: get_l1_phys ptr_array failed\n");
        munmap(binary, ROUND_UP(program_len, PAGE_SIZE));
        munmap(l1_ptr_array, PAGE_SIZE);
        return -1;
    }

    /* Step 6: forward vmcall(13) to L0 */
    l0_slot = proxy_vmcall2(13, (unsigned long)ptr_array_phys,
                             (unsigned long)program_len);

    munmap(binary, ROUND_UP(program_len, PAGE_SIZE));
    munmap(l1_ptr_array, PAGE_SIZE);

    fprintf(stderr, "proxy_load: L0 slot = %ld\n", l0_slot);
    return l0_slot;
}

/* ------------------------------------------------------------------ */
/* vmcall 15 proxy: link — copy prog_name from L2 GPA, forward        */
/* ------------------------------------------------------------------ */

static long proxy_link_hyperupcall_to_l0(CPUState *cpu,
                                          unsigned long l0_slot,
                                          unsigned long prog_name_gpa,
                                          unsigned long major_id,
                                          unsigned long minor_id)
{
    char *name_page;
    uintptr_t name_phys;
    long ret;
    MemTxResult mtr;

    name_page = hyperupcall_proxy_alloc_pinned(PAGE_SIZE);
    if (name_page == MAP_FAILED) {
        perror("proxy_link: mmap name_page");
        return -1;
    }

    mtr = address_space_read(cpu->as, prog_name_gpa,
                             MEMTXATTRS_UNSPECIFIED,
                             name_page, HYPERUPCALL_PROG_NAME_LEN);
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "proxy_link: read prog_name failed %d\n", mtr);
        munmap(name_page, PAGE_SIZE);
        return -1;
    }
    name_page[HYPERUPCALL_PROG_NAME_LEN - 1] = '\0';

    name_phys = hyperupcall_proxy_get_l1_phys(name_page);
    if (name_phys == 0) {
        fprintf(stderr, "proxy_link: get_l1_phys name_page failed\n");
        munmap(name_page, PAGE_SIZE);
        return -1;
    }

    ret = proxy_vmcall4(15, l0_slot, name_phys, major_id, minor_id);
    munmap(name_page, PAGE_SIZE);
    return ret;
}

/* ------------------------------------------------------------------ */
/* vmcall 17 proxy: map BPF map — copy map_name from L2 GPA, forward  */
/* ------------------------------------------------------------------ */

static long proxy_map_hyperupcall_map_to_l0(CPUState *cpu,
                                             unsigned long l0_slot,
                                             unsigned long map_name_gpa)
{
    char *name_page;
    uintptr_t name_phys;
    long ret;
    MemTxResult mtr;

    name_page = hyperupcall_proxy_alloc_pinned(PAGE_SIZE);
    if (name_page == MAP_FAILED) {
        perror("proxy_map_map: mmap name_page");
        return -1;
    }

    mtr = address_space_read(cpu->as, map_name_gpa,
                             MEMTXATTRS_UNSPECIFIED,
                             name_page, HYPERUPCALL_PROG_NAME_LEN);
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "proxy_map_map: read map_name failed %d\n", mtr);
        munmap(name_page, PAGE_SIZE);
        return -1;
    }
    name_page[HYPERUPCALL_PROG_NAME_LEN - 1] = '\0';

    name_phys = hyperupcall_proxy_get_l1_phys(name_page);
    if (name_phys == 0) {
        fprintf(stderr, "proxy_map_map: get_l1_phys failed\n");
        munmap(name_page, PAGE_SIZE);
        return -1;
    }

    ret = proxy_vmcall2(17, l0_slot, name_phys);
    munmap(name_page, PAGE_SIZE);
    return ret;
}

/* ------------------------------------------------------------------ */
/* vmcall 19 proxy: map elem get/set — copy attr struct from L2 GPA   */
/* ------------------------------------------------------------------ */

static long proxy_map_elem_to_l0(CPUState *cpu,
                                  unsigned long l0_slot,
                                  unsigned long attr_gpa)
{
    char *attr_page;
    uintptr_t attr_phys;
    long ret;
    MemTxResult mtr;

    attr_page = hyperupcall_proxy_alloc_pinned(PAGE_SIZE);
    if (attr_page == MAP_FAILED) {
        perror("proxy_map_elem: mmap attr_page");
        return -1;
    }

    mtr = address_space_read(cpu->as, attr_gpa,
                             MEMTXATTRS_UNSPECIFIED,
                             attr_page, PAGE_SIZE);
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "proxy_map_elem: read attr failed %d\n", mtr);
        munmap(attr_page, PAGE_SIZE);
        return -1;
    }

    attr_phys = hyperupcall_proxy_get_l1_phys(attr_page);
    if (attr_phys == 0) {
        fprintf(stderr, "proxy_map_elem: get_l1_phys failed\n");
        munmap(attr_page, PAGE_SIZE);
        return -1;
    }

    ret = proxy_vmcall2(19, l0_slot, attr_phys);
    munmap(attr_page, PAGE_SIZE);
    return ret;
}

/* ------------------------------------------------------------------ */
/* L2 teardown: unload all eBPF objects this L2 VM loaded at L0       */
/* ------------------------------------------------------------------ */

void hyperupcall_l2_teardown(void)
{
    pthread_mutex_lock(&l2_hyperupcalls_lock);
    for (int i = 0; i < MAX_L2_HYPERUPCALL_OBJS; i++) {
        if (l2_slot_used[i]) {
            long l0_slot = l2_slot_to_l0_slot[i];
            fprintf(stderr,
                    "hyperupcall_l2_teardown: unloading L2 slot %d "
                    "→ L0 slot %ld\n", i, l0_slot);
            proxy_vmcall1(14, (unsigned long)l0_slot);
            l2_free_slot(i);
        }
    }
    pthread_mutex_unlock(&l2_hyperupcalls_lock);
}

/* ------------------------------------------------------------------ */
/* Main L2 proxy dispatcher — called from handle_hypercall()           */
/* ------------------------------------------------------------------ */

static long handle_l2_hypercall(CPUState *cpu, MemTxAttrs attrs,
                                 unsigned long nr,
                                 unsigned long a0, unsigned long a1,
                                 unsigned long a2, unsigned long a3)
{
    long ret = -1;

    /* Lazily initialize L2 state */
    if (!l2_hyperupcalls_initialized) {
        memset(l2_slot_to_l0_slot, -1, sizeof(l2_slot_to_l0_slot));
        memset(l2_slot_used, 0, sizeof(l2_slot_used));
        pthread_mutex_init(&l2_hyperupcalls_lock, NULL);
        l2_hyperupcalls_initialized = 1;
    }

    fprintf(stderr,
            "handle_l2_hypercall: nr=%lu a0=%lu a1=%lu a2=%lu a3=%lu\n",
            nr, a0, a1, a2, a3);

    switch (nr) {
    case 13: { /* load: a0=l2_ptr_array_gpa, a1=program_len */
        long l0_slot;
        int l2_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        l2_slot = l2_alloc_slot();
        if (l2_slot < 0) {
            fprintf(stderr, "handle_l2_hypercall: no free L2 slots\n");
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }

        l0_slot = proxy_load_hyperupcall_to_l0(cpu, attrs, a0, a1);
        if (l0_slot < 0) {
            l2_free_slot(l2_slot);
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }

        l2_slot_to_l0_slot[l2_slot] = l0_slot;
        pthread_mutex_unlock(&l2_hyperupcalls_lock);
        /* Return L2-local slot to the guest; L2 uses this for link/unload */
        ret = l2_slot;
        break;
    }

    case 14: { /* unload: a0=l2_slot */
        int l2_slot = (int)a0;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            fprintf(stderr, "handle_l2_hypercall: invalid L2 slot %d\n",
                    l2_slot);
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        ret = proxy_vmcall1(14, (unsigned long)l2_slot_to_l0_slot[l2_slot]);
        l2_free_slot(l2_slot);
        pthread_mutex_unlock(&l2_hyperupcalls_lock);
        break;
    }

    case 15: { /* link: a0=l2_slot, a1=prog_name_gpa, a2=major, a3=minor */
        int l2_slot = (int)a0;
        long l0_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            fprintf(stderr, "handle_l2_hypercall: invalid L2 slot %d\n",
                    l2_slot);
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        l0_slot = l2_slot_to_l0_slot[l2_slot];
        pthread_mutex_unlock(&l2_hyperupcalls_lock);

        ret = proxy_link_hyperupcall_to_l0(cpu, l0_slot, a1, a2, a3);
        break;
    }

    case 16: { /* unlink: a0=l2_slot, a1=program_slot */
        int l2_slot = (int)a0;
        long l0_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        l0_slot = l2_slot_to_l0_slot[l2_slot];
        pthread_mutex_unlock(&l2_hyperupcalls_lock);

        ret = proxy_vmcall2(16, (unsigned long)l0_slot, a1);
        break;
    }

    case 17: { /* map BPF map: a0=l2_slot, a1=map_name_gpa */
        int l2_slot = (int)a0;
        long l0_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        l0_slot = l2_slot_to_l0_slot[l2_slot];
        pthread_mutex_unlock(&l2_hyperupcalls_lock);

        ret = proxy_map_hyperupcall_map_to_l0(cpu, l0_slot, a1);
        break;
    }

    case 18: { /* unmap BPF map: a0=l2_slot, a1=map_slot (direct forward) */
        int l2_slot = (int)a0;
        long l0_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        l0_slot = l2_slot_to_l0_slot[l2_slot];
        pthread_mutex_unlock(&l2_hyperupcalls_lock);

        ret = proxy_vmcall2(18, (unsigned long)l0_slot, a1);
        break;
    }

    case 19: { /* map elem get/set: a0=l2_slot, a1=attr_gpa */
        int l2_slot = (int)a0;
        long l0_slot;

        pthread_mutex_lock(&l2_hyperupcalls_lock);
        if (l2_slot < 0 || l2_slot >= MAX_L2_HYPERUPCALL_OBJS
                || !l2_slot_used[l2_slot]) {
            pthread_mutex_unlock(&l2_hyperupcalls_lock);
            return -1;
        }
        l0_slot = l2_slot_to_l0_slot[l2_slot];
        pthread_mutex_unlock(&l2_hyperupcalls_lock);

        ret = proxy_map_elem_to_l0(cpu, l0_slot, a1);
        break;
    }

    default:
        fprintf(stderr, "handle_l2_hypercall: unhandled nr=%lu\n", nr);
        ret = -1;
    }

    return ret;
}


static inline void kvm_resample_fd_remove(int gsi)
{
    KVMResampleFd *rfd;

    QLIST_FOREACH(rfd, &kvm_resample_fd_list, node) {
        if (rfd->gsi == gsi) {
            QLIST_REMOVE(rfd, node);
            g_free(rfd);
            break;
        }
    }
}

static inline void kvm_resample_fd_insert(int gsi, EventNotifier *event)
{
    KVMResampleFd *rfd = g_new0(KVMResampleFd, 1);

    rfd->gsi = gsi;
    rfd->resample_event = event;

    QLIST_INSERT_HEAD(&kvm_resample_fd_list, rfd, node);
}

void kvm_resample_fd_notify(int gsi)
{
    KVMResampleFd *rfd;

    QLIST_FOREACH(rfd, &kvm_resample_fd_list, node) {
        if (rfd->gsi == gsi) {
            event_notifier_set(rfd->resample_event);
            trace_kvm_resample_fd_notify(gsi);
            return;
        }
    }
}

int kvm_get_max_memslots(void)
{
    KVMState *s = KVM_STATE(current_accel());

    return s->nr_slots;
}

/* Called with KVMMemoryListener.slots_lock held */
static KVMSlot *kvm_get_free_slot(KVMMemoryListener *kml)
{
    KVMState *s = kvm_state;
    int i;

    for (i = 0; i < s->nr_slots; i++) {
        if (kml->slots[i].memory_size == 0) {
            return &kml->slots[i];
        }
    }

    return NULL;
}

bool kvm_has_free_slot(MachineState *ms)
{
    KVMState *s = KVM_STATE(ms->accelerator);
    bool result;
    KVMMemoryListener *kml = &s->memory_listener;

    kvm_slots_lock();
    result = !!kvm_get_free_slot(kml);
    kvm_slots_unlock();

    return result;
}

/* Called with KVMMemoryListener.slots_lock held */
static KVMSlot *kvm_alloc_slot(KVMMemoryListener *kml)
{
    KVMSlot *slot = kvm_get_free_slot(kml);

    if (slot) {
        return slot;
    }

    fprintf(stderr, "%s: no free slot available\n", __func__);
    abort();
}

static KVMSlot *kvm_lookup_matching_slot(KVMMemoryListener *kml,
                                         hwaddr start_addr,
                                         hwaddr size)
{
    KVMState *s = kvm_state;
    int i;

    for (i = 0; i < s->nr_slots; i++) {
        KVMSlot *mem = &kml->slots[i];

        if (start_addr == mem->start_addr && size == mem->memory_size) {
            return mem;
        }
    }

    return NULL;
}

/*
 * Calculate and align the start address and the size of the section.
 * Return the size. If the size is 0, the aligned section is empty.
 */
static hwaddr kvm_align_section(MemoryRegionSection *section,
                                hwaddr *start)
{
    hwaddr size = int128_get64(section->size);
    hwaddr delta, aligned;

    /* kvm works in page size chunks, but the function may be called
       with sub-page size and unaligned start address. Pad the start
       address to next and truncate size to previous page boundary. */
    aligned = ROUND_UP(section->offset_within_address_space,
                       qemu_real_host_page_size());
    delta = aligned - section->offset_within_address_space;
    *start = aligned;
    if (delta > size) {
        return 0;
    }

    return (size - delta) & qemu_real_host_page_mask();
}

int kvm_physical_memory_addr_from_host(KVMState *s, void *ram,
                                       hwaddr *phys_addr)
{
    KVMMemoryListener *kml = &s->memory_listener;
    int i, ret = 0;

    kvm_slots_lock();
    for (i = 0; i < s->nr_slots; i++) {
        KVMSlot *mem = &kml->slots[i];

        if (ram >= mem->ram && ram < mem->ram + mem->memory_size) {
            *phys_addr = mem->start_addr + (ram - mem->ram);
            ret = 1;
            break;
        }
    }
    kvm_slots_unlock();

    return ret;
}

static int kvm_set_user_memory_region(KVMMemoryListener *kml, KVMSlot *slot, bool new)
{
    KVMState *s = kvm_state;
    struct kvm_userspace_memory_region mem;
    int ret;

    mem.slot = slot->slot | (kml->as_id << 16);
    mem.guest_phys_addr = slot->start_addr;
    mem.userspace_addr = (unsigned long)slot->ram;
    mem.flags = slot->flags;

    if (slot->memory_size && !new && (mem.flags ^ slot->old_flags) & KVM_MEM_READONLY) {
        /* Set the slot size to 0 before setting the slot to the desired
         * value. This is needed based on KVM commit 75d61fbc. */
        mem.memory_size = 0;
        ret = kvm_vm_ioctl(s, KVM_SET_USER_MEMORY_REGION, &mem);
        if (ret < 0) {
            goto err;
        }
    }
    mem.memory_size = slot->memory_size;
    ret = kvm_vm_ioctl(s, KVM_SET_USER_MEMORY_REGION, &mem);
    slot->old_flags = mem.flags;
err:
    trace_kvm_set_user_memory(mem.slot, mem.flags, mem.guest_phys_addr,
                              mem.memory_size, mem.userspace_addr, ret);
    if (ret < 0) {
        error_report("%s: KVM_SET_USER_MEMORY_REGION failed, slot=%d,"
                     " start=0x%" PRIx64 ", size=0x%" PRIx64 ": %s",
                     __func__, mem.slot, slot->start_addr,
                     (uint64_t)mem.memory_size, strerror(errno));
        return ret;
    }


    if (slot->slot >= HYPERUPCALL_MAX_N_MEMSLOTS) {
        fprintf(stderr, "No more memslots available. Need %d memslots\n", slot->slot);
        return ret;
    }

    used_memslots = used_memslots < slot->slot ? slot->slot : used_memslots;
    // if (slot->memory_size == 0) { // remove slot
    //     memslot_base_gfns_local[slot->slot] = 0;
    //     memslot_npages_local[slot->slot] = 0;
    //     memslot_userptrs_local[slot->slot] = 0;
    //     memslot_as_id[slot->slot] = 0;
    // }
    // else if (memslot_npages_local[slot->slot] != 0) { // extend slot
    //     memslot_npages_local[slot->slot] += (unsigned long long)mem.memory_size >> 12;
    // }
    // else { // new slot
    //     if (memslot_as_id[slot->slot] != kml->as_id && memslot_userptrs_local[slot->slot] != 0 && mem.memory_size != 0) {
    //         fprintf(stderr, "Slot %d already in use by as_id %d\n", slot->slot, memslot_as_id[slot->slot]);
    //     }
    //     memslot_as_id[slot->slot] = kml->as_id;
    //     memslot_npages_local[slot->slot] = (unsigned long long)mem.memory_size >> 12;
    //     memslot_base_gfns_local[slot->slot] = (unsigned long long)mem.guest_phys_addr >> 12;
    //     memslot_userptrs_local[slot->slot] = (unsigned long long)mem.userspace_addr;
    // }
    return ret;
}

static int do_kvm_destroy_vcpu(CPUState *cpu)
{
    KVMState *s = kvm_state;
    long mmap_size;
    struct KVMParkedVcpu *vcpu = NULL;
    int ret = 0;

    DPRINTF("kvm_destroy_vcpu\n");

    ret = kvm_arch_destroy_vcpu(cpu);
    if (ret < 0) {
        goto err;
    }

    mmap_size = kvm_ioctl(s, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        ret = mmap_size;
        DPRINTF("KVM_GET_VCPU_MMAP_SIZE failed\n");
        goto err;
    }

    ret = munmap(cpu->kvm_run, mmap_size);
    if (ret < 0) {
        goto err;
    }

    if (cpu->kvm_dirty_gfns) {
        ret = munmap(cpu->kvm_dirty_gfns, s->kvm_dirty_ring_bytes);
        if (ret < 0) {
            goto err;
        }
    }

    vcpu = g_malloc0(sizeof(*vcpu));
    vcpu->vcpu_id = kvm_arch_vcpu_id(cpu);
    vcpu->kvm_fd = cpu->kvm_fd;
    QLIST_INSERT_HEAD(&kvm_state->kvm_parked_vcpus, vcpu, node);
err:
    return ret;
}

void kvm_destroy_vcpu(CPUState *cpu)
{
    /*
     * On CPU 0 teardown, unload any eBPF objects that were proxied to L0
     * on behalf of L2 nested guests.  This ensures L0 cleans up BPF
     * programs/links even if the L2 guest exits without calling unload().
     */
    if (cpu->cpu_index == 0 && l2_hyperupcalls_initialized)
        hyperupcall_l2_teardown();

    if (do_kvm_destroy_vcpu(cpu) < 0) {
        error_report("kvm_destroy_vcpu failed");
        exit(EXIT_FAILURE);
    }
}

static int kvm_get_vcpu(KVMState *s, unsigned long vcpu_id)
{
    struct KVMParkedVcpu *cpu;

    QLIST_FOREACH(cpu, &s->kvm_parked_vcpus, node) {
        if (cpu->vcpu_id == vcpu_id) {
            int kvm_fd;

            QLIST_REMOVE(cpu, node);
            kvm_fd = cpu->kvm_fd;
            g_free(cpu);
            return kvm_fd;
        }
    }

    return kvm_vm_ioctl(s, KVM_CREATE_VCPU, (void *)vcpu_id);
}

int kvm_init_vcpu(CPUState *cpu, Error **errp)
{
    KVMState *s = kvm_state;
    long mmap_size;
    int ret;

    trace_kvm_init_vcpu(cpu->cpu_index, kvm_arch_vcpu_id(cpu));

    ret = kvm_get_vcpu(s, kvm_arch_vcpu_id(cpu));
    if (ret < 0) {
        error_setg_errno(errp, -ret, "kvm_init_vcpu: kvm_get_vcpu failed (%lu)",
                         kvm_arch_vcpu_id(cpu));
        goto err;
    }

    cpu->kvm_fd = ret;
    cpu->kvm_state = s;
    cpu->vcpu_dirty = true;
    cpu->dirty_pages = 0;
    cpu->throttle_us_per_full = 0;

    mmap_size = kvm_ioctl(s, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        ret = mmap_size;
        error_setg_errno(errp, -mmap_size,
                         "kvm_init_vcpu: KVM_GET_VCPU_MMAP_SIZE failed");
        goto err;
    }

    cpu->kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        cpu->kvm_fd, 0);
    if (cpu->kvm_run == MAP_FAILED) {
        ret = -errno;
        error_setg_errno(errp, ret,
                         "kvm_init_vcpu: mmap'ing vcpu state failed (%lu)",
                         kvm_arch_vcpu_id(cpu));
        goto err;
    }

    if (s->coalesced_mmio && !s->coalesced_mmio_ring) {
        s->coalesced_mmio_ring =
            (void *)cpu->kvm_run + s->coalesced_mmio * PAGE_SIZE;
    }

    if (s->kvm_dirty_ring_size) {
        /* Use MAP_SHARED to share pages with the kernel */
        cpu->kvm_dirty_gfns = mmap(NULL, s->kvm_dirty_ring_bytes,
                                   PROT_READ | PROT_WRITE, MAP_SHARED,
                                   cpu->kvm_fd,
                                   PAGE_SIZE * KVM_DIRTY_LOG_PAGE_OFFSET);
        if (cpu->kvm_dirty_gfns == MAP_FAILED) {
            ret = -errno;
            DPRINTF("mmap'ing vcpu dirty gfns failed: %d\n", ret);
            goto err;
        }
    }

    ret = kvm_arch_init_vcpu(cpu);
    if (ret < 0) {
        error_setg_errno(errp, -ret,
                         "kvm_init_vcpu: kvm_arch_init_vcpu failed (%lu)",
                         kvm_arch_vcpu_id(cpu));
    }
err:
    return ret;
}

/*
 * dirty pages logging control
 */

static int kvm_mem_flags(MemoryRegion *mr)
{
    bool readonly = mr->readonly || memory_region_is_romd(mr);
    int flags = 0;

    if (memory_region_get_dirty_log_mask(mr) != 0) {
        flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }
    if (readonly && kvm_readonly_mem_allowed) {
        flags |= KVM_MEM_READONLY;
    }
    return flags;
}

/* Called with KVMMemoryListener.slots_lock held */
static int kvm_slot_update_flags(KVMMemoryListener *kml, KVMSlot *mem,
                                 MemoryRegion *mr)
{
    mem->flags = kvm_mem_flags(mr);

    /* If nothing changed effectively, no need to issue ioctl */
    if (mem->flags == mem->old_flags) {
        return 0;
    }

    kvm_slot_init_dirty_bitmap(mem);
    return kvm_set_user_memory_region(kml, mem, false);
}

static int kvm_section_update_flags(KVMMemoryListener *kml,
                                    MemoryRegionSection *section)
{
    hwaddr start_addr, size, slot_size;
    KVMSlot *mem;
    int ret = 0;

    size = kvm_align_section(section, &start_addr);
    if (!size) {
        return 0;
    }

    kvm_slots_lock();

    while (size && !ret) {
        slot_size = MIN(kvm_max_slot_size, size);
        mem = kvm_lookup_matching_slot(kml, start_addr, slot_size);
        if (!mem) {
            /* We don't have a slot if we want to trap every access. */
            goto out;
        }

        ret = kvm_slot_update_flags(kml, mem, section->mr);
        start_addr += slot_size;
        size -= slot_size;
    }

out:
    kvm_slots_unlock();
    return ret;
}

static void kvm_log_start(MemoryListener *listener,
                          MemoryRegionSection *section,
                          int old, int new)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);
    int r;

    if (old != 0) {
        return;
    }

    r = kvm_section_update_flags(kml, section);
    if (r < 0) {
        abort();
    }
}

static void kvm_log_stop(MemoryListener *listener,
                          MemoryRegionSection *section,
                          int old, int new)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);
    int r;

    if (new != 0) {
        return;
    }

    r = kvm_section_update_flags(kml, section);
    if (r < 0) {
        abort();
    }
}

/* get kvm's dirty pages bitmap and update qemu's */
static void kvm_slot_sync_dirty_pages(KVMSlot *slot)
{
    ram_addr_t start = slot->ram_start_offset;
    ram_addr_t pages = slot->memory_size / qemu_real_host_page_size();

    cpu_physical_memory_set_dirty_lebitmap(slot->dirty_bmap, start, pages);
}

static void kvm_slot_reset_dirty_pages(KVMSlot *slot)
{
    memset(slot->dirty_bmap, 0, slot->dirty_bmap_size);
}

#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))

/* Allocate the dirty bitmap for a slot  */
static void kvm_slot_init_dirty_bitmap(KVMSlot *mem)
{
    if (!(mem->flags & KVM_MEM_LOG_DIRTY_PAGES) || mem->dirty_bmap) {
        return;
    }

    /*
     * XXX bad kernel interface alert
     * For dirty bitmap, kernel allocates array of size aligned to
     * bits-per-long.  But for case when the kernel is 64bits and
     * the userspace is 32bits, userspace can't align to the same
     * bits-per-long, since sizeof(long) is different between kernel
     * and user space.  This way, userspace will provide buffer which
     * may be 4 bytes less than the kernel will use, resulting in
     * userspace memory corruption (which is not detectable by valgrind
     * too, in most cases).
     * So for now, let's align to 64 instead of HOST_LONG_BITS here, in
     * a hope that sizeof(long) won't become >8 any time soon.
     *
     * Note: the granule of kvm dirty log is qemu_real_host_page_size.
     * And mem->memory_size is aligned to it (otherwise this mem can't
     * be registered to KVM).
     */
    hwaddr bitmap_size = ALIGN(mem->memory_size / qemu_real_host_page_size(),
                                        /*HOST_LONG_BITS*/ 64) / 8;
    mem->dirty_bmap = g_malloc0(bitmap_size);
    mem->dirty_bmap_size = bitmap_size;
}

/*
 * Sync dirty bitmap from kernel to KVMSlot.dirty_bmap, return true if
 * succeeded, false otherwise
 */
static bool kvm_slot_get_dirty_log(KVMState *s, KVMSlot *slot)
{
    struct kvm_dirty_log d = {};
    int ret;

    d.dirty_bitmap = slot->dirty_bmap;
    d.slot = slot->slot | (slot->as_id << 16);
    ret = kvm_vm_ioctl(s, KVM_GET_DIRTY_LOG, &d);

    if (ret == -ENOENT) {
        /* kernel does not have dirty bitmap in this slot */
        ret = 0;
    }
    if (ret) {
        error_report_once("%s: KVM_GET_DIRTY_LOG failed with %d",
                          __func__, ret);
    }
    return ret == 0;
}

/* Should be with all slots_lock held for the address spaces. */
static void kvm_dirty_ring_mark_page(KVMState *s, uint32_t as_id,
                                     uint32_t slot_id, uint64_t offset)
{
    KVMMemoryListener *kml;
    KVMSlot *mem;

    if (as_id >= s->nr_as) {
        return;
    }

    kml = s->as[as_id].ml;
    mem = &kml->slots[slot_id];

    if (!mem->memory_size || offset >=
        (mem->memory_size / qemu_real_host_page_size())) {
        return;
    }

    set_bit(offset, mem->dirty_bmap);
}

static bool dirty_gfn_is_dirtied(struct kvm_dirty_gfn *gfn)
{
    /*
     * Read the flags before the value.  Pairs with barrier in
     * KVM's kvm_dirty_ring_push() function.
     */
    return qatomic_load_acquire(&gfn->flags) == KVM_DIRTY_GFN_F_DIRTY;
}

static void dirty_gfn_set_collected(struct kvm_dirty_gfn *gfn)
{
    /*
     * Use a store-release so that the CPU that executes KVM_RESET_DIRTY_RINGS
     * sees the full content of the ring:
     *
     * CPU0                     CPU1                         CPU2
     * ------------------------------------------------------------------------------
     *                                                       fill gfn0
     *                                                       store-rel flags for gfn0
     * load-acq flags for gfn0
     * store-rel RESET for gfn0
     *                          ioctl(RESET_RINGS)
     *                            load-acq flags for gfn0
     *                            check if flags have RESET
     *
     * The synchronization goes from CPU2 to CPU0 to CPU1.
     */
    qatomic_store_release(&gfn->flags, KVM_DIRTY_GFN_F_RESET);
}

/*
 * Should be with all slots_lock held for the address spaces.  It returns the
 * dirty page we've collected on this dirty ring.
 */
static uint32_t kvm_dirty_ring_reap_one(KVMState *s, CPUState *cpu)
{
    struct kvm_dirty_gfn *dirty_gfns = cpu->kvm_dirty_gfns, *cur;
    uint32_t ring_size = s->kvm_dirty_ring_size;
    uint32_t count = 0, fetch = cpu->kvm_fetch_index;

    assert(dirty_gfns && ring_size);
    trace_kvm_dirty_ring_reap_vcpu(cpu->cpu_index);

    while (true) {
        cur = &dirty_gfns[fetch % ring_size];
        if (!dirty_gfn_is_dirtied(cur)) {
            break;
        }
        kvm_dirty_ring_mark_page(s, cur->slot >> 16, cur->slot & 0xffff,
                                 cur->offset);
        dirty_gfn_set_collected(cur);
        trace_kvm_dirty_ring_page(cpu->cpu_index, fetch, cur->offset);
        fetch++;
        count++;
    }
    cpu->kvm_fetch_index = fetch;
    cpu->dirty_pages += count;

    return count;
}

/* Must be with slots_lock held */
static uint64_t kvm_dirty_ring_reap_locked(KVMState *s, CPUState* cpu)
{
    int ret;
    uint64_t total = 0;
    int64_t stamp;

    stamp = get_clock();

    if (cpu) {
        total = kvm_dirty_ring_reap_one(s, cpu);
    } else {
        CPU_FOREACH(cpu) {
            total += kvm_dirty_ring_reap_one(s, cpu);
        }
    }

    if (total) {
        ret = kvm_vm_ioctl(s, KVM_RESET_DIRTY_RINGS);
        assert(ret == total);
    }

    stamp = get_clock() - stamp;

    if (total) {
        trace_kvm_dirty_ring_reap(total, stamp / 1000);
    }

    return total;
}

/*
 * Currently for simplicity, we must hold BQL before calling this.  We can
 * consider to drop the BQL if we're clear with all the race conditions.
 */
static uint64_t kvm_dirty_ring_reap(KVMState *s, CPUState *cpu)
{
    uint64_t total;

    /*
     * We need to lock all kvm slots for all address spaces here,
     * because:
     *
     * (1) We need to mark dirty for dirty bitmaps in multiple slots
     *     and for tons of pages, so it's better to take the lock here
     *     once rather than once per page.  And more importantly,
     *
     * (2) We must _NOT_ publish dirty bits to the other threads
     *     (e.g., the migration thread) via the kvm memory slot dirty
     *     bitmaps before correctly re-protect those dirtied pages.
     *     Otherwise we can have potential risk of data corruption if
     *     the page data is read in the other thread before we do
     *     reset below.
     */
    kvm_slots_lock();
    total = kvm_dirty_ring_reap_locked(s, cpu);
    kvm_slots_unlock();

    return total;
}

static void do_kvm_cpu_synchronize_kick(CPUState *cpu, run_on_cpu_data arg)
{
    /* No need to do anything */
}

/*
 * Kick all vcpus out in a synchronized way.  When returned, we
 * guarantee that every vcpu has been kicked and at least returned to
 * userspace once.
 */
static void kvm_cpu_synchronize_kick_all(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        run_on_cpu(cpu, do_kvm_cpu_synchronize_kick, RUN_ON_CPU_NULL);
    }
}

/*
 * Flush all the existing dirty pages to the KVM slot buffers.  When
 * this call returns, we guarantee that all the touched dirty pages
 * before calling this function have been put into the per-kvmslot
 * dirty bitmap.
 *
 * This function must be called with BQL held.
 */
static void kvm_dirty_ring_flush(void)
{
    trace_kvm_dirty_ring_flush(0);
    /*
     * The function needs to be serialized.  Since this function
     * should always be with BQL held, serialization is guaranteed.
     * However, let's be sure of it.
     */
    assert(qemu_mutex_iothread_locked());
    /*
     * First make sure to flush the hardware buffers by kicking all
     * vcpus out in a synchronous way.
     */
    kvm_cpu_synchronize_kick_all();
    kvm_dirty_ring_reap(kvm_state, NULL);
    trace_kvm_dirty_ring_flush(1);
}

/**
 * kvm_physical_sync_dirty_bitmap - Sync dirty bitmap from kernel space
 *
 * This function will first try to fetch dirty bitmap from the kernel,
 * and then updates qemu's dirty bitmap.
 *
 * NOTE: caller must be with kml->slots_lock held.
 *
 * @kml: the KVM memory listener object
 * @section: the memory section to sync the dirty bitmap with
 */
static void kvm_physical_sync_dirty_bitmap(KVMMemoryListener *kml,
                                           MemoryRegionSection *section)
{
    KVMState *s = kvm_state;
    KVMSlot *mem;
    hwaddr start_addr, size;
    hwaddr slot_size;

    size = kvm_align_section(section, &start_addr);
    while (size) {
        slot_size = MIN(kvm_max_slot_size, size);
        mem = kvm_lookup_matching_slot(kml, start_addr, slot_size);
        if (!mem) {
            /* We don't have a slot if we want to trap every access. */
            return;
        }
        if (kvm_slot_get_dirty_log(s, mem)) {
            kvm_slot_sync_dirty_pages(mem);
        }
        start_addr += slot_size;
        size -= slot_size;
    }
}

/* Alignment requirement for KVM_CLEAR_DIRTY_LOG - 64 pages */
#define KVM_CLEAR_LOG_SHIFT  6
#define KVM_CLEAR_LOG_ALIGN  (qemu_real_host_page_size() << KVM_CLEAR_LOG_SHIFT)
#define KVM_CLEAR_LOG_MASK   (-KVM_CLEAR_LOG_ALIGN)

static int kvm_log_clear_one_slot(KVMSlot *mem, int as_id, uint64_t start,
                                  uint64_t size)
{
    KVMState *s = kvm_state;
    uint64_t end, bmap_start, start_delta, bmap_npages;
    struct kvm_clear_dirty_log d;
    unsigned long *bmap_clear = NULL, psize = qemu_real_host_page_size();
    int ret;

    /*
     * We need to extend either the start or the size or both to
     * satisfy the KVM interface requirement.  Firstly, do the start
     * page alignment on 64 host pages
     */
    bmap_start = start & KVM_CLEAR_LOG_MASK;
    start_delta = start - bmap_start;
    bmap_start /= psize;

    /*
     * The kernel interface has restriction on the size too, that either:
     *
     * (1) the size is 64 host pages aligned (just like the start), or
     * (2) the size fills up until the end of the KVM memslot.
     */
    bmap_npages = DIV_ROUND_UP(size + start_delta, KVM_CLEAR_LOG_ALIGN)
        << KVM_CLEAR_LOG_SHIFT;
    end = mem->memory_size / psize;
    if (bmap_npages > end - bmap_start) {
        bmap_npages = end - bmap_start;
    }
    start_delta /= psize;

    /*
     * Prepare the bitmap to clear dirty bits.  Here we must guarantee
     * that we won't clear any unknown dirty bits otherwise we might
     * accidentally clear some set bits which are not yet synced from
     * the kernel into QEMU's bitmap, then we'll lose track of the
     * guest modifications upon those pages (which can directly lead
     * to guest data loss or panic after migration).
     *
     * Layout of the KVMSlot.dirty_bmap:
     *
     *                   |<-------- bmap_npages -----------..>|
     *                                                     [1]
     *                     start_delta         size
     *  |----------------|-------------|------------------|------------|
     *  ^                ^             ^                               ^
     *  |                |             |                               |
     * start          bmap_start     (start)                         end
     * of memslot                                             of memslot
     *
     * [1] bmap_npages can be aligned to either 64 pages or the end of slot
     */

    assert(bmap_start % BITS_PER_LONG == 0);
    /* We should never do log_clear before log_sync */
    assert(mem->dirty_bmap);
    if (start_delta || bmap_npages - size / psize) {
        /* Slow path - we need to manipulate a temp bitmap */
        bmap_clear = bitmap_new(bmap_npages);
        bitmap_copy_with_src_offset(bmap_clear, mem->dirty_bmap,
                                    bmap_start, start_delta + size / psize);
        /*
         * We need to fill the holes at start because that was not
         * specified by the caller and we extended the bitmap only for
         * 64 pages alignment
         */
        bitmap_clear(bmap_clear, 0, start_delta);
        d.dirty_bitmap = bmap_clear;
    } else {
        /*
         * Fast path - both start and size align well with BITS_PER_LONG
         * (or the end of memory slot)
         */
        d.dirty_bitmap = mem->dirty_bmap + BIT_WORD(bmap_start);
    }

    d.first_page = bmap_start;
    /* It should never overflow.  If it happens, say something */
    assert(bmap_npages <= UINT32_MAX);
    d.num_pages = bmap_npages;
    d.slot = mem->slot | (as_id << 16);

    ret = kvm_vm_ioctl(s, KVM_CLEAR_DIRTY_LOG, &d);
    if (ret < 0 && ret != -ENOENT) {
        error_report("%s: KVM_CLEAR_DIRTY_LOG failed, slot=%d, "
                     "start=0x%"PRIx64", size=0x%"PRIx32", errno=%d",
                     __func__, d.slot, (uint64_t)d.first_page,
                     (uint32_t)d.num_pages, ret);
    } else {
        ret = 0;
        trace_kvm_clear_dirty_log(d.slot, d.first_page, d.num_pages);
    }

    /*
     * After we have updated the remote dirty bitmap, we update the
     * cached bitmap as well for the memslot, then if another user
     * clears the same region we know we shouldn't clear it again on
     * the remote otherwise it's data loss as well.
     */
    bitmap_clear(mem->dirty_bmap, bmap_start + start_delta,
                 size / psize);
    /* This handles the NULL case well */
    g_free(bmap_clear);
    return ret;
}


/**
 * kvm_physical_log_clear - Clear the kernel's dirty bitmap for range
 *
 * NOTE: this will be a no-op if we haven't enabled manual dirty log
 * protection in the host kernel because in that case this operation
 * will be done within log_sync().
 *
 * @kml:     the kvm memory listener
 * @section: the memory range to clear dirty bitmap
 */
static int kvm_physical_log_clear(KVMMemoryListener *kml,
                                  MemoryRegionSection *section)
{
    KVMState *s = kvm_state;
    uint64_t start, size, offset, count;
    KVMSlot *mem;
    int ret = 0, i;

    if (!s->manual_dirty_log_protect) {
        /* No need to do explicit clear */
        return ret;
    }

    start = section->offset_within_address_space;
    size = int128_get64(section->size);

    if (!size) {
        /* Nothing more we can do... */
        return ret;
    }

    kvm_slots_lock();

    for (i = 0; i < s->nr_slots; i++) {
        mem = &kml->slots[i];
        /* Discard slots that are empty or do not overlap the section */
        if (!mem->memory_size ||
            mem->start_addr > start + size - 1 ||
            start > mem->start_addr + mem->memory_size - 1) {
            continue;
        }

        if (start >= mem->start_addr) {
            /* The slot starts before section or is aligned to it.  */
            offset = start - mem->start_addr;
            count = MIN(mem->memory_size - offset, size);
        } else {
            /* The slot starts after section.  */
            offset = 0;
            count = MIN(mem->memory_size, size - (mem->start_addr - start));
        }
        ret = kvm_log_clear_one_slot(mem, kml->as_id, offset, count);
        if (ret < 0) {
            break;
        }
    }

    kvm_slots_unlock();

    return ret;
}

static void kvm_coalesce_mmio_region(MemoryListener *listener,
                                     MemoryRegionSection *secion,
                                     hwaddr start, hwaddr size)
{
    KVMState *s = kvm_state;

    if (s->coalesced_mmio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;
        zone.pad = 0;

        (void)kvm_vm_ioctl(s, KVM_REGISTER_COALESCED_MMIO, &zone);
    }
}

static void kvm_uncoalesce_mmio_region(MemoryListener *listener,
                                       MemoryRegionSection *secion,
                                       hwaddr start, hwaddr size)
{
    KVMState *s = kvm_state;

    if (s->coalesced_mmio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;
        zone.pad = 0;

        (void)kvm_vm_ioctl(s, KVM_UNREGISTER_COALESCED_MMIO, &zone);
    }
}

static void kvm_coalesce_pio_add(MemoryListener *listener,
                                MemoryRegionSection *section,
                                hwaddr start, hwaddr size)
{
    KVMState *s = kvm_state;

    if (s->coalesced_pio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;
        zone.pio = 1;

        (void)kvm_vm_ioctl(s, KVM_REGISTER_COALESCED_MMIO, &zone);
    }
}

static void kvm_coalesce_pio_del(MemoryListener *listener,
                                MemoryRegionSection *section,
                                hwaddr start, hwaddr size)
{
    KVMState *s = kvm_state;

    if (s->coalesced_pio) {
        struct kvm_coalesced_mmio_zone zone;

        zone.addr = start;
        zone.size = size;
        zone.pio = 1;

        (void)kvm_vm_ioctl(s, KVM_UNREGISTER_COALESCED_MMIO, &zone);
     }
}

static MemoryListener kvm_coalesced_pio_listener = {
    .name = "kvm-coalesced-pio",
    .coalesced_io_add = kvm_coalesce_pio_add,
    .coalesced_io_del = kvm_coalesce_pio_del,
};

int kvm_check_extension(KVMState *s, unsigned int extension)
{
    int ret;

    ret = kvm_ioctl(s, KVM_CHECK_EXTENSION, extension);
    if (ret < 0) {
        ret = 0;
    }

    return ret;
}

int kvm_vm_check_extension(KVMState *s, unsigned int extension)
{
    int ret;

    ret = kvm_vm_ioctl(s, KVM_CHECK_EXTENSION, extension);
    if (ret < 0) {
        /* VM wide version not implemented, use global one instead */
        ret = kvm_check_extension(s, extension);
    }

    return ret;
}

typedef struct HWPoisonPage {
    ram_addr_t ram_addr;
    QLIST_ENTRY(HWPoisonPage) list;
} HWPoisonPage;

static QLIST_HEAD(, HWPoisonPage) hwpoison_page_list =
    QLIST_HEAD_INITIALIZER(hwpoison_page_list);

static void kvm_unpoison_all(void *param)
{
    HWPoisonPage *page, *next_page;

    QLIST_FOREACH_SAFE(page, &hwpoison_page_list, list, next_page) {
        QLIST_REMOVE(page, list);
        qemu_ram_remap(page->ram_addr, TARGET_PAGE_SIZE);
        g_free(page);
    }
}

void kvm_hwpoison_page_add(ram_addr_t ram_addr)
{
    HWPoisonPage *page;

    QLIST_FOREACH(page, &hwpoison_page_list, list) {
        if (page->ram_addr == ram_addr) {
            return;
        }
    }
    page = g_new(HWPoisonPage, 1);
    page->ram_addr = ram_addr;
    QLIST_INSERT_HEAD(&hwpoison_page_list, page, list);
}

static uint32_t adjust_ioeventfd_endianness(uint32_t val, uint32_t size)
{
#if HOST_BIG_ENDIAN != TARGET_BIG_ENDIAN
    /* The kernel expects ioeventfd values in HOST_BIG_ENDIAN
     * endianness, but the memory core hands them in target endianness.
     * For example, PPC is always treated as big-endian even if running
     * on KVM and on PPC64LE.  Correct here.
     */
    switch (size) {
    case 2:
        val = bswap16(val);
        break;
    case 4:
        val = bswap32(val);
        break;
    }
#endif
    return val;
}

static int kvm_set_ioeventfd_mmio(int fd, hwaddr addr, uint32_t val,
                                  bool assign, uint32_t size, bool datamatch)
{
    int ret;
    struct kvm_ioeventfd iofd = {
        .datamatch = datamatch ? adjust_ioeventfd_endianness(val, size) : 0,
        .addr = addr,
        .len = size,
        .flags = 0,
        .fd = fd,
    };

    trace_kvm_set_ioeventfd_mmio(fd, (uint64_t)addr, val, assign, size,
                                 datamatch);
    if (!kvm_enabled()) {
        return -ENOSYS;
    }

    if (datamatch) {
        iofd.flags |= KVM_IOEVENTFD_FLAG_DATAMATCH;
    }
    if (!assign) {
        iofd.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
    }

    ret = kvm_vm_ioctl(kvm_state, KVM_IOEVENTFD, &iofd);

    if (ret < 0) {
        return -errno;
    }

    return 0;
}

static int kvm_set_ioeventfd_pio(int fd, uint16_t addr, uint16_t val,
                                 bool assign, uint32_t size, bool datamatch)
{
    struct kvm_ioeventfd kick = {
        .datamatch = datamatch ? adjust_ioeventfd_endianness(val, size) : 0,
        .addr = addr,
        .flags = KVM_IOEVENTFD_FLAG_PIO,
        .len = size,
        .fd = fd,
    };
    int r;
    trace_kvm_set_ioeventfd_pio(fd, addr, val, assign, size, datamatch);
    if (!kvm_enabled()) {
        return -ENOSYS;
    }
    if (datamatch) {
        kick.flags |= KVM_IOEVENTFD_FLAG_DATAMATCH;
    }
    if (!assign) {
        kick.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
    }
    r = kvm_vm_ioctl(kvm_state, KVM_IOEVENTFD, &kick);
    if (r < 0) {
        return r;
    }
    return 0;
}


static int kvm_check_many_ioeventfds(void)
{
    /* Userspace can use ioeventfd for io notification.  This requires a host
     * that supports eventfd(2) and an I/O thread; since eventfd does not
     * support SIGIO it cannot interrupt the vcpu.
     *
     * Older kernels have a 6 device limit on the KVM io bus.  Find out so we
     * can avoid creating too many ioeventfds.
     */
#if defined(CONFIG_EVENTFD)
    int ioeventfds[7];
    int i, ret = 0;
    for (i = 0; i < ARRAY_SIZE(ioeventfds); i++) {
        ioeventfds[i] = eventfd(0, EFD_CLOEXEC);
        if (ioeventfds[i] < 0) {
            break;
        }
        ret = kvm_set_ioeventfd_pio(ioeventfds[i], 0, i, true, 2, true);
        if (ret < 0) {
            close(ioeventfds[i]);
            break;
        }
    }

    /* Decide whether many devices are supported or not */
    ret = i == ARRAY_SIZE(ioeventfds);

    while (i-- > 0) {
        kvm_set_ioeventfd_pio(ioeventfds[i], 0, i, false, 2, true);
        close(ioeventfds[i]);
    }
    return ret;
#else
    return 0;
#endif
}

static const KVMCapabilityInfo *
kvm_check_extension_list(KVMState *s, const KVMCapabilityInfo *list)
{
    while (list->name) {
        if (!kvm_check_extension(s, list->value)) {
            return list;
        }
        list++;
    }
    return NULL;
}

void kvm_set_max_memslot_size(hwaddr max_slot_size)
{
    g_assert(
        ROUND_UP(max_slot_size, qemu_real_host_page_size()) == max_slot_size
    );
    kvm_max_slot_size = max_slot_size;
}

static void kvm_set_phys_mem(KVMMemoryListener *kml,
                             MemoryRegionSection *section, bool add)
{
    KVMSlot *mem;
    int err;
    MemoryRegion *mr = section->mr;
    bool writable = !mr->readonly && !mr->rom_device;
    hwaddr start_addr, size, slot_size, mr_offset;
    ram_addr_t ram_start_offset;
    void *ram;

    if (!memory_region_is_ram(mr)) {
        if (writable || !kvm_readonly_mem_allowed) {
            return;
        } else if (!mr->romd_mode) {
            /* If the memory device is not in romd_mode, then we actually want
             * to remove the kvm memory slot so all accesses will trap. */
            add = false;
        }
    }

    size = kvm_align_section(section, &start_addr);
    if (!size) {
        return;
    }

    /* The offset of the kvmslot within the memory region */
    mr_offset = section->offset_within_region + start_addr -
        section->offset_within_address_space;

    /* use aligned delta to align the ram address and offset */
    ram = memory_region_get_ram_ptr(mr) + mr_offset;
    ram_start_offset = memory_region_get_ram_addr(mr) + mr_offset;

    kvm_slots_lock();
    int i = 0;

    if (!add) {
        do {
            slot_size = MIN(kvm_max_slot_size, size);
            mem = kvm_lookup_matching_slot(kml, start_addr, slot_size);
            if (!mem) {
                goto out;
            }
            if (mem->flags & KVM_MEM_LOG_DIRTY_PAGES) {
                /*
                 * NOTE: We should be aware of the fact that here we're only
                 * doing a best effort to sync dirty bits.  No matter whether
                 * we're using dirty log or dirty ring, we ignored two facts:
                 *
                 * (1) dirty bits can reside in hardware buffers (PML)
                 *
                 * (2) after we collected dirty bits here, pages can be dirtied
                 * again before we do the final KVM_SET_USER_MEMORY_REGION to
                 * remove the slot.
                 *
                 * Not easy.  Let's cross the fingers until it's fixed.
                 */
                if (kvm_state->kvm_dirty_ring_size) {
                    kvm_dirty_ring_reap_locked(kvm_state, NULL);
                } else {
                    kvm_slot_get_dirty_log(kvm_state, mem);
                }
                kvm_slot_sync_dirty_pages(mem);
            }

            /* unregister the slot */
            g_free(mem->dirty_bmap);
            mem->dirty_bmap = NULL;
            mem->memory_size = 0;
            mem->flags = 0;
            if (mem->slot < HYPERUPCALL_MAX_N_MEMSLOTS && memslot_npages_local[mem->slot] != 0 && mem->as_id == 0) {
                fprintf(stderr, "delete: i: %d mem->slot: %d slot_size: %lx start_addr: %lx ram: %p \n", i++, mem->slot, slot_size, start_addr, ram);
                memslot_as_id[mem->slot] = 0;
                memslot_npages_local[mem->slot] = 0;
                memslot_base_gfns_local[mem->slot] = 0;
                memslot_userptrs_local[mem->slot] = 0;
            }
            err = kvm_set_user_memory_region(kml, mem, false);
            if (err) {
                fprintf(stderr, "%s: error unregistering slot: %s\n",
                        __func__, strerror(-err));
                abort();
            }
            start_addr += slot_size;
            size -= slot_size;
        } while (size);
        goto out;
    }

    /* register the new slot */
    // temp_start_addr = start_addr;
    // temp_ram = ram;
    // total_slot_size = size;
    do {
        slot_size = MIN(kvm_max_slot_size, size);
        mem = kvm_alloc_slot(kml);
        mem->as_id = kml->as_id;
        mem->memory_size = slot_size;
        mem->start_addr = start_addr;
        mem->ram_start_offset = ram_start_offset;
        mem->ram = ram;
        mem->flags = kvm_mem_flags(mr);
        kvm_slot_init_dirty_bitmap(mem);
        if (mem != NULL && mem->slot < HYPERUPCALL_MAX_N_MEMSLOTS && mem->as_id == 0) {
            fprintf(stderr, "create: i: %d, mem->slot: %d slot_size: %lx start_addr: %lx ram: %p \n", i++, mem->slot, slot_size, start_addr, ram);
            memslot_as_id[mem->slot] = kml->as_id;
            memslot_npages_local[mem->slot] = (unsigned long long)slot_size >> 12;
            memslot_base_gfns_local[mem->slot] = (unsigned long long)start_addr >> 12;
            memslot_userptrs_local[mem->slot] = (unsigned long long)ram;
        }
        else {
            fprintf(stderr, "kvm_set_phys_mem: mem->slot %d exceeds HYPERUPCALL_MAX_N_MEMSLOTS %d\n",
                    mem->slot, HYPERUPCALL_MAX_N_MEMSLOTS);
        }
        err = kvm_set_user_memory_region(kml, mem, true);
        if (err) {
            fprintf(stderr, "%s: error registering slot: %s\n", __func__,
                    strerror(-err));
            abort();
        }
        start_addr += slot_size;
        ram_start_offset += slot_size;
        ram += slot_size;
        size -= slot_size;
    } while (size);

out:
    kvm_slots_unlock();
}

static void *kvm_dirty_ring_reaper_thread(void *data)
{
    KVMState *s = data;
    struct KVMDirtyRingReaper *r = &s->reaper;

    rcu_register_thread();

    trace_kvm_dirty_ring_reaper("init");

    while (true) {
        r->reaper_state = KVM_DIRTY_RING_REAPER_WAIT;
        trace_kvm_dirty_ring_reaper("wait");
        /*
         * TODO: provide a smarter timeout rather than a constant?
         */
        sleep(1);

        /* keep sleeping so that dirtylimit not be interfered by reaper */
        if (dirtylimit_in_service()) {
            continue;
        }

        trace_kvm_dirty_ring_reaper("wakeup");
        r->reaper_state = KVM_DIRTY_RING_REAPER_REAPING;

        qemu_mutex_lock_iothread();
        kvm_dirty_ring_reap(s, NULL);
        qemu_mutex_unlock_iothread();

        r->reaper_iteration++;
    }

    trace_kvm_dirty_ring_reaper("exit");

    rcu_unregister_thread();

    return NULL;
}

static int kvm_dirty_ring_reaper_init(KVMState *s)
{
    struct KVMDirtyRingReaper *r = &s->reaper;

    qemu_thread_create(&r->reaper_thr, "kvm-reaper",
                       kvm_dirty_ring_reaper_thread,
                       s, QEMU_THREAD_JOINABLE);

    return 0;
}

static void kvm_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);

    memory_region_ref(section->mr);
    kvm_set_phys_mem(kml, section, true);
}

static void kvm_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);

    kvm_set_phys_mem(kml, section, false);
    memory_region_unref(section->mr);
}

static void kvm_log_sync(MemoryListener *listener,
                         MemoryRegionSection *section)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);

    kvm_slots_lock();
    kvm_physical_sync_dirty_bitmap(kml, section);
    kvm_slots_unlock();
}

static void kvm_log_sync_global(MemoryListener *l)
{
    KVMMemoryListener *kml = container_of(l, KVMMemoryListener, listener);
    KVMState *s = kvm_state;
    KVMSlot *mem;
    int i;

    /* Flush all kernel dirty addresses into KVMSlot dirty bitmap */
    kvm_dirty_ring_flush();

    /*
     * TODO: make this faster when nr_slots is big while there are
     * only a few used slots (small VMs).
     */
    kvm_slots_lock();
    for (i = 0; i < s->nr_slots; i++) {
        mem = &kml->slots[i];
        if (mem->memory_size && mem->flags & KVM_MEM_LOG_DIRTY_PAGES) {
            kvm_slot_sync_dirty_pages(mem);
            /*
             * This is not needed by KVM_GET_DIRTY_LOG because the
             * ioctl will unconditionally overwrite the whole region.
             * However kvm dirty ring has no such side effect.
             */
            kvm_slot_reset_dirty_pages(mem);
        }
    }
    kvm_slots_unlock();
}

static void kvm_log_clear(MemoryListener *listener,
                          MemoryRegionSection *section)
{
    KVMMemoryListener *kml = container_of(listener, KVMMemoryListener, listener);
    int r;

    r = kvm_physical_log_clear(kml, section);
    if (r < 0) {
        error_report_once("%s: kvm log clear failed: mr=%s "
                          "offset=%"HWADDR_PRIx" size=%"PRIx64, __func__,
                          section->mr->name, section->offset_within_region,
                          int128_get64(section->size));
        abort();
    }
}

static void kvm_mem_ioeventfd_add(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    r = kvm_set_ioeventfd_mmio(fd, section->offset_within_address_space,
                               data, true, int128_get64(section->size),
                               match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n",
                __func__, strerror(-r), -r);
        abort();
    }
}

static void kvm_mem_ioeventfd_del(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    r = kvm_set_ioeventfd_mmio(fd, section->offset_within_address_space,
                               data, false, int128_get64(section->size),
                               match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error deleting ioeventfd: %s (%d)\n",
                __func__, strerror(-r), -r);
        abort();
    }
}

static void kvm_io_ioeventfd_add(MemoryListener *listener,
                                 MemoryRegionSection *section,
                                 bool match_data, uint64_t data,
                                 EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    r = kvm_set_ioeventfd_pio(fd, section->offset_within_address_space,
                              data, true, int128_get64(section->size),
                              match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n",
                __func__, strerror(-r), -r);
        abort();
    }
}

static void kvm_io_ioeventfd_del(MemoryListener *listener,
                                 MemoryRegionSection *section,
                                 bool match_data, uint64_t data,
                                 EventNotifier *e)

{
    int fd = event_notifier_get_fd(e);
    int r;

    r = kvm_set_ioeventfd_pio(fd, section->offset_within_address_space,
                              data, false, int128_get64(section->size),
                              match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error deleting ioeventfd: %s (%d)\n",
                __func__, strerror(-r), -r);
        abort();
    }
}

void kvm_memory_listener_register(KVMState *s, KVMMemoryListener *kml,
                                  AddressSpace *as, int as_id, const char *name)
{
    int i;

    kml->slots = g_new0(KVMSlot, s->nr_slots);
    kml->as_id = as_id;

    for (i = 0; i < s->nr_slots; i++) {
        kml->slots[i].slot = i;
    }

    kml->listener.region_add = kvm_region_add;
    kml->listener.region_del = kvm_region_del;
    kml->listener.log_start = kvm_log_start;
    kml->listener.log_stop = kvm_log_stop;
    kml->listener.priority = 10;
    kml->listener.name = name;

    if (s->kvm_dirty_ring_size) {
        kml->listener.log_sync_global = kvm_log_sync_global;
    } else {
        kml->listener.log_sync = kvm_log_sync;
        kml->listener.log_clear = kvm_log_clear;
    }

    memory_listener_register(&kml->listener, as);

    for (i = 0; i < s->nr_as; ++i) {
        if (!s->as[i].as) {
            s->as[i].as = as;
            s->as[i].ml = kml;
            break;
        }
    }
}

static MemoryListener kvm_io_listener = {
    .name = "kvm-io",
    .eventfd_add = kvm_io_ioeventfd_add,
    .eventfd_del = kvm_io_ioeventfd_del,
    .priority = 10,
};

int kvm_set_irq(KVMState *s, int irq, int level)
{
    struct kvm_irq_level event;
    int ret;

    assert(kvm_async_interrupts_enabled());

    event.level = level;
    event.irq = irq;
    ret = kvm_vm_ioctl(s, s->irq_set_ioctl, &event);
    if (ret < 0) {
        perror("kvm_set_irq");
        abort();
    }

    return (s->irq_set_ioctl == KVM_IRQ_LINE) ? 1 : event.status;
}

#ifdef KVM_CAP_IRQ_ROUTING
typedef struct KVMMSIRoute {
    struct kvm_irq_routing_entry kroute;
    QTAILQ_ENTRY(KVMMSIRoute) entry;
} KVMMSIRoute;

static void set_gsi(KVMState *s, unsigned int gsi)
{
    set_bit(gsi, s->used_gsi_bitmap);
}

static void clear_gsi(KVMState *s, unsigned int gsi)
{
    clear_bit(gsi, s->used_gsi_bitmap);
}

void kvm_init_irq_routing(KVMState *s)
{
    int gsi_count, i;

    gsi_count = kvm_check_extension(s, KVM_CAP_IRQ_ROUTING) - 1;
    if (gsi_count > 0) {
        /* Round up so we can search ints using ffs */
        s->used_gsi_bitmap = bitmap_new(gsi_count);
        s->gsi_count = gsi_count;
    }

    s->irq_routes = g_malloc0(sizeof(*s->irq_routes));
    s->nr_allocated_irq_routes = 0;

    if (!kvm_direct_msi_allowed) {
        for (i = 0; i < KVM_MSI_HASHTAB_SIZE; i++) {
            QTAILQ_INIT(&s->msi_hashtab[i]);
        }
    }

    kvm_arch_init_irq_routing(s);
}

void kvm_irqchip_commit_routes(KVMState *s)
{
    int ret;

    if (kvm_gsi_direct_mapping()) {
        return;
    }

    if (!kvm_gsi_routing_enabled()) {
        return;
    }

    s->irq_routes->flags = 0;
    trace_kvm_irqchip_commit_routes();
    ret = kvm_vm_ioctl(s, KVM_SET_GSI_ROUTING, s->irq_routes);
    assert(ret == 0);
}

static void kvm_add_routing_entry(KVMState *s,
                                  struct kvm_irq_routing_entry *entry)
{
    struct kvm_irq_routing_entry *new;
    int n, size;

    if (s->irq_routes->nr == s->nr_allocated_irq_routes) {
        n = s->nr_allocated_irq_routes * 2;
        if (n < 64) {
            n = 64;
        }
        size = sizeof(struct kvm_irq_routing);
        size += n * sizeof(*new);
        s->irq_routes = g_realloc(s->irq_routes, size);
        s->nr_allocated_irq_routes = n;
    }
    n = s->irq_routes->nr++;
    new = &s->irq_routes->entries[n];

    *new = *entry;

    set_gsi(s, entry->gsi);
}

static int kvm_update_routing_entry(KVMState *s,
                                    struct kvm_irq_routing_entry *new_entry)
{
    struct kvm_irq_routing_entry *entry;
    int n;

    for (n = 0; n < s->irq_routes->nr; n++) {
        entry = &s->irq_routes->entries[n];
        if (entry->gsi != new_entry->gsi) {
            continue;
        }

        if(!memcmp(entry, new_entry, sizeof *entry)) {
            return 0;
        }

        *entry = *new_entry;

        return 0;
    }

    return -ESRCH;
}

void kvm_irqchip_add_irq_route(KVMState *s, int irq, int irqchip, int pin)
{
    struct kvm_irq_routing_entry e = {};

    assert(pin < s->gsi_count);

    e.gsi = irq;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    kvm_add_routing_entry(s, &e);
}

void kvm_irqchip_release_virq(KVMState *s, int virq)
{
    struct kvm_irq_routing_entry *e;
    int i;

    if (kvm_gsi_direct_mapping()) {
        return;
    }

    for (i = 0; i < s->irq_routes->nr; i++) {
        e = &s->irq_routes->entries[i];
        if (e->gsi == virq) {
            s->irq_routes->nr--;
            *e = s->irq_routes->entries[s->irq_routes->nr];
        }
    }
    clear_gsi(s, virq);
    kvm_arch_release_virq_post(virq);
    trace_kvm_irqchip_release_virq(virq);
}

void kvm_irqchip_add_change_notifier(Notifier *n)
{
    notifier_list_add(&kvm_irqchip_change_notifiers, n);
}

void kvm_irqchip_remove_change_notifier(Notifier *n)
{
    notifier_remove(n);
}

void kvm_irqchip_change_notify(void)
{
    notifier_list_notify(&kvm_irqchip_change_notifiers, NULL);
}

static unsigned int kvm_hash_msi(uint32_t data)
{
    /* This is optimized for IA32 MSI layout. However, no other arch shall
     * repeat the mistake of not providing a direct MSI injection API. */
    return data & 0xff;
}

static void kvm_flush_dynamic_msi_routes(KVMState *s)
{
    KVMMSIRoute *route, *next;
    unsigned int hash;

    for (hash = 0; hash < KVM_MSI_HASHTAB_SIZE; hash++) {
        QTAILQ_FOREACH_SAFE(route, &s->msi_hashtab[hash], entry, next) {
            kvm_irqchip_release_virq(s, route->kroute.gsi);
            QTAILQ_REMOVE(&s->msi_hashtab[hash], route, entry);
            g_free(route);
        }
    }
}

static int kvm_irqchip_get_virq(KVMState *s)
{
    int next_virq;

    /*
     * PIC and IOAPIC share the first 16 GSI numbers, thus the available
     * GSI numbers are more than the number of IRQ route. Allocating a GSI
     * number can succeed even though a new route entry cannot be added.
     * When this happens, flush dynamic MSI entries to free IRQ route entries.
     */
    if (!kvm_direct_msi_allowed && s->irq_routes->nr == s->gsi_count) {
        kvm_flush_dynamic_msi_routes(s);
    }

    /* Return the lowest unused GSI in the bitmap */
    next_virq = find_first_zero_bit(s->used_gsi_bitmap, s->gsi_count);
    if (next_virq >= s->gsi_count) {
        return -ENOSPC;
    } else {
        return next_virq;
    }
}

static KVMMSIRoute *kvm_lookup_msi_route(KVMState *s, MSIMessage msg)
{
    unsigned int hash = kvm_hash_msi(msg.data);
    KVMMSIRoute *route;

    QTAILQ_FOREACH(route, &s->msi_hashtab[hash], entry) {
        if (route->kroute.u.msi.address_lo == (uint32_t)msg.address &&
            route->kroute.u.msi.address_hi == (msg.address >> 32) &&
            route->kroute.u.msi.data == le32_to_cpu(msg.data)) {
            return route;
        }
    }
    return NULL;
}

int kvm_irqchip_send_msi(KVMState *s, MSIMessage msg)
{
    struct kvm_msi msi;
    KVMMSIRoute *route;

    if (kvm_direct_msi_allowed) {
        msi.address_lo = (uint32_t)msg.address;
        msi.address_hi = msg.address >> 32;
        msi.data = le32_to_cpu(msg.data);
        msi.flags = 0;
        memset(msi.pad, 0, sizeof(msi.pad));

        return kvm_vm_ioctl(s, KVM_SIGNAL_MSI, &msi);
    }

    route = kvm_lookup_msi_route(s, msg);
    if (!route) {
        int virq;

        virq = kvm_irqchip_get_virq(s);
        if (virq < 0) {
            return virq;
        }

        route = g_new0(KVMMSIRoute, 1);
        route->kroute.gsi = virq;
        route->kroute.type = KVM_IRQ_ROUTING_MSI;
        route->kroute.flags = 0;
        route->kroute.u.msi.address_lo = (uint32_t)msg.address;
        route->kroute.u.msi.address_hi = msg.address >> 32;
        route->kroute.u.msi.data = le32_to_cpu(msg.data);

        kvm_add_routing_entry(s, &route->kroute);
        kvm_irqchip_commit_routes(s);

        QTAILQ_INSERT_TAIL(&s->msi_hashtab[kvm_hash_msi(msg.data)], route,
                           entry);
    }

    assert(route->kroute.type == KVM_IRQ_ROUTING_MSI);

    return kvm_set_irq(s, route->kroute.gsi, 1);
}

int kvm_irqchip_add_msi_route(KVMRouteChange *c, int vector, PCIDevice *dev)
{
    struct kvm_irq_routing_entry kroute = {};
    int virq;
    KVMState *s = c->s;
    MSIMessage msg = {0, 0};

    if (pci_available && dev) {
        msg = pci_get_msi_message(dev, vector);
    }

    if (kvm_gsi_direct_mapping()) {
        return kvm_arch_msi_data_to_gsi(msg.data);
    }

    if (!kvm_gsi_routing_enabled()) {
        return -ENOSYS;
    }

    virq = kvm_irqchip_get_virq(s);
    if (virq < 0) {
        return virq;
    }

    kroute.gsi = virq;
    kroute.type = KVM_IRQ_ROUTING_MSI;
    kroute.flags = 0;
    kroute.u.msi.address_lo = (uint32_t)msg.address;
    kroute.u.msi.address_hi = msg.address >> 32;
    kroute.u.msi.data = le32_to_cpu(msg.data);
    if (pci_available && kvm_msi_devid_required()) {
        kroute.flags = KVM_MSI_VALID_DEVID;
        kroute.u.msi.devid = pci_requester_id(dev);
    }
    if (kvm_arch_fixup_msi_route(&kroute, msg.address, msg.data, dev)) {
        kvm_irqchip_release_virq(s, virq);
        return -EINVAL;
    }

    trace_kvm_irqchip_add_msi_route(dev ? dev->name : (char *)"N/A",
                                    vector, virq);

    kvm_add_routing_entry(s, &kroute);
    kvm_arch_add_msi_route_post(&kroute, vector, dev);
    c->changes++;

    return virq;
}

int kvm_irqchip_update_msi_route(KVMState *s, int virq, MSIMessage msg,
                                 PCIDevice *dev)
{
    struct kvm_irq_routing_entry kroute = {};

    if (kvm_gsi_direct_mapping()) {
        return 0;
    }

    if (!kvm_irqchip_in_kernel()) {
        return -ENOSYS;
    }

    kroute.gsi = virq;
    kroute.type = KVM_IRQ_ROUTING_MSI;
    kroute.flags = 0;
    kroute.u.msi.address_lo = (uint32_t)msg.address;
    kroute.u.msi.address_hi = msg.address >> 32;
    kroute.u.msi.data = le32_to_cpu(msg.data);
    if (pci_available && kvm_msi_devid_required()) {
        kroute.flags = KVM_MSI_VALID_DEVID;
        kroute.u.msi.devid = pci_requester_id(dev);
    }
    if (kvm_arch_fixup_msi_route(&kroute, msg.address, msg.data, dev)) {
        return -EINVAL;
    }

    trace_kvm_irqchip_update_msi_route(virq);

    return kvm_update_routing_entry(s, &kroute);
}

static int kvm_irqchip_assign_irqfd(KVMState *s, EventNotifier *event,
                                    EventNotifier *resample, int virq,
                                    bool assign)
{
    int fd = event_notifier_get_fd(event);
    int rfd = resample ? event_notifier_get_fd(resample) : -1;

    struct kvm_irqfd irqfd = {
        .fd = fd,
        .gsi = virq,
        .flags = assign ? 0 : KVM_IRQFD_FLAG_DEASSIGN,
    };

    if (rfd != -1) {
        assert(assign);
        if (kvm_irqchip_is_split()) {
            /*
             * When the slow irqchip (e.g. IOAPIC) is in the
             * userspace, KVM kernel resamplefd will not work because
             * the EOI of the interrupt will be delivered to userspace
             * instead, so the KVM kernel resamplefd kick will be
             * skipped.  The userspace here mimics what the kernel
             * provides with resamplefd, remember the resamplefd and
             * kick it when we receive EOI of this IRQ.
             *
             * This is hackery because IOAPIC is mostly bypassed
             * (except EOI broadcasts) when irqfd is used.  However
             * this can bring much performance back for split irqchip
             * with INTx IRQs (for VFIO, this gives 93% perf of the
             * full fast path, which is 46% perf boost comparing to
             * the INTx slow path).
             */
            kvm_resample_fd_insert(virq, resample);
        } else {
            irqfd.flags |= KVM_IRQFD_FLAG_RESAMPLE;
            irqfd.resamplefd = rfd;
        }
    } else if (!assign) {
        if (kvm_irqchip_is_split()) {
            kvm_resample_fd_remove(virq);
        }
    }

    if (!kvm_irqfds_enabled()) {
        return -ENOSYS;
    }

    return kvm_vm_ioctl(s, KVM_IRQFD, &irqfd);
}

int kvm_irqchip_add_adapter_route(KVMState *s, AdapterInfo *adapter)
{
    struct kvm_irq_routing_entry kroute = {};
    int virq;

    if (!kvm_gsi_routing_enabled()) {
        return -ENOSYS;
    }

    virq = kvm_irqchip_get_virq(s);
    if (virq < 0) {
        return virq;
    }

    kroute.gsi = virq;
    kroute.type = KVM_IRQ_ROUTING_S390_ADAPTER;
    kroute.flags = 0;
    kroute.u.adapter.summary_addr = adapter->summary_addr;
    kroute.u.adapter.ind_addr = adapter->ind_addr;
    kroute.u.adapter.summary_offset = adapter->summary_offset;
    kroute.u.adapter.ind_offset = adapter->ind_offset;
    kroute.u.adapter.adapter_id = adapter->adapter_id;

    kvm_add_routing_entry(s, &kroute);

    return virq;
}

int kvm_irqchip_add_hv_sint_route(KVMState *s, uint32_t vcpu, uint32_t sint)
{
    struct kvm_irq_routing_entry kroute = {};
    int virq;

    if (!kvm_gsi_routing_enabled()) {
        return -ENOSYS;
    }
    if (!kvm_check_extension(s, KVM_CAP_HYPERV_SYNIC)) {
        return -ENOSYS;
    }
    virq = kvm_irqchip_get_virq(s);
    if (virq < 0) {
        return virq;
    }

    kroute.gsi = virq;
    kroute.type = KVM_IRQ_ROUTING_HV_SINT;
    kroute.flags = 0;
    kroute.u.hv_sint.vcpu = vcpu;
    kroute.u.hv_sint.sint = sint;

    kvm_add_routing_entry(s, &kroute);
    kvm_irqchip_commit_routes(s);

    return virq;
}

#else /* !KVM_CAP_IRQ_ROUTING */

void kvm_init_irq_routing(KVMState *s)
{
}

void kvm_irqchip_release_virq(KVMState *s, int virq)
{
}

int kvm_irqchip_send_msi(KVMState *s, MSIMessage msg)
{
    abort();
}

int kvm_irqchip_add_msi_route(KVMRouteChange *c, int vector, PCIDevice *dev)
{
    return -ENOSYS;
}

int kvm_irqchip_add_adapter_route(KVMState *s, AdapterInfo *adapter)
{
    return -ENOSYS;
}

int kvm_irqchip_add_hv_sint_route(KVMState *s, uint32_t vcpu, uint32_t sint)
{
    return -ENOSYS;
}

static int kvm_irqchip_assign_irqfd(KVMState *s, EventNotifier *event,
                                    EventNotifier *resample, int virq,
                                    bool assign)
{
    abort();
}

int kvm_irqchip_update_msi_route(KVMState *s, int virq, MSIMessage msg)
{
    return -ENOSYS;
}
#endif /* !KVM_CAP_IRQ_ROUTING */

int kvm_irqchip_add_irqfd_notifier_gsi(KVMState *s, EventNotifier *n,
                                       EventNotifier *rn, int virq)
{
    return kvm_irqchip_assign_irqfd(s, n, rn, virq, true);
}

int kvm_irqchip_remove_irqfd_notifier_gsi(KVMState *s, EventNotifier *n,
                                          int virq)
{
    return kvm_irqchip_assign_irqfd(s, n, NULL, virq, false);
}

int kvm_irqchip_add_irqfd_notifier(KVMState *s, EventNotifier *n,
                                   EventNotifier *rn, qemu_irq irq)
{
    gpointer key, gsi;
    gboolean found = g_hash_table_lookup_extended(s->gsimap, irq, &key, &gsi);

    if (!found) {
        return -ENXIO;
    }
    return kvm_irqchip_add_irqfd_notifier_gsi(s, n, rn, GPOINTER_TO_INT(gsi));
}

int kvm_irqchip_remove_irqfd_notifier(KVMState *s, EventNotifier *n,
                                      qemu_irq irq)
{
    gpointer key, gsi;
    gboolean found = g_hash_table_lookup_extended(s->gsimap, irq, &key, &gsi);

    if (!found) {
        return -ENXIO;
    }
    return kvm_irqchip_remove_irqfd_notifier_gsi(s, n, GPOINTER_TO_INT(gsi));
}

void kvm_irqchip_set_qemuirq_gsi(KVMState *s, qemu_irq irq, int gsi)
{
    g_hash_table_insert(s->gsimap, irq, GINT_TO_POINTER(gsi));
}

static void kvm_irqchip_create(KVMState *s)
{
    int ret;

    assert(s->kernel_irqchip_split != ON_OFF_AUTO_AUTO);
    if (kvm_check_extension(s, KVM_CAP_IRQCHIP)) {
        ;
    } else if (kvm_check_extension(s, KVM_CAP_S390_IRQCHIP)) {
        ret = kvm_vm_enable_cap(s, KVM_CAP_S390_IRQCHIP, 0);
        if (ret < 0) {
            fprintf(stderr, "Enable kernel irqchip failed: %s\n", strerror(-ret));
            exit(1);
        }
    } else {
        return;
    }

    /* First probe and see if there's a arch-specific hook to create the
     * in-kernel irqchip for us */
    ret = kvm_arch_irqchip_create(s);
    if (ret == 0) {
        if (s->kernel_irqchip_split == ON_OFF_AUTO_ON) {
            error_report("Split IRQ chip mode not supported.");
            exit(1);
        } else {
            ret = kvm_vm_ioctl(s, KVM_CREATE_IRQCHIP);
        }
    }
    if (ret < 0) {
        fprintf(stderr, "Create kernel irqchip failed: %s\n", strerror(-ret));
        exit(1);
    }

    kvm_kernel_irqchip = true;
    /* If we have an in-kernel IRQ chip then we must have asynchronous
     * interrupt delivery (though the reverse is not necessarily true)
     */
    kvm_async_interrupts_allowed = true;
    kvm_halt_in_kernel_allowed = true;

    kvm_init_irq_routing(s);

    s->gsimap = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/* Find number of supported CPUs using the recommended
 * procedure from the kernel API documentation to cope with
 * older kernels that may be missing capabilities.
 */
static int kvm_recommended_vcpus(KVMState *s)
{
    int ret = kvm_vm_check_extension(s, KVM_CAP_NR_VCPUS);
    return (ret) ? ret : 4;
}

static int kvm_max_vcpus(KVMState *s)
{
    int ret = kvm_check_extension(s, KVM_CAP_MAX_VCPUS);
    return (ret) ? ret : kvm_recommended_vcpus(s);
}

static int kvm_max_vcpu_id(KVMState *s)
{
    int ret = kvm_check_extension(s, KVM_CAP_MAX_VCPU_ID);
    return (ret) ? ret : kvm_max_vcpus(s);
}

bool kvm_vcpu_id_is_valid(int vcpu_id)
{
    KVMState *s = KVM_STATE(current_accel());
    return vcpu_id >= 0 && vcpu_id < kvm_max_vcpu_id(s);
}

bool kvm_dirty_ring_enabled(void)
{
    return kvm_state->kvm_dirty_ring_size ? true : false;
}

static void query_stats_cb(StatsResultList **result, StatsTarget target,
                           strList *names, strList *targets, Error **errp);
static void query_stats_schemas_cb(StatsSchemaList **result, Error **errp);

uint32_t kvm_dirty_ring_size(void)
{
    return kvm_state->kvm_dirty_ring_size;
}

static int kvm_init(MachineState *ms)
{
    MachineClass *mc = MACHINE_GET_CLASS(ms);
    static const char upgrade_note[] =
        "Please upgrade to at least kernel 2.6.29 or recent kvm-kmod\n"
        "(see http://sourceforge.net/projects/kvm).\n";
    struct {
        const char *name;
        int num;
    } num_cpus[] = {
        { "SMP",          ms->smp.cpus },
        { "hotpluggable", ms->smp.max_cpus },
        { NULL, }
    }, *nc = num_cpus;
    int soft_vcpus_limit, hard_vcpus_limit;
    KVMState *s;
    const KVMCapabilityInfo *missing_cap;
    int ret;
    int type = 0;
    uint64_t dirty_log_manual_caps;

    qemu_mutex_init(&kml_slots_lock);

    s = KVM_STATE(ms->accelerator);

    /*
     * On systems where the kernel can support different base page
     * sizes, host page size may be different from TARGET_PAGE_SIZE,
     * even with KVM.  TARGET_PAGE_SIZE is assumed to be the minimum
     * page size for the system though.
     */
    assert(TARGET_PAGE_SIZE <= qemu_real_host_page_size());

    s->sigmask_len = 8;

#ifdef KVM_CAP_SET_GUEST_DEBUG
    QTAILQ_INIT(&s->kvm_sw_breakpoints);
#endif
    QLIST_INIT(&s->kvm_parked_vcpus);
    s->fd = qemu_open_old("/dev/kvm", O_RDWR);
    if (s->fd == -1) {
        fprintf(stderr, "Could not access KVM kernel module: %m\n");
        ret = -errno;
        goto err;
    }

    ret = kvm_ioctl(s, KVM_GET_API_VERSION, 0);
    if (ret < KVM_API_VERSION) {
        if (ret >= 0) {
            ret = -EINVAL;
        }
        fprintf(stderr, "kvm version too old\n");
        goto err;
    }

    if (ret > KVM_API_VERSION) {
        ret = -EINVAL;
        fprintf(stderr, "kvm version not supported\n");
        goto err;
    }

    kvm_immediate_exit = kvm_check_extension(s, KVM_CAP_IMMEDIATE_EXIT);
    s->nr_slots = kvm_check_extension(s, KVM_CAP_NR_MEMSLOTS);

    /* If unspecified, use the default value */
    if (!s->nr_slots) {
        s->nr_slots = 32;
    }

    s->nr_as = kvm_check_extension(s, KVM_CAP_MULTI_ADDRESS_SPACE);
    if (s->nr_as <= 1) {
        s->nr_as = 1;
    }
    s->as = g_new0(struct KVMAs, s->nr_as);

    if (object_property_find(OBJECT(current_machine), "kvm-type")) {
        g_autofree char *kvm_type = object_property_get_str(OBJECT(current_machine),
                                                            "kvm-type",
                                                            &error_abort);
        type = mc->kvm_type(ms, kvm_type);
    } else if (mc->kvm_type) {
        type = mc->kvm_type(ms, NULL);
    }

    do {
        ret = kvm_ioctl(s, KVM_CREATE_VM, type);
    } while (ret == -EINTR);

    if (ret < 0) {
        fprintf(stderr, "ioctl(KVM_CREATE_VM) failed: %d %s\n", -ret,
                strerror(-ret));

#ifdef TARGET_S390X
        if (ret == -EINVAL) {
            fprintf(stderr,
                    "Host kernel setup problem detected. Please verify:\n");
            fprintf(stderr, "- for kernels supporting the switch_amode or"
                    " user_mode parameters, whether\n");
            fprintf(stderr,
                    "  user space is running in primary address space\n");
            fprintf(stderr,
                    "- for kernels supporting the vm.allocate_pgste sysctl, "
                    "whether it is enabled\n");
        }
#elif defined(TARGET_PPC)
        if (ret == -EINVAL) {
            fprintf(stderr,
                    "PPC KVM module is not loaded. Try modprobe kvm_%s.\n",
                    (type == 2) ? "pr" : "hv");
        }
#endif
        goto err;
    }

    s->vmfd = ret;

    /* check the vcpu limits */
    soft_vcpus_limit = kvm_recommended_vcpus(s);
    hard_vcpus_limit = kvm_max_vcpus(s);

    while (nc->name) {
        if (nc->num > soft_vcpus_limit) {
            warn_report("Number of %s cpus requested (%d) exceeds "
                        "the recommended cpus supported by KVM (%d)",
                        nc->name, nc->num, soft_vcpus_limit);

            if (nc->num > hard_vcpus_limit) {
                fprintf(stderr, "Number of %s cpus requested (%d) exceeds "
                        "the maximum cpus supported by KVM (%d)\n",
                        nc->name, nc->num, hard_vcpus_limit);
                exit(1);
            }
        }
        nc++;
    }

    missing_cap = kvm_check_extension_list(s, kvm_required_capabilites);
    if (!missing_cap) {
        missing_cap =
            kvm_check_extension_list(s, kvm_arch_required_capabilities);
    }
    if (missing_cap) {
        ret = -EINVAL;
        fprintf(stderr, "kvm does not support %s\n%s",
                missing_cap->name, upgrade_note);
        goto err;
    }

    s->coalesced_mmio = kvm_check_extension(s, KVM_CAP_COALESCED_MMIO);
    s->coalesced_pio = s->coalesced_mmio &&
                       kvm_check_extension(s, KVM_CAP_COALESCED_PIO);

    /*
     * Enable KVM dirty ring if supported, otherwise fall back to
     * dirty logging mode
     */
    if (s->kvm_dirty_ring_size > 0) {
        uint64_t ring_bytes;

        ring_bytes = s->kvm_dirty_ring_size * sizeof(struct kvm_dirty_gfn);

        /* Read the max supported pages */
        ret = kvm_vm_check_extension(s, KVM_CAP_DIRTY_LOG_RING);
        if (ret > 0) {
            if (ring_bytes > ret) {
                error_report("KVM dirty ring size %" PRIu32 " too big "
                             "(maximum is %ld).  Please use a smaller value.",
                             s->kvm_dirty_ring_size,
                             (long)ret / sizeof(struct kvm_dirty_gfn));
                ret = -EINVAL;
                goto err;
            }

            ret = kvm_vm_enable_cap(s, KVM_CAP_DIRTY_LOG_RING, 0, ring_bytes);
            if (ret) {
                error_report("Enabling of KVM dirty ring failed: %s. "
                             "Suggested minimum value is 1024.", strerror(-ret));
                goto err;
            }

            s->kvm_dirty_ring_bytes = ring_bytes;
         } else {
             warn_report("KVM dirty ring not available, using bitmap method");
             s->kvm_dirty_ring_size = 0;
        }
    }

    /*
     * KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 is not needed when dirty ring is
     * enabled.  More importantly, KVM_DIRTY_LOG_INITIALLY_SET will assume no
     * page is wr-protected initially, which is against how kvm dirty ring is
     * usage - kvm dirty ring requires all pages are wr-protected at the very
     * beginning.  Enabling this feature for dirty ring causes data corruption.
     *
     * TODO: Without KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 and kvm clear dirty log,
     * we may expect a higher stall time when starting the migration.  In the
     * future we can enable KVM_CLEAR_DIRTY_LOG to work with dirty ring too:
     * instead of clearing dirty bit, it can be a way to explicitly wr-protect
     * guest pages.
     */
    if (!s->kvm_dirty_ring_size) {
        dirty_log_manual_caps =
            kvm_check_extension(s, KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2);
        dirty_log_manual_caps &= (KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE |
                                  KVM_DIRTY_LOG_INITIALLY_SET);
        s->manual_dirty_log_protect = dirty_log_manual_caps;
        if (dirty_log_manual_caps) {
            ret = kvm_vm_enable_cap(s, KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2, 0,
                                    dirty_log_manual_caps);
            if (ret) {
                warn_report("Trying to enable capability %"PRIu64" of "
                            "KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 but failed. "
                            "Falling back to the legacy mode. ",
                            dirty_log_manual_caps);
                s->manual_dirty_log_protect = 0;
            }
        }
    }

#ifdef KVM_CAP_VCPU_EVENTS
    s->vcpu_events = kvm_check_extension(s, KVM_CAP_VCPU_EVENTS);
#endif

    s->robust_singlestep =
        kvm_check_extension(s, KVM_CAP_X86_ROBUST_SINGLESTEP);

#ifdef KVM_CAP_DEBUGREGS
    s->debugregs = kvm_check_extension(s, KVM_CAP_DEBUGREGS);
#endif

    s->max_nested_state_len = kvm_check_extension(s, KVM_CAP_NESTED_STATE);

#ifdef KVM_CAP_IRQ_ROUTING
    kvm_direct_msi_allowed = (kvm_check_extension(s, KVM_CAP_SIGNAL_MSI) > 0);
#endif

    s->intx_set_mask = kvm_check_extension(s, KVM_CAP_PCI_2_3);

    s->irq_set_ioctl = KVM_IRQ_LINE;
    if (kvm_check_extension(s, KVM_CAP_IRQ_INJECT_STATUS)) {
        s->irq_set_ioctl = KVM_IRQ_LINE_STATUS;
    }

    kvm_readonly_mem_allowed =
        (kvm_check_extension(s, KVM_CAP_READONLY_MEM) > 0);

    kvm_eventfds_allowed =
        (kvm_check_extension(s, KVM_CAP_IOEVENTFD) > 0);

    kvm_irqfds_allowed =
        (kvm_check_extension(s, KVM_CAP_IRQFD) > 0);

    kvm_resamplefds_allowed =
        (kvm_check_extension(s, KVM_CAP_IRQFD_RESAMPLE) > 0);

    kvm_vm_attributes_allowed =
        (kvm_check_extension(s, KVM_CAP_VM_ATTRIBUTES) > 0);

    kvm_ioeventfd_any_length_allowed =
        (kvm_check_extension(s, KVM_CAP_IOEVENTFD_ANY_LENGTH) > 0);

#ifdef KVM_CAP_SET_GUEST_DEBUG
    kvm_has_guest_debug =
        (kvm_check_extension(s, KVM_CAP_SET_GUEST_DEBUG) > 0);
#endif

    kvm_sstep_flags = 0;
    if (kvm_has_guest_debug) {
        kvm_sstep_flags = SSTEP_ENABLE;

#if defined KVM_CAP_SET_GUEST_DEBUG2
        int guest_debug_flags =
            kvm_check_extension(s, KVM_CAP_SET_GUEST_DEBUG2);

        if (guest_debug_flags & KVM_GUESTDBG_BLOCKIRQ) {
            kvm_sstep_flags |= SSTEP_NOIRQ;
        }
#endif
    }

    kvm_state = s;

    ret = kvm_arch_init(ms, s);
    if (ret < 0) {
        goto err;
    }

    if (s->kernel_irqchip_split == ON_OFF_AUTO_AUTO) {
        s->kernel_irqchip_split = mc->default_kernel_irqchip_split ? ON_OFF_AUTO_ON : ON_OFF_AUTO_OFF;
    }

    qemu_register_reset(kvm_unpoison_all, NULL);

    if (s->kernel_irqchip_allowed) {
        kvm_irqchip_create(s);
    }

    if (kvm_eventfds_allowed) {
        s->memory_listener.listener.eventfd_add = kvm_mem_ioeventfd_add;
        s->memory_listener.listener.eventfd_del = kvm_mem_ioeventfd_del;
    }
    s->memory_listener.listener.coalesced_io_add = kvm_coalesce_mmio_region;
    s->memory_listener.listener.coalesced_io_del = kvm_uncoalesce_mmio_region;

    kvm_memory_listener_register(s, &s->memory_listener,
                                 &address_space_memory, 0, "kvm-memory");
    if (kvm_eventfds_allowed) {
        memory_listener_register(&kvm_io_listener,
                                 &address_space_io);
    }
    memory_listener_register(&kvm_coalesced_pio_listener,
                             &address_space_io);

    s->many_ioeventfds = kvm_check_many_ioeventfds();

    s->sync_mmu = !!kvm_vm_check_extension(kvm_state, KVM_CAP_SYNC_MMU);
    if (!s->sync_mmu) {
        ret = ram_block_discard_disable(true);
        assert(!ret);
    }

    if (s->kvm_dirty_ring_size) {
        ret = kvm_dirty_ring_reaper_init(s);
        if (ret) {
            goto err;
        }
    }

    if (kvm_check_extension(kvm_state, KVM_CAP_BINARY_STATS_FD)) {
        add_stats_callbacks(STATS_PROVIDER_KVM, query_stats_cb,
                            query_stats_schemas_cb);
    }

    /* To allocate maps on launch, do it here Ori */

    return 0;

err:
    assert(ret < 0);
    if (s->vmfd >= 0) {
        close(s->vmfd);
    }
    if (s->fd != -1) {
        close(s->fd);
    }
    g_free(s->memory_listener.slots);

    return ret;
}

void kvm_set_sigmask_len(KVMState *s, unsigned int sigmask_len)
{
    s->sigmask_len = sigmask_len;
}

static void kvm_handle_io(uint16_t port, MemTxAttrs attrs, void *data, int direction,
                          int size, uint32_t count)
{
    int i;
    uint8_t *ptr = data;

    for (i = 0; i < count; i++) {
        address_space_rw(&address_space_io, port, attrs,
                         ptr, size,
                         direction == KVM_EXIT_IO_OUT);
        ptr += size;
    }
}

static int kvm_handle_internal_error(CPUState *cpu, struct kvm_run *run)
{
    fprintf(stderr, "KVM internal error. Suberror: %d\n",
            run->internal.suberror);

    if (kvm_check_extension(kvm_state, KVM_CAP_INTERNAL_ERROR_DATA)) {
        int i;

        for (i = 0; i < run->internal.ndata; ++i) {
            fprintf(stderr, "extra data[%d]: 0x%016"PRIx64"\n",
                    i, (uint64_t)run->internal.data[i]);
        }
    }
    if (run->internal.suberror == KVM_INTERNAL_ERROR_EMULATION) {
        fprintf(stderr, "emulation failure\n");
        if (!kvm_arch_stop_on_emulation_error(cpu)) {
            cpu_dump_state(cpu, stderr, CPU_DUMP_CODE);
            return EXCP_INTERRUPT;
        }
    }
    /* FIXME: Should trigger a qmp message to let management know
     * something went wrong.
     */
    return -1;
}

void kvm_flush_coalesced_mmio_buffer(void)
{
    KVMState *s = kvm_state;

    if (s->coalesced_flush_in_progress) {
        return;
    }

    s->coalesced_flush_in_progress = true;

    if (s->coalesced_mmio_ring) {
        struct kvm_coalesced_mmio_ring *ring = s->coalesced_mmio_ring;
        while (ring->first != ring->last) {
            struct kvm_coalesced_mmio *ent;

            ent = &ring->coalesced_mmio[ring->first];

            if (ent->pio == 1) {
                address_space_write(&address_space_io, ent->phys_addr,
                                    MEMTXATTRS_UNSPECIFIED, ent->data,
                                    ent->len);
            } else {
                cpu_physical_memory_write(ent->phys_addr, ent->data, ent->len);
            }
            smp_wmb();
            ring->first = (ring->first + 1) % KVM_COALESCED_MMIO_MAX;
        }
    }

    s->coalesced_flush_in_progress = false;
}

bool kvm_cpu_check_are_resettable(void)
{
    return kvm_arch_cpu_check_are_resettable();
}

static void do_kvm_cpu_synchronize_state(CPUState *cpu, run_on_cpu_data arg)
{
    if (!cpu->vcpu_dirty) {
        kvm_arch_get_registers(cpu);
        cpu->vcpu_dirty = true;
    }
}

void kvm_cpu_synchronize_state(CPUState *cpu)
{
    if (!cpu->vcpu_dirty) {
        run_on_cpu(cpu, do_kvm_cpu_synchronize_state, RUN_ON_CPU_NULL);
    }
}

static void do_kvm_cpu_synchronize_post_reset(CPUState *cpu, run_on_cpu_data arg)
{
    kvm_arch_put_registers(cpu, KVM_PUT_RESET_STATE);
    cpu->vcpu_dirty = false;
}

void kvm_cpu_synchronize_post_reset(CPUState *cpu)
{
    run_on_cpu(cpu, do_kvm_cpu_synchronize_post_reset, RUN_ON_CPU_NULL);
}

static void do_kvm_cpu_synchronize_post_init(CPUState *cpu, run_on_cpu_data arg)
{
    kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
    cpu->vcpu_dirty = false;
}

void kvm_cpu_synchronize_post_init(CPUState *cpu)
{
    run_on_cpu(cpu, do_kvm_cpu_synchronize_post_init, RUN_ON_CPU_NULL);
}

static void do_kvm_cpu_synchronize_pre_loadvm(CPUState *cpu, run_on_cpu_data arg)
{
    cpu->vcpu_dirty = true;
}

void kvm_cpu_synchronize_pre_loadvm(CPUState *cpu)
{
    run_on_cpu(cpu, do_kvm_cpu_synchronize_pre_loadvm, RUN_ON_CPU_NULL);
}

#ifdef KVM_HAVE_MCE_INJECTION
static __thread void *pending_sigbus_addr;
static __thread int pending_sigbus_code;
static __thread bool have_sigbus_pending;
#endif

static void kvm_cpu_kick(CPUState *cpu)
{
    qatomic_set(&cpu->kvm_run->immediate_exit, 1);
}

static void kvm_cpu_kick_self(void)
{
    if (kvm_immediate_exit) {
        kvm_cpu_kick(current_cpu);
    } else {
        qemu_cpu_kick_self();
    }
}

static void kvm_eat_signals(CPUState *cpu)
{
    struct timespec ts = { 0, 0 };
    siginfo_t siginfo;
    sigset_t waitset;
    sigset_t chkset;
    int r;

    if (kvm_immediate_exit) {
        qatomic_set(&cpu->kvm_run->immediate_exit, 0);
        /* Write kvm_run->immediate_exit before the cpu->exit_request
         * write in kvm_cpu_exec.
         */
        smp_wmb();
        return;
    }

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);

    do {
        r = sigtimedwait(&waitset, &siginfo, &ts);
        if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
            perror("sigtimedwait");
            exit(1);
        }

        r = sigpending(&chkset);
        if (r == -1) {
            perror("sigpending");
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI));
}

//TODO: add bounds checking to memory copies?

/**
 * Called must hold hyperupcalls lock.
 * @return: slot number on success, -1 on failure.
*/
static int allocate_hyperupcall_slot(void) {
    int slot = -1;
    for (int i = 0; i < MAX_NUM_HYPERUPCALL_OBJS; i++) {
        if (hyperupcalls[i].obj == NULL) {
            slot = i;
            break;
        }
    }
    return slot;
}

/**
 * Called must hold hyperupcalls lock.
 * @return: slot number on success, -1 on failure.
*/
static int allocate_hyperupcall_map_slot(void) {
    int slot = -1;
    for (int i = 0; i < HYPERUPCALL_N_MAP_SLOTS; i++) {
        if (hyperupcalls->maps[i] == NULL) {
            slot = i;
            break;
        }
    }
    return slot;
}

/**
 * Called must hold hyperupcalls lock.
 * @return: 0 on success, -1 on failure.
*/
static int free_hyperupcall_map_slot(int slot) {
    if (slot >= HYPERUPCALL_N_MAP_SLOTS) {
        fprintf(stderr, "Invalid hyperupcall map slot: %d\n", slot);
        return -1;
    }
    if (hyperupcalls->maps[slot] == NULL) {
        fprintf(stderr, "Hyperupcall map slot is already free: %d\n", slot);
        return -1;
    }
    hyperupcalls->maps[slot] = NULL;
    hyperupcalls->mmaped_map_ptrs[slot] = NULL;
    return 0;
}

static int allocate_hyperupcall_prog_slot(struct HyperUpCall *hyperupcall) {
    int slot = -1;
    for (int i = 0; i < HYPERUPCALL_N_PROGRAM_SLOTS; i++) {
        if (hyperupcalls->progs[i] == NULL) {
            slot = i;
            break;
        }
    }
    return slot;
}


/**
 * Loads hyperupcall from guest to host. Currently only supports one program.
 * Called must hold the hyperupcall Lock
 * TODO: Add support for multiple programs.
 *
 * @cpu: CPUState
 * @attrs: MemTxAttrs
 * @program_ptr_arr: Physical address of array of physical addresses to pages containing the program
 * @program_len: Length of program in bytes
 * @returns: hyperupcall index on success, -1 on failure.
 */
static int load_hyperupcall(CPUState *cpu, MemTxAttrs attrs, unsigned long program_ptr_arr, unsigned long program_len) {
    int hyperupcall_slot;
    struct bpf_object *obj;
    char *binary;
    hwaddr binary_gptrs[PAGE_SIZE / sizeof(hwaddr)];
    int r, program_pages = DIV_ROUND_UP(program_len, PAGE_SIZE);
    MemTxResult mtr;

    hyperupcall_slot = allocate_hyperupcall_slot();
    if (hyperupcall_slot < 0) {
        fprintf(stderr, "No free hyperupcall slots\n");
        return -1;
    }

    binary = g_try_malloc0(ROUND_UP(program_len, PAGE_SIZE));
    if (binary < 0) {
        fprintf(stderr, "g_malloc0 failed\n");
        return -1;
    }

    mtr = address_space_read(cpu->as, program_ptr_arr, MEMTXATTRS_UNSPECIFIED, binary_gptrs, program_pages * sizeof(hwaddr));
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "address_space_rw failed %d\n", mtr);
        g_free(binary);
        return -1;
    }

    for (int i = 0; i < program_pages; i++) {
        mtr = address_space_read(cpu->as, binary_gptrs[i], attrs, binary + (i*PAGE_SIZE), PAGE_SIZE);
        if (mtr != MEMTX_OK) {
            fprintf(stderr, "address_space_rw failed %d\n", mtr);
            g_free(binary);
            return -1;
        }
        fprintf(stderr, "binary[%d]: %p\n", i, binary + (i*PAGE_SIZE));
    }


    obj = bpf_object__open_mem(binary, program_len, NULL);
    if (obj == NULL) {
		fprintf(stderr, "Failed to open BPF object file '%lu'\n", program_len);
        g_free(binary);
		return -1;
	}

	r = bpf_object__load(obj);
	if (r < 0) {
		fprintf(stderr, "Failed to load BPF object file \n");
        bpf_object__close(obj);
        g_free(binary);
		return -1;
	}

    hyperupcalls[hyperupcall_slot].obj = obj;
    g_free(binary);
    return hyperupcall_slot;
}

static int export_memslots_hyperupcall(struct bpf_object *obj) {
    int memslots_base_gfns_fd, memslots_npages_fd, memslots_userptrs_fd;
    unsigned long long *memslot_base_gfns, *memslot_npages, *memslot_userptrs; 
    struct bpf_map* memslot_base_gfns_map, *memslot_npages_map, *memslot_userptrs_map;

    memslot_base_gfns_map = bpf_object__find_map_by_name(obj, "l0_memslots_base_gfns");
    memslot_npages_map = bpf_object__find_map_by_name(obj, "l0_memslots_npages");
    memslot_userptrs_map = bpf_object__find_map_by_name(obj, "l0_memslots_userspace_addr");

    memslots_base_gfns_fd = bpf_map__fd(memslot_base_gfns_map);
    memslots_npages_fd = bpf_map__fd(memslot_npages_map);
    memslots_userptrs_fd = bpf_map__fd(memslot_userptrs_map);

    if (memslots_base_gfns_fd < 0 || memslots_npages_fd < 0 || memslots_userptrs_fd < 0) {
        if (memslots_base_gfns_fd >= 0) close(memslots_base_gfns_fd);
        if (memslots_npages_fd >= 0) close(memslots_npages_fd);
        if (memslots_userptrs_fd >= 0) close(memslots_userptrs_fd);
        fprintf(stderr, "Failed to get memslots fds\n");
        return -1;
    }

    memslot_base_gfns = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, memslots_base_gfns_fd, 0);
    memslot_npages = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, memslots_npages_fd, 0);
    memslot_userptrs = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, memslots_userptrs_fd, 0);

    if (memslot_base_gfns == MAP_FAILED || memslot_npages == MAP_FAILED || memslot_userptrs == MAP_FAILED) {
        fprintf(stderr, "export_memslots_hyperupcall failed\n");
        if (memslot_base_gfns != MAP_FAILED) munmap(memslot_base_gfns, 4096);
        if (memslot_npages != MAP_FAILED) munmap(memslot_npages, 4096);
        if (memslot_userptrs != MAP_FAILED) munmap(memslot_userptrs, 4096);
        return -1;
    }

    for (int i = 0; i < used_memslots; i++) {
        memslot_base_gfns[i] = memslot_base_gfns_local[i];
        memslot_npages[i] = memslot_npages_local[i];
        memslot_userptrs[i] = memslot_userptrs_local[i];
    }

    munmap(memslot_base_gfns, 4096);
    munmap(memslot_npages, 4096);
    munmap(memslot_userptrs, 4096);
    close(memslots_base_gfns_fd);
    close(memslots_npages_fd);
    close(memslots_userptrs_fd);
    return 0;
}

static int set_perf_event(unsigned long sample_freq) {
    int fd;
    struct perf_event_attr attr = {0};

    attr.type = PERF_TYPE_SOFTWARE;
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.size = sizeof(attr);
    attr.freq = 1;
    attr.sample_freq = sample_freq;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.mmap = 1;
    attr.comm = 1;
    attr.task = 1;
    attr.sample_id_all = 1;
    attr.exclude_host = 1;
    attr.mmap2 = 1;
    
    fd = syscall(SYS_perf_event_open, &attr, -1, 5, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        perror("Failed to open perf event");
        return -1;
    }
    return fd;
}

static int guest_netindex_to_ifindex(unsigned int guest_netindex) {
    char ifname[128];
    int ifindex;
    NetClientState *nc = qemu_find_netdev_via_index(guest_netindex);

    if (nc->info->type != NET_CLIENT_DRIVER_TAP) 
        return -1;

    tap_fd_get_ifname(tap_get_fd(nc), ifname);
    ifindex = if_nametoindex(ifname);
    return ifindex;
}


/**
 * Create vdpa interface and hotplug it into the vm
 *
 */


enum VDPA_CMD {
    VDPA_INVALID = 0,
    VDPA_CREATE = 1,
    VDPA_DESTOY = 2,
};

static int create_vdpa_and_hotplug(CPUState *cpu, MemTxAttrs attrs, unsigned int cmd, unsigned int interface_id) {
    Monitor* mon = monitor_cur();
    if (cmd == VDPA_DESTOY) {
        const char* id_template = "Nvdpa-n";
        char* id  = malloc(8);

        strncpy(id, id_template, 8);
        id[6] = interface_id + '0';
        NetClientState* dev = qemu_find_dev(id);

        if (dev == NULL) {
            fprintf(stderr, "netdev with id %s does not exists. Aborting.", id);
            return -1;
        }

        Error *err = NULL;
        QDict *dev_qdict;

        dev_qdict = qdict_new();
        if (dev_qdict == NULL) {
            fprintf(stderr, "qdict_new failed\n");
            return -1;
        }
        qdict_put_str(dev_qdict, "driver", "virtio-net-pci");
        qdict_put_str(dev_qdict, "id", id);
        qdict_put_str(dev_qdict, "bus", "root");
        qemu_mutex_lock_iothread();

        hmp_device_del(mon, dev_qdict);
        if (err != NULL) {
            fprintf(stderr, "qmp_device_add failed\n");
            error_report_err(err);
            qemu_mutex_unlock_iothread();
            return -1;
        }
        qemu_mutex_unlock_iothread();
        dev = qemu_find_dev(id+sizeof(char));
        qemu_del_net_client(dev);

    } else if (cmd == VDPA_CREATE) {
        // create vhost net
        Netdev object = {0};
        object.type = NET_CLIENT_DRIVER_VHOST_VDPA;

        object.id = malloc(8);
        char str[7] = "vdpa-n";
        str[5] = interface_id + '0';
        strncpy(object.id+sizeof(char), str, 7);
        object.id[0] = 'N';
        vdpa_create(interface_id);

        const char* dev_path = "/dev/vhost-vdpa-0";

        object.u.vhost_vdpa.vhostdev= malloc(18);
        strncpy(object.u.vhost_vdpa.vhostdev, dev_path, 17);
        object.u.vhost_vdpa.vhostdev[16] = interface_id + '0';
        object.u.vhost_vdpa.vhostdev[17] = 0;


        if (access(object.u.vhost_vdpa.vhostdev, F_OK) != 0) {
            fprintf(stderr, "device %s does not exist on hypervisor\n", object.u.vhost_vdpa.vhostdev);
            return -1;
        }
        object.u.vhost_vdpa.has_vhostdev = true;
        object.u.vhost_vdpa.has_vhostfd = false;

        NetClientState *peer = peer = net_hub_add_port(0, NULL, NULL);
        if(qemu_find_netdev(object.id) != NULL) {
            fprintf(stderr, "netdev with id %s already exists. Aborting.", object.id);
            return -1;
        }
        Error *err = NULL;
        net_init_vhost_vdpa(&object, str, peer, &err);
        if(err != NULL) {
            error_printf("failed to initialize vhost vda device: %s\n", err->msg);
        }

        // hotplug into vm
    QDict *dev_qdict;

    dev_qdict = qdict_new();
    if (dev_qdict == NULL) {
        fprintf(stderr, "qdict_new failed\n");
        return -1;
    }
    qdict_put_str(dev_qdict, "driver", "virtio-net-pci");
    qdict_put_str(dev_qdict, "id", object.id);
    qdict_put_str(dev_qdict, "bus", "root/br");
   // qdict_put_str(dev_qdict, "type", "vhost-vdpa");
    qemu_mutex_lock_iothread();
        // hmp_netdev_add(mon, dev_qdict);
    qmp_device_add(dev_qdict, NULL, &err);
    if (err != NULL) {
        fprintf(stderr, "qmp_device_add failed\n");
        error_report_err(err);
        qemu_mutex_unlock_iothread();
        return -1;
    }
    qemu_mutex_unlock_iothread();
    } else {
        fprintf(stderr, "Invalid vdpa command\n");
        return -1;
    }
    return 0;
}


/**
 * Attaches and links hyperupcall to hook.
 * 
 * @cpu: CPUState
 * @attrs: MemTxAttrs
 * @hyperupcall_slot: hyperupcall slot that containers the hyperupcall object.
 * @prog_name: physical address of buffer that containers the name of program to attach.
 * @major_id: major ID of hook to attach.
 * @minor_id: minor ID of hook to attach.
 * @return hyperupcall program slot on success, -1 on failure.
*/
static int link_hyperupcall(CPUState *cpu, MemTxAttrs attrs, unsigned int hyperupcall_slot, char *guest_prog_name, unsigned long major_id, unsigned long minor_id) {
    int program_slot, perf_fd, r = 0;
    char prog_name[HYPERUPCALL_PROG_NAME_LEN];
    struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL;
    struct bpf_object *obj;
    // struct bpf_tc_hook tc_hook = {0};
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex =
			    guest_netindex_to_ifindex(minor_id), .attach_point = BPF_TC_EGRESS);
    LIBBPF_OPTS(bpf_tc_opts, tc_optl);
    tc_optl.priority = 1;
    tc_optl.handle = 1;
    MemTxResult mtr;

    if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
        fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
        return -1;
    }
    obj = hyperupcalls[hyperupcall_slot].obj;
    
    mtr = address_space_read(cpu->as, (hwaddr)guest_prog_name, MEMTXATTRS_UNSPECIFIED, prog_name, HYPERUPCALL_PROG_NAME_LEN);
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "Couldn't read hyperupcall program name via address_space_read %d\n", mtr);
        return -1;
    }
    prog_name[HYPERUPCALL_PROG_NAME_LEN - 1] = '\0';

    program_slot = allocate_hyperupcall_prog_slot(&hyperupcalls[hyperupcall_slot]);
    if (program_slot < 0) {
        fprintf(stderr, "No free hyperupcall program slots\n");
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, prog_name);
	if (prog == NULL) {
		fprintf(stderr, "Failed to find BPF program in file\n");
		return -1;
	}

    switch(major_id) {
        case HYPERUPCALL_MAJORID_XDP:
            link = bpf_program__attach_xdp(prog, guest_netindex_to_ifindex(minor_id));
            if (link == NULL) {
                fprintf(stderr, "Failed to attach BPF XDP prog\n");
                return -1;
            }
            break;
        case HYPERUPCALL_MAJORID_PAGEFAULT:
            if (minor_id == 0) {
                link = bpf_program__attach_kprobe(prog, true, "alloc_bypass");
                export_memslots_hyperupcall(obj);
            }
            else if (minor_id == 1)
                link = bpf_program__attach_kprobe(prog, true, "update_mapping");
            else
                link = NULL;
            if (link == NULL) {
                fprintf(stderr, "Failed to attach BPF prog M: %lu m: %lu \n", major_id, minor_id);
                return -1;
            }
            break;
        case HYPERUPCALL_MAJORID_TC_INGRESS:
            tc_hook.attach_point = BPF_TC_INGRESS;
            // fall through
        case HYPERUPCALL_MAJORID_TC_EGRESS:
            // tc_hook = (struct bpf_tc_hook){
            //     .sz = sizeof(tc_hook),
            //     .ifindex = minor_id,
            //     .attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS,
            //     .parent = 1,
            // };
            r = bpf_tc_hook_create(&tc_hook);
            if (r < 0) {
                fprintf(stderr, "Failed to create BPF TC hook\n");
                return -1;
            }
            
            tc_optl.prog_fd = bpf_program__fd(prog);
            tc_optl.flags = BPF_TC_F_REPLACE;
            r = bpf_tc_attach(&tc_hook, &tc_optl);
            if (r < 0) {
                fprintf(stderr, "Failed to attach BPF TC prog\n");
                bpf_tc_hook_destroy(&tc_hook);
                return -1;
            }
            break;
        case HYPERUPCALL_MAJORID_DIRECT_EXE:
            if (minor_id == 0) {
                link = bpf_program__attach_kprobe(prog, true, "sched_direct_exe");
            }
            if (link == NULL) {
                fprintf(stderr, "Failed to attach BPF prog M: %lu m: %lu \n", major_id, minor_id);
                return -1;
            }
            break;
       case HYPERUPCALL_MAJORID_PROFILING:
           perf_fd = set_perf_event(minor_id);
           if (perf_fd < 0) {
               fprintf(stderr, "Failed to set perf event");
               return -1;
           }
           link = bpf_program__attach_perf_event(prog, perf_fd);
           if (link == NULL) {
               close(perf_fd);
               perror("Failed to attach perf event");
               return -1;
           }

           if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
               close(perf_fd);
               bpf_link__destroy(link);
               perror("Failed to enable perf event");
               return -1;
           }
           break;

        default:
            fprintf(stderr, "Invalid major id: %lu\n", major_id);
            return -1;
    }

    hyperupcalls[hyperupcall_slot].links[program_slot] = link;
    hyperupcalls[hyperupcall_slot].hooks[program_slot] = tc_hook;
    hyperupcalls[hyperupcall_slot].progs[program_slot] = prog;
    hyperupcalls[hyperupcall_slot].major_ids[program_slot] = major_id;
    hyperupcalls[hyperupcall_slot].minor_ids[program_slot] = minor_id;
    return program_slot;
}


/**
 * Unlinks hyperupcall link from hook.
*/
static int unlink_hyperupcall(CPUState *cpu, unsigned int hyperupcall_slot, unsigned int program_slot) {
    int r = 0;
    LIBBPF_OPTS(bpf_tc_opts, tc_optl);
    tc_optl.handle = 1;
    tc_optl.priority = 1;

    if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
        fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
        return -1;
    }

    if (program_slot >= HYPERUPCALL_N_PROGRAM_SLOTS || hyperupcalls[hyperupcall_slot].progs[program_slot] == NULL) {
        fprintf(stderr, "Invalid program slot: %d\n", program_slot);
        return -1;
    }

    if (hyperupcalls[hyperupcall_slot].links[program_slot] != NULL) {
	    bpf_link__destroy(hyperupcalls[hyperupcall_slot].links[program_slot]);
        fprintf(stderr, "Link destroyed\n");
    }
    else if (hyperupcalls[hyperupcall_slot].hooks[program_slot].sz != 0) {
        r = bpf_tc_detach(&hyperupcalls[hyperupcall_slot].hooks[program_slot], &tc_optl);
        if (r < 0) {
            fprintf(stderr, "Failed to detach BPF TC prog %s\n", strerror(r));
            return -1;
        }
        r = bpf_tc_hook_destroy(&hyperupcalls[hyperupcall_slot].hooks[program_slot]);
        if (r < 0) {
            fprintf(stderr, "Failed to destroy BPF TC hook %s\n", strerror(r));
            return -1;
        }
        fprintf(stderr, "Hook destroyed\n");
    }
    else {
        fprintf(stderr, "Error! No link or hook exist for these indices!\n");
        return -1;
    }

    hyperupcalls[hyperupcall_slot].links[program_slot] = NULL;
    hyperupcalls[hyperupcall_slot].hooks[program_slot] = (struct bpf_tc_hook){0};
    hyperupcalls[hyperupcall_slot].progs[program_slot] = NULL;
    hyperupcalls[hyperupcall_slot].major_ids[program_slot] = -1;
    hyperupcalls[hyperupcall_slot].minor_ids[program_slot] = -1;
    return 0;
}


/**
 * Maps an eBPF map from a hyperupcall to memory pointed by map_ptr.
 * TODO: fix memory leak
 * 
 * @cpu: CPUState
 * @attrs: MemTxAttrs
 * @hyperupcall_slot: hyperupcall slot that containers the hyperupcall object.
 * @map_name: physical address of buffer that containers the name of map to attach.
 * @map_ptr: physical address of physically contigous buffer that the eBPF map will be mapped to.
*/
static int map_hyperupcall_map(CPUState *cpu, MemTxAttrs attrs, unsigned int hyperupcall_slot, char *map_name_guest) {
    Error *err = NULL;
    void *mmapped_map;
    int map_slot;
    MemTxResult mtr;
    Object *obj;
    char mmaped_map_str[32];
    char mmaped_map_size[32];
    char map_name[HYPERUPCALL_PROG_NAME_LEN];

    if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
        fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
        return -1;
    }

    map_slot = allocate_hyperupcall_map_slot();
    if (map_slot == -1) {
        fprintf(stderr, "No free hyperupcall map slots\n");
        return -1;
    }

    mtr = address_space_read(cpu->as, (hwaddr)map_name_guest, MEMTXATTRS_UNSPECIFIED, map_name, HYPERUPCALL_PROG_NAME_LEN);
    if (mtr != MEMTX_OK) {
        fprintf(stderr, "Couldn't read hyperupcall map name via address_space_read %d\n", mtr);
        return -1;
    }
    map_name[HYPERUPCALL_PROG_NAME_LEN - 1] = '\0';

    struct bpf_map *map = bpf_object__find_map_by_name(hyperupcalls[hyperupcall_slot].obj, map_name);
    if (map == NULL) {
        fprintf(stderr, "Map not found: %s\n", map_name);
        return -1;
    }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor\n");
        return -1;
    }

    mmapped_map = mmap(NULL, bpf_map__max_entries(map)*bpf_map__value_size(map), PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (mmapped_map == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap ebpf map\n");
        return -1;
	}

    /* Create object */
    // Might need to add this to memfd: memory_region_init_ram_device_ptr(...)
    sprintf(mmaped_map_str, "%p", mmapped_map);
    sprintf(mmaped_map_size, "%d", (int)ROUND_UP(bpf_map__max_entries(map)*bpf_map__value_size(map), PAGE_SIZE));
    fprintf(stderr, "mmapped_map size: %s\n", mmaped_map_size);
    obj = object_new_with_props("memory-backend-memfd", object_get_objects_root(), memory_backend_names[map_slot], &err,
        "size", mmaped_map_size,
        "share", "true",
        "prealloc", "true",
        "user-ptr", mmaped_map_str,
        NULL);

    if (obj == NULL) {
        fprintf(stderr, "object_new_with_props failed\n");
        error_report_err(err);
        munmap(mmapped_map, bpf_map__max_entries(map)*bpf_map__value_size(map));
        return -1;
    }

    QDict *dev_qdict;

    dev_qdict = qdict_new();
    if (dev_qdict == NULL) {
        fprintf(stderr, "qdict_new failed\n");
        munmap(mmapped_map, bpf_map__max_entries(map)*bpf_map__value_size(map));
        return -1;
    }
    qdict_put_str(dev_qdict, "driver", "ivshmem-plain");
    qdict_put_str(dev_qdict, "bus", memory_backend_ids[map_slot]);
    qdict_put_str(dev_qdict, "memdev", memory_backend_names[map_slot]);
    qdict_put_str(dev_qdict, "id", memory_devices_names[map_slot]);
    qemu_mutex_lock_iothread();
    
    qmp_device_add(dev_qdict, NULL, &err);
    if (err != NULL) {
        fprintf(stderr, "qmp_device_add failed\n");
        error_report_err(err);
        munmap(mmapped_map, bpf_map__max_entries(map)*bpf_map__value_size(map));
        qemu_mutex_unlock_iothread();
        return -1;
    }
    qemu_mutex_unlock_iothread();
    hyperupcalls[hyperupcall_slot].mmaped_map_ptrs[map_slot] = mmapped_map;
    hyperupcalls[hyperupcall_slot].maps[map_slot] = map;
    fprintf(stderr, "added device\n");   
    return map_slot;
}

static int unmap_hyperupcall_map_th(int hyperupcall_slot, int map_slot) {
    int map_size;
    Object *obj;
    Error *err = NULL;
    DeviceState *dev;
    if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
        fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
        return -1;
    }

    if (map_slot >= HYPERUPCALL_N_MAP_SLOTS || hyperupcalls[hyperupcall_slot].maps[map_slot] == NULL) {
        fprintf(stderr, "Invalid map slot: %d\n", map_slot);
        return -1;
    }

    obj = object_resolve_path_at(container_get(qdev_get_machine(), "/peripheral"), memory_devices_names[map_slot]);
    dev = (DeviceState *)object_dynamic_cast(obj, TYPE_DEVICE);
    qdev_unplug(dev, &err);
    if (err != NULL) {
        fprintf(stderr, "qmp_device_del failed\n");
        error_report_err(err);
        return -1;
    }

    memory_backend_bh = memory_backend_names[map_slot];

    map_size = bpf_map__max_entries(hyperupcalls[hyperupcall_slot].maps[map_slot]) * bpf_map__value_size(hyperupcalls[hyperupcall_slot].maps[map_slot]);
    if (munmap(hyperupcalls[hyperupcall_slot].mmaped_map_ptrs[map_slot], map_size) < 0) {
        fprintf(stderr, "munmap failed\n");
        return -1;
    }
    free_hyperupcall_map_slot(map_slot);
    return 0;
}



/**
 * Unload hyperupcall from host. Unlinks all of its links.
 * Called should hold the hyperupcall Lock
 * 
*/
static int unload_hyperupcall(CPUState *cpu, unsigned int hyperupcall_slot) { 
    if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
        fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
        return -1;
    }

    for (int i = 0; i < HYPERUPCALL_N_PROGRAM_SLOTS; i++) {
        if (hyperupcalls[hyperupcall_slot].links[i] != NULL) {
            unlink_hyperupcall(cpu, hyperupcall_slot, i);
        }
    }

    for (int i = 0; i < HYPERUPCALL_N_MAP_SLOTS; i++) {
        unmap_hyperupcall_map_th(hyperupcall_slot, i);
    }

    bpf_object__close(hyperupcalls[hyperupcall_slot].obj);

    hyperupcalls[hyperupcall_slot].obj = NULL;
    return 0;
}


struct map_update_attr {
    char map_name[512];
    unsigned int key;
    size_t value_size;
    bool is_set;
    char value[0];
};


static int hyperupcall_map_elem_get_set(CPUState *cpu, unsigned int hyperupcall_slot, struct map_update_attr *usr_attr) {
    return -1;
    // TODO: fix implementation
    
    // struct bpf_map* map;
    // struct map_update_attr attr;
    // MemTxResult mtr;

    // int ret = 0;
    // if (hyperupcall_slot >= MAX_NUM_HYPERUPCALL_OBJS || hyperupcalls[hyperupcall_slot].obj == NULL) {
    //     fprintf(stderr, "Invalid hyperupcall slot: %d\n", hyperupcall_slot);
    //     return -1;
    // }

    // mtr = address_space_read(cpu->as, (hwaddr)usr_attr, MEMTXATTRS_UNSPECIFIED, &attr, sizeof(attr));
    // if (mtr != MEMTX_OK) {
    //     fprintf(stderr, "Couldn't read hyperupcall update attributes via address_space_read %d\n", mtr);
    //     return -1;
    // }

    // map = bpf_object__find_map_by_name(hyperupcalls[hyperupcall_slot].obj, attr.map_name);
    // if (!map) {
    //     fprintf(stderr, "Failed to find map 'packets'\n");
    //     return -1;
    // }

    // //read value
    // void *value = g_try_malloc0(attr.value_size);
    // if (value < 0) {
    //     fprintf(stderr, "g_malloc0 failed\n");
    //     return -1;
    // }

    // if (!attr.is_set) {
    //     ret = bpf_map__lookup_elem(map, &attr.key, sizeof(attr.key), &attr.value, attr.value_size, 0);
    //     if (ret < 0)
    //         return ret;
        
    //     fprintf(stderr, "key: %u, value: %llu\n", attr.key, *(unsigned long long *)value);
    //     mtr = address_space_write(cpu->as, (hwaddr)(usr_attr + 1), MEMTXATTRS_UNSPECIFIED, value, attr.value_size);
    //     if (mtr != MEMTX_OK) {
    //         fprintf(stderr, "Couldn't write hyperupcall map value via address_space_write %d\n", mtr);
    //         ret = -1;
    //     }

    //     g_free(value);
    //     return ret;
    // }

    // mtr = address_space_read(cpu->as, (hwaddr)attr.value, MEMTXATTRS_UNSPECIFIED, value, attr.value_size);
    // if (mtr != MEMTX_OK) {
    //     fprintf(stderr, "Couldn't read hyperupcall map value via address_space_read %d\n", mtr);
    //     g_free(value);
    //     return -1;
    // }

    // ret = bpf_map__update_elem(map, &attr.key, sizeof(attr.key), &attr.value, attr.value_size, 0);
    // g_free(value);
    // return ret;
}


/*
 * handle_hypercall - dispatch a KVM_EXIT_HYPERCALL to the appropriate handler.
 *
 * @is_nested: non-zero when the vmcall originated from an L2 guest (set by
 *             x86.c via args[4] = is_guest_mode(vcpu)).  When set, calls are
 *             forwarded through the L2 proxy to L0 rather than handled locally.
 */
static int handle_hypercall(CPUState *cpu, MemTxAttrs attrs,
                             unsigned long nr,
                             unsigned long a0, unsigned long a1,
                             unsigned long a2, unsigned long a3,
                             unsigned long is_nested) {
    int ret;
    Error *err = NULL;
    fprintf(stderr, "got hypercall nr %lu; args: %lu %lu %lu %lu (nested=%lu)\n",
            nr, a0, a1, a2, a3, is_nested);

    /*
     * L2 nested-guest hyperupcalls: proxy the call up to L0 QEMU via an
     * inline vmcall from within L1's address space.
     */
    if (is_nested && nr >= 13 && nr <= 19) {
        return (int)handle_l2_hypercall(cpu, attrs, nr, a0, a1, a2, a3);
    }

    if (memory_backend_bh != NULL) {
        qemu_mutex_lock_iothread();
        if (user_creatable_del(memory_backend_bh, &err))
            memory_backend_bh = NULL;
        qemu_mutex_unlock_iothread();
    }
    if (memory_backend_bh != NULL) {
        fprintf(stderr, "failed to delete memory_backend object: %s\n", memory_backend_bh);
        error_report_err(err);
    }
    
    switch(nr) {
        case 13:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = load_hyperupcall(cpu, attrs, a0, a1);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 14:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = unload_hyperupcall(cpu, a0);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 15:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = link_hyperupcall(cpu, attrs, a0, (char *)a1, a2, a3);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 16:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = unlink_hyperupcall(cpu, a0, a1);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 17:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = map_hyperupcall_map(cpu, attrs, a0, (char *)a1);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 18:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = unmap_hyperupcall_map_th(a0, a1);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;
        case 19:
            if (pthread_mutex_lock(&hyperupcalls_lock) != 0) {
                fprintf(stderr, "pthread_mutex_lock failed\n");
                return -1;
            }
            ret = hyperupcall_map_elem_get_set(cpu, a0, (struct map_update_attr *)a1);
            pthread_mutex_unlock(&hyperupcalls_lock);
            break;

        /*
         * Create vDPA interface and hotplug
         */
        case 23:
            ret = create_vdpa_and_hotplug(cpu, attrs, a0, a1);
            return 0;
            break;
        default:
            fprintf(stderr, "unknown hypercall number: %lu\n", nr);
            ret = 0;
            break;
    }
    return ret;
}


int kvm_cpu_exec(CPUState *cpu)
{
    struct kvm_run *run = cpu->kvm_run;
    int ret = 0, run_ret;
    static int was_hyperupcall_init = 0;

    DPRINTF("kvm_cpu_exec()\n");
    
    if (was_hyperupcall_init == 0 && cpu->cpu_index == 0) {
        memset(hyperupcalls, 0, sizeof(hyperupcalls));
        ret = pthread_mutex_init(&hyperupcalls_lock, NULL);
    }
    if (was_hyperupcall_init == 0 && ret == 0) {
        was_hyperupcall_init = 1;
        fprintf(stderr, "\n Initialize hyperupcall lock \n"); 
    }
    else if (was_hyperupcall_init == 0) {
        fprintf(stderr, "\n Couldn't initialize hyperupcall lock \n"); 
        was_hyperupcall_init = -1;
    }
    ret = 0;

    if (kvm_arch_process_async_events(cpu)) {
        qatomic_set(&cpu->exit_request, 0);
        return EXCP_HLT;
    }

    qemu_mutex_unlock_iothread();
    cpu_exec_start(cpu);

    do {
        MemTxAttrs attrs;

        if (cpu->vcpu_dirty) {
            kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
            cpu->vcpu_dirty = false;
        }

        kvm_arch_pre_run(cpu, run);
        if (qatomic_read(&cpu->exit_request)) {
            DPRINTF("interrupt exit requested\n");
            /*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
            kvm_cpu_kick_self();
        }

        /* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
        smp_rmb();

        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);

        attrs = kvm_arch_post_run(cpu, run);

#ifdef KVM_HAVE_MCE_INJECTION
        if (unlikely(have_sigbus_pending)) {
            qemu_mutex_lock_iothread();
            kvm_arch_on_sigbus_vcpu(cpu, pending_sigbus_code,
                                    pending_sigbus_addr);
            have_sigbus_pending = false;
            qemu_mutex_unlock_iothread();
        }
#endif

        if (run_ret < 0) {
            if (run_ret == -EINTR || run_ret == -EAGAIN) {
                DPRINTF("io window exit\n");
                kvm_eat_signals(cpu);
                ret = EXCP_INTERRUPT;
                break;
            }
            fprintf(stderr, "error: kvm run failed %s\n",
                    strerror(-run_ret));
#ifdef TARGET_PPC
            if (run_ret == -EBUSY) {
                fprintf(stderr,
                        "This is probably because your SMT is enabled.\n"
                        "VCPU can only run on primary threads with all "
                        "secondary threads offline.\n");
            }
#endif
            ret = -1;
            break;
        }

        trace_kvm_run_exit(cpu->cpu_index, run->exit_reason);
        switch (run->exit_reason) {
        case KVM_EXIT_HYPERCALL:
            run->hypercall.ret = handle_hypercall(
                cpu, attrs,
                run->hypercall.nr,
                run->hypercall.args[0],
                run->hypercall.args[1],
                run->hypercall.args[2],
                run->hypercall.args[3],
                run->hypercall.args[4]   /* is_nested: set by x86.c */
            );
            ret = 0;
            break;
        case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
            /* Called outside BQL */
            kvm_handle_io(run->io.port, attrs,
                          (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                          run->io.size,
                          run->io.count);
            ret = 0;
            break;
        case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
            /* Called outside BQL */
            address_space_rw(&address_space_memory,
                             run->mmio.phys_addr, attrs,
                             run->mmio.data,
                             run->mmio.len,
                             run->mmio.is_write);
            ret = 0;
            break;
        case KVM_EXIT_IRQ_WINDOW_OPEN:
            DPRINTF("irq_window_open\n");
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_SHUTDOWN:
            DPRINTF("shutdown\n");
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_UNKNOWN:
            fprintf(stderr, "KVM: unknown exit, hardware reason %" PRIx64 "\n",
                    (uint64_t)run->hw.hardware_exit_reason);
            ret = -1;
            break;
        case KVM_EXIT_INTERNAL_ERROR:
            ret = kvm_handle_internal_error(cpu, run);
            break;
        case KVM_EXIT_DIRTY_RING_FULL:
            /*
             * We shouldn't continue if the dirty ring of this vcpu is
             * still full.  Got kicked by KVM_RESET_DIRTY_RINGS.
             */
            trace_kvm_dirty_ring_full(cpu->cpu_index);
            qemu_mutex_lock_iothread();
            /*
             * We throttle vCPU by making it sleep once it exit from kernel
             * due to dirty ring full. In the dirtylimit scenario, reaping
             * all vCPUs after a single vCPU dirty ring get full result in
             * the miss of sleep, so just reap the ring-fulled vCPU.
             */
            if (dirtylimit_in_service()) {
                kvm_dirty_ring_reap(kvm_state, cpu);
            } else {
                kvm_dirty_ring_reap(kvm_state, NULL);
            }
            qemu_mutex_unlock_iothread();
            dirtylimit_vcpu_execute(cpu);
            ret = 0;
            break;
        case KVM_EXIT_SYSTEM_EVENT:
            switch (run->system_event.type) {
            case KVM_SYSTEM_EVENT_SHUTDOWN:
                qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
                ret = EXCP_INTERRUPT;
                break;
            case KVM_SYSTEM_EVENT_RESET:
                qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
                ret = EXCP_INTERRUPT;
                break;
            case KVM_SYSTEM_EVENT_CRASH:
                kvm_cpu_synchronize_state(cpu);
                qemu_mutex_lock_iothread();
                qemu_system_guest_panicked(cpu_get_crash_info(cpu));
                qemu_mutex_unlock_iothread();
                ret = 0;
                break;
            default:
                DPRINTF("kvm_arch_handle_exit\n");
                ret = kvm_arch_handle_exit(cpu, run);
                break;
            }
            break;
        default:
            DPRINTF("kvm_arch_handle_exit\n");
            ret = kvm_arch_handle_exit(cpu, run);
            break;
        }
    } while (ret == 0);

    cpu_exec_end(cpu);
    qemu_mutex_lock_iothread();

    if (ret < 0) {
        cpu_dump_state(cpu, stderr, CPU_DUMP_CODE);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    qatomic_set(&cpu->exit_request, 0);
    return ret;
}

int kvm_ioctl(KVMState *s, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_ioctl(type, arg);
    ret = ioctl(s->fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_vm_ioctl(KVMState *s, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vm_ioctl(type, arg);
    ret = ioctl(s->vmfd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_vcpu_ioctl(CPUState *cpu, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vcpu_ioctl(cpu->cpu_index, type, arg);
    ret = ioctl(cpu->kvm_fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_device_ioctl(int fd, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_device_ioctl(fd, type, arg);
    ret = ioctl(fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int kvm_vm_check_attr(KVMState *s, uint32_t group, uint64_t attr)
{
    int ret;
    struct kvm_device_attr attribute = {
        .group = group,
        .attr = attr,
    };

    if (!kvm_vm_attributes_allowed) {
        return 0;
    }

    ret = kvm_vm_ioctl(s, KVM_HAS_DEVICE_ATTR, &attribute);
    /* kvm returns 0 on success for HAS_DEVICE_ATTR */
    return ret ? 0 : 1;
}

int kvm_device_check_attr(int dev_fd, uint32_t group, uint64_t attr)
{
    struct kvm_device_attr attribute = {
        .group = group,
        .attr = attr,
        .flags = 0,
    };

    return kvm_device_ioctl(dev_fd, KVM_HAS_DEVICE_ATTR, &attribute) ? 0 : 1;
}

int kvm_device_access(int fd, int group, uint64_t attr,
                      void *val, bool write, Error **errp)
{
    struct kvm_device_attr kvmattr;
    int err;

    kvmattr.flags = 0;
    kvmattr.group = group;
    kvmattr.attr = attr;
    kvmattr.addr = (uintptr_t)val;

    err = kvm_device_ioctl(fd,
                           write ? KVM_SET_DEVICE_ATTR : KVM_GET_DEVICE_ATTR,
                           &kvmattr);
    if (err < 0) {
        error_setg_errno(errp, -err,
                         "KVM_%s_DEVICE_ATTR failed: Group %d "
                         "attr 0x%016" PRIx64,
                         write ? "SET" : "GET", group, attr);
    }
    return err;
}

bool kvm_has_sync_mmu(void)
{
    return kvm_state->sync_mmu;
}

int kvm_has_vcpu_events(void)
{
    return kvm_state->vcpu_events;
}

int kvm_has_robust_singlestep(void)
{
    return kvm_state->robust_singlestep;
}

int kvm_has_debugregs(void)
{
    return kvm_state->debugregs;
}

int kvm_max_nested_state_length(void)
{
    return kvm_state->max_nested_state_len;
}

int kvm_has_many_ioeventfds(void)
{
    if (!kvm_enabled()) {
        return 0;
    }
    return kvm_state->many_ioeventfds;
}

int kvm_has_gsi_routing(void)
{
#ifdef KVM_CAP_IRQ_ROUTING
    return kvm_check_extension(kvm_state, KVM_CAP_IRQ_ROUTING);
#else
    return false;
#endif
}

int kvm_has_intx_set_mask(void)
{
    return kvm_state->intx_set_mask;
}

bool kvm_arm_supports_user_irq(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_ARM_USER_IRQ);
}

#ifdef KVM_CAP_SET_GUEST_DEBUG
struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(CPUState *cpu,
                                                 target_ulong pc)
{
    struct kvm_sw_breakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->kvm_state->kvm_sw_breakpoints, entry) {
        if (bp->pc == pc) {
            return bp;
        }
    }
    return NULL;
}

int kvm_sw_breakpoints_active(CPUState *cpu)
{
    return !QTAILQ_EMPTY(&cpu->kvm_state->kvm_sw_breakpoints);
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int err;
};

static void kvm_invoke_set_guest_debug(CPUState *cpu, run_on_cpu_data data)
{
    struct kvm_set_guest_debug_data *dbg_data =
        (struct kvm_set_guest_debug_data *) data.host_ptr;

    dbg_data->err = kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG,
                                   &dbg_data->dbg);
}

int kvm_update_guest_debug(CPUState *cpu, unsigned long reinject_trap)
{
    struct kvm_set_guest_debug_data data;

    data.dbg.control = reinject_trap;

    if (cpu->singlestep_enabled) {
        data.dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

        if (cpu->singlestep_enabled & SSTEP_NOIRQ) {
            data.dbg.control |= KVM_GUESTDBG_BLOCKIRQ;
        }
    }
    kvm_arch_update_guest_debug(cpu, &data.dbg);

    run_on_cpu(cpu, kvm_invoke_set_guest_debug,
               RUN_ON_CPU_HOST_PTR(&data));
    return data.err;
}

bool kvm_supports_guest_debug(void)
{
    /* probed during kvm_init() */
    return kvm_has_guest_debug;
}

int kvm_insert_breakpoint(CPUState *cpu, int type, hwaddr addr, hwaddr len)
{
    struct kvm_sw_breakpoint *bp;
    int err;

    if (type == GDB_BREAKPOINT_SW) {
        bp = kvm_find_sw_breakpoint(cpu, addr);
        if (bp) {
            bp->use_count++;
            return 0;
        }

        bp = g_new(struct kvm_sw_breakpoint, 1);
        bp->pc = addr;
        bp->use_count = 1;
        err = kvm_arch_insert_sw_breakpoint(cpu, bp);
        if (err) {
            g_free(bp);
            return err;
        }

        QTAILQ_INSERT_HEAD(&cpu->kvm_state->kvm_sw_breakpoints, bp, entry);
    } else {
        err = kvm_arch_insert_hw_breakpoint(addr, len, type);
        if (err) {
            return err;
        }
    }

    CPU_FOREACH(cpu) {
        err = kvm_update_guest_debug(cpu, 0);
        if (err) {
            return err;
        }
    }
    return 0;
}

int kvm_remove_breakpoint(CPUState *cpu, int type, hwaddr addr, hwaddr len)
{
    struct kvm_sw_breakpoint *bp;
    int err;

    if (type == GDB_BREAKPOINT_SW) {
        bp = kvm_find_sw_breakpoint(cpu, addr);
        if (!bp) {
            return -ENOENT;
        }

        if (bp->use_count > 1) {
            bp->use_count--;
            return 0;
        }

        err = kvm_arch_remove_sw_breakpoint(cpu, bp);
        if (err) {
            return err;
        }

        QTAILQ_REMOVE(&cpu->kvm_state->kvm_sw_breakpoints, bp, entry);
        g_free(bp);
    } else {
        err = kvm_arch_remove_hw_breakpoint(addr, len, type);
        if (err) {
            return err;
        }
    }

    CPU_FOREACH(cpu) {
        err = kvm_update_guest_debug(cpu, 0);
        if (err) {
            return err;
        }
    }
    return 0;
}

void kvm_remove_all_breakpoints(CPUState *cpu)
{
    struct kvm_sw_breakpoint *bp, *next;
    KVMState *s = cpu->kvm_state;
    CPUState *tmpcpu;

    QTAILQ_FOREACH_SAFE(bp, &s->kvm_sw_breakpoints, entry, next) {
        if (kvm_arch_remove_sw_breakpoint(cpu, bp) != 0) {
            /* Try harder to find a CPU that currently sees the breakpoint. */
            CPU_FOREACH(tmpcpu) {
                if (kvm_arch_remove_sw_breakpoint(tmpcpu, bp) == 0) {
                    break;
                }
            }
        }
        QTAILQ_REMOVE(&s->kvm_sw_breakpoints, bp, entry);
        g_free(bp);
    }
    kvm_arch_remove_all_hw_breakpoints();

    CPU_FOREACH(cpu) {
        kvm_update_guest_debug(cpu, 0);
    }
}

#endif /* !KVM_CAP_SET_GUEST_DEBUG */

static int kvm_set_signal_mask(CPUState *cpu, const sigset_t *sigset)
{
    KVMState *s = kvm_state;
    struct kvm_signal_mask *sigmask;
    int r;

    sigmask = g_malloc(sizeof(*sigmask) + sizeof(*sigset));

    sigmask->len = s->sigmask_len;
    memcpy(sigmask->sigset, sigset, sizeof(*sigset));
    r = kvm_vcpu_ioctl(cpu, KVM_SET_SIGNAL_MASK, sigmask);
    g_free(sigmask);

    return r;
}

static void kvm_ipi_signal(int sig)
{
    if (current_cpu) {
        assert(kvm_immediate_exit);
        kvm_cpu_kick(current_cpu);
    }
}

void kvm_init_cpu_signals(CPUState *cpu)
{
    int r;
    sigset_t set;
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = kvm_ipi_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
#if defined KVM_HAVE_MCE_INJECTION
    sigdelset(&set, SIGBUS);
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#endif
    sigdelset(&set, SIG_IPI);
    if (kvm_immediate_exit) {
        r = pthread_sigmask(SIG_SETMASK, &set, NULL);
    } else {
        r = kvm_set_signal_mask(cpu, &set);
    }
    if (r) {
        fprintf(stderr, "kvm_set_signal_mask: %s\n", strerror(-r));
        exit(1);
    }
}

/* Called asynchronously in VCPU thread.  */
int kvm_on_sigbus_vcpu(CPUState *cpu, int code, void *addr)
{
#ifdef KVM_HAVE_MCE_INJECTION
    if (have_sigbus_pending) {
        return 1;
    }
    have_sigbus_pending = true;
    pending_sigbus_addr = addr;
    pending_sigbus_code = code;
    qatomic_set(&cpu->exit_request, 1);
    return 0;
#else
    return 1;
#endif
}

/* Called synchronously (via signalfd) in main thread.  */
int kvm_on_sigbus(int code, void *addr)
{
#ifdef KVM_HAVE_MCE_INJECTION
    /* Action required MCE kills the process if SIGBUS is blocked.  Because
     * that's what happens in the I/O thread, where we handle MCE via signalfd,
     * we can only get action optional here.
     */
    assert(code != BUS_MCEERR_AR);
    kvm_arch_on_sigbus_vcpu(first_cpu, code, addr);
    return 0;
#else
    return 1;
#endif
}

int kvm_create_device(KVMState *s, uint64_t type, bool test)
{
    int ret;
    struct kvm_create_device create_dev;

    create_dev.type = type;
    create_dev.fd = -1;
    create_dev.flags = test ? KVM_CREATE_DEVICE_TEST : 0;

    if (!kvm_check_extension(s, KVM_CAP_DEVICE_CTRL)) {
        return -ENOTSUP;
    }

    ret = kvm_vm_ioctl(s, KVM_CREATE_DEVICE, &create_dev);
    if (ret) {
        return ret;
    }

    return test ? 0 : create_dev.fd;
}

bool kvm_device_supported(int vmfd, uint64_t type)
{
    struct kvm_create_device create_dev = {
        .type = type,
        .fd = -1,
        .flags = KVM_CREATE_DEVICE_TEST,
    };

    if (ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_DEVICE_CTRL) <= 0) {
        return false;
    }

    return (ioctl(vmfd, KVM_CREATE_DEVICE, &create_dev) >= 0);
}

int kvm_set_one_reg(CPUState *cs, uint64_t id, void *source)
{
    struct kvm_one_reg reg;
    int r;

    reg.id = id;
    reg.addr = (uintptr_t) source;
    r = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (r) {
        trace_kvm_failed_reg_set(id, strerror(-r));
    }
    return r;
}

int kvm_get_one_reg(CPUState *cs, uint64_t id, void *target)
{
    struct kvm_one_reg reg;
    int r;

    reg.id = id;
    reg.addr = (uintptr_t) target;
    r = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (r) {
        trace_kvm_failed_reg_get(id, strerror(-r));
    }
    return r;
}

static bool kvm_accel_has_memory(MachineState *ms, AddressSpace *as,
                                 hwaddr start_addr, hwaddr size)
{
    KVMState *kvm = KVM_STATE(ms->accelerator);
    int i;

    for (i = 0; i < kvm->nr_as; ++i) {
        if (kvm->as[i].as == as && kvm->as[i].ml) {
            size = MIN(kvm_max_slot_size, size);
            return NULL != kvm_lookup_matching_slot(kvm->as[i].ml,
                                                    start_addr, size);
        }
    }

    return false;
}

static void kvm_get_kvm_shadow_mem(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    int64_t value = s->kvm_shadow_mem;

    visit_type_int(v, name, &value, errp);
}

static void kvm_set_kvm_shadow_mem(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    int64_t value;

    if (s->fd != -1) {
        error_setg(errp, "Cannot set properties after the accelerator has been initialized");
        return;
    }

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }

    s->kvm_shadow_mem = value;
}

static void kvm_set_kernel_irqchip(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    OnOffSplit mode;

    if (s->fd != -1) {
        error_setg(errp, "Cannot set properties after the accelerator has been initialized");
        return;
    }

    if (!visit_type_OnOffSplit(v, name, &mode, errp)) {
        return;
    }
    switch (mode) {
    case ON_OFF_SPLIT_ON:
        s->kernel_irqchip_allowed = true;
        s->kernel_irqchip_required = true;
        s->kernel_irqchip_split = ON_OFF_AUTO_OFF;
        break;
    case ON_OFF_SPLIT_OFF:
        s->kernel_irqchip_allowed = false;
        s->kernel_irqchip_required = false;
        s->kernel_irqchip_split = ON_OFF_AUTO_OFF;
        break;
    case ON_OFF_SPLIT_SPLIT:
        s->kernel_irqchip_allowed = true;
        s->kernel_irqchip_required = true;
        s->kernel_irqchip_split = ON_OFF_AUTO_ON;
        break;
    default:
        /* The value was checked in visit_type_OnOffSplit() above. If
         * we get here, then something is wrong in QEMU.
         */
        abort();
    }
}

bool kvm_kernel_irqchip_allowed(void)
{
    return kvm_state->kernel_irqchip_allowed;
}

bool kvm_kernel_irqchip_required(void)
{
    return kvm_state->kernel_irqchip_required;
}

bool kvm_kernel_irqchip_split(void)
{
    return kvm_state->kernel_irqchip_split == ON_OFF_AUTO_ON;
}

static void kvm_get_dirty_ring_size(Object *obj, Visitor *v,
                                    const char *name, void *opaque,
                                    Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    uint32_t value = s->kvm_dirty_ring_size;

    visit_type_uint32(v, name, &value, errp);
}

static void kvm_set_dirty_ring_size(Object *obj, Visitor *v,
                                    const char *name, void *opaque,
                                    Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    Error *error = NULL;
    uint32_t value;

    if (s->fd != -1) {
        error_setg(errp, "Cannot set properties after the accelerator has been initialized");
        return;
    }

    visit_type_uint32(v, name, &value, &error);
    if (error) {
        error_propagate(errp, error);
        return;
    }
    if (value & (value - 1)) {
        error_setg(errp, "dirty-ring-size must be a power of two.");
        return;
    }

    s->kvm_dirty_ring_size = value;
}

static void kvm_accel_instance_init(Object *obj)
{
    KVMState *s = KVM_STATE(obj);

    s->fd = -1;
    s->vmfd = -1;
    s->kvm_shadow_mem = -1;
    s->kernel_irqchip_allowed = true;
    s->kernel_irqchip_split = ON_OFF_AUTO_AUTO;
    /* KVM dirty ring is by default off */
    s->kvm_dirty_ring_size = 0;
    s->notify_vmexit = NOTIFY_VMEXIT_OPTION_RUN;
    s->notify_window = 0;
}

/**
 * kvm_gdbstub_sstep_flags():
 *
 * Returns: SSTEP_* flags that KVM supports for guest debug. The
 * support is probed during kvm_init()
 */
static int kvm_gdbstub_sstep_flags(void)
{
    return kvm_sstep_flags;
}

static void kvm_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "KVM";
    ac->init_machine = kvm_init;
    ac->has_memory = kvm_accel_has_memory;
    ac->allowed = &kvm_allowed;
    ac->gdbstub_supported_sstep_flags = kvm_gdbstub_sstep_flags;

    object_class_property_add(oc, "kernel-irqchip", "on|off|split",
        NULL, kvm_set_kernel_irqchip,
        NULL, NULL);
    object_class_property_set_description(oc, "kernel-irqchip",
        "Configure KVM in-kernel irqchip");

    object_class_property_add(oc, "kvm-shadow-mem", "int",
        kvm_get_kvm_shadow_mem, kvm_set_kvm_shadow_mem,
        NULL, NULL);
    object_class_property_set_description(oc, "kvm-shadow-mem",
        "KVM shadow MMU size");

    object_class_property_add(oc, "dirty-ring-size", "uint32",
        kvm_get_dirty_ring_size, kvm_set_dirty_ring_size,
        NULL, NULL);
    object_class_property_set_description(oc, "dirty-ring-size",
        "Size of KVM dirty page ring buffer (default: 0, i.e. use bitmap)");

    kvm_arch_accel_class_init(oc);
}

static const TypeInfo kvm_accel_type = {
    .name = TYPE_KVM_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = kvm_accel_instance_init,
    .class_init = kvm_accel_class_init,
    .instance_size = sizeof(KVMState),
};

static void kvm_type_init(void)
{
    type_register_static(&kvm_accel_type);
}

type_init(kvm_type_init);

typedef struct StatsArgs {
    union StatsResultsType {
        StatsResultList **stats;
        StatsSchemaList **schema;
    } result;
    strList *names;
    Error **errp;
} StatsArgs;

static StatsList *add_kvmstat_entry(struct kvm_stats_desc *pdesc,
                                    uint64_t *stats_data,
                                    StatsList *stats_list,
                                    Error **errp)
{

    Stats *stats;
    uint64List *val_list = NULL;

    /* Only add stats that we understand.  */
    switch (pdesc->flags & KVM_STATS_TYPE_MASK) {
    case KVM_STATS_TYPE_CUMULATIVE:
    case KVM_STATS_TYPE_INSTANT:
    case KVM_STATS_TYPE_PEAK:
    case KVM_STATS_TYPE_LINEAR_HIST:
    case KVM_STATS_TYPE_LOG_HIST:
        break;
    default:
        return stats_list;
    }

    switch (pdesc->flags & KVM_STATS_UNIT_MASK) {
    case KVM_STATS_UNIT_NONE:
    case KVM_STATS_UNIT_BYTES:
    case KVM_STATS_UNIT_CYCLES:
    case KVM_STATS_UNIT_SECONDS:
    case KVM_STATS_UNIT_BOOLEAN:
        break;
    default:
        return stats_list;
    }

    switch (pdesc->flags & KVM_STATS_BASE_MASK) {
    case KVM_STATS_BASE_POW10:
    case KVM_STATS_BASE_POW2:
        break;
    default:
        return stats_list;
    }

    /* Alloc and populate data list */
    stats = g_new0(Stats, 1);
    stats->name = g_strdup(pdesc->name);
    stats->value = g_new0(StatsValue, 1);;

    if ((pdesc->flags & KVM_STATS_UNIT_MASK) == KVM_STATS_UNIT_BOOLEAN) {
        stats->value->u.boolean = *stats_data;
        stats->value->type = QTYPE_QBOOL;
    } else if (pdesc->size == 1) {
        stats->value->u.scalar = *stats_data;
        stats->value->type = QTYPE_QNUM;
    } else {
        int i;
        for (i = 0; i < pdesc->size; i++) {
            QAPI_LIST_PREPEND(val_list, stats_data[i]);
        }
        stats->value->u.list = val_list;
        stats->value->type = QTYPE_QLIST;
    }

    QAPI_LIST_PREPEND(stats_list, stats);
    return stats_list;
}

static StatsSchemaValueList *add_kvmschema_entry(struct kvm_stats_desc *pdesc,
                                                 StatsSchemaValueList *list,
                                                 Error **errp)
{
    StatsSchemaValueList *schema_entry = g_new0(StatsSchemaValueList, 1);
    schema_entry->value = g_new0(StatsSchemaValue, 1);

    switch (pdesc->flags & KVM_STATS_TYPE_MASK) {
    case KVM_STATS_TYPE_CUMULATIVE:
        schema_entry->value->type = STATS_TYPE_CUMULATIVE;
        break;
    case KVM_STATS_TYPE_INSTANT:
        schema_entry->value->type = STATS_TYPE_INSTANT;
        break;
    case KVM_STATS_TYPE_PEAK:
        schema_entry->value->type = STATS_TYPE_PEAK;
        break;
    case KVM_STATS_TYPE_LINEAR_HIST:
        schema_entry->value->type = STATS_TYPE_LINEAR_HISTOGRAM;
        schema_entry->value->bucket_size = pdesc->bucket_size;
        schema_entry->value->has_bucket_size = true;
        break;
    case KVM_STATS_TYPE_LOG_HIST:
        schema_entry->value->type = STATS_TYPE_LOG2_HISTOGRAM;
        break;
    default:
        goto exit;
    }

    switch (pdesc->flags & KVM_STATS_UNIT_MASK) {
    case KVM_STATS_UNIT_NONE:
        break;
    case KVM_STATS_UNIT_BOOLEAN:
        schema_entry->value->has_unit = true;
        schema_entry->value->unit = STATS_UNIT_BOOLEAN;
        break;
    case KVM_STATS_UNIT_BYTES:
        schema_entry->value->has_unit = true;
        schema_entry->value->unit = STATS_UNIT_BYTES;
        break;
    case KVM_STATS_UNIT_CYCLES:
        schema_entry->value->has_unit = true;
        schema_entry->value->unit = STATS_UNIT_CYCLES;
        break;
    case KVM_STATS_UNIT_SECONDS:
        schema_entry->value->has_unit = true;
        schema_entry->value->unit = STATS_UNIT_SECONDS;
        break;
    default:
        goto exit;
    }

    schema_entry->value->exponent = pdesc->exponent;
    if (pdesc->exponent) {
        switch (pdesc->flags & KVM_STATS_BASE_MASK) {
        case KVM_STATS_BASE_POW10:
            schema_entry->value->has_base = true;
            schema_entry->value->base = 10;
            break;
        case KVM_STATS_BASE_POW2:
            schema_entry->value->has_base = true;
            schema_entry->value->base = 2;
            break;
        default:
            goto exit;
        }
    }

    schema_entry->value->name = g_strdup(pdesc->name);
    schema_entry->next = list;
    return schema_entry;
exit:
    g_free(schema_entry->value);
    g_free(schema_entry);
    return list;
}

/* Cached stats descriptors */
typedef struct StatsDescriptors {
    const char *ident; /* cache key, currently the StatsTarget */
    struct kvm_stats_desc *kvm_stats_desc;
    struct kvm_stats_header kvm_stats_header;
    QTAILQ_ENTRY(StatsDescriptors) next;
} StatsDescriptors;

static QTAILQ_HEAD(, StatsDescriptors) stats_descriptors =
    QTAILQ_HEAD_INITIALIZER(stats_descriptors);

/*
 * Return the descriptors for 'target', that either have already been read
 * or are retrieved from 'stats_fd'.
 */
static StatsDescriptors *find_stats_descriptors(StatsTarget target, int stats_fd,
                                                Error **errp)
{
    StatsDescriptors *descriptors;
    const char *ident;
    struct kvm_stats_desc *kvm_stats_desc;
    struct kvm_stats_header *kvm_stats_header;
    size_t size_desc;
    ssize_t ret;

    ident = StatsTarget_str(target);
    QTAILQ_FOREACH(descriptors, &stats_descriptors, next) {
        if (g_str_equal(descriptors->ident, ident)) {
            return descriptors;
        }
    }

    descriptors = g_new0(StatsDescriptors, 1);

    /* Read stats header */
    kvm_stats_header = &descriptors->kvm_stats_header;
    ret = read(stats_fd, kvm_stats_header, sizeof(*kvm_stats_header));
    if (ret != sizeof(*kvm_stats_header)) {
        error_setg(errp, "KVM stats: failed to read stats header: "
                   "expected %zu actual %zu",
                   sizeof(*kvm_stats_header), ret);
        g_free(descriptors);
        return NULL;
    }
    size_desc = sizeof(*kvm_stats_desc) + kvm_stats_header->name_size;

    /* Read stats descriptors */
    kvm_stats_desc = g_malloc0_n(kvm_stats_header->num_desc, size_desc);
    ret = pread(stats_fd, kvm_stats_desc,
                size_desc * kvm_stats_header->num_desc,
                kvm_stats_header->desc_offset);

    if (ret != size_desc * kvm_stats_header->num_desc) {
        error_setg(errp, "KVM stats: failed to read stats descriptors: "
                   "expected %zu actual %zu",
                   size_desc * kvm_stats_header->num_desc, ret);
        g_free(descriptors);
        g_free(kvm_stats_desc);
        return NULL;
    }
    descriptors->kvm_stats_desc = kvm_stats_desc;
    descriptors->ident = ident;
    QTAILQ_INSERT_TAIL(&stats_descriptors, descriptors, next);
    return descriptors;
}

static void query_stats(StatsResultList **result, StatsTarget target,
                        strList *names, int stats_fd, Error **errp)
{
    struct kvm_stats_desc *kvm_stats_desc;
    struct kvm_stats_header *kvm_stats_header;
    StatsDescriptors *descriptors;
    g_autofree uint64_t *stats_data = NULL;
    struct kvm_stats_desc *pdesc;
    StatsList *stats_list = NULL;
    size_t size_desc, size_data = 0;
    ssize_t ret;
    int i;

    descriptors = find_stats_descriptors(target, stats_fd, errp);
    if (!descriptors) {
        return;
    }

    kvm_stats_header = &descriptors->kvm_stats_header;
    kvm_stats_desc = descriptors->kvm_stats_desc;
    size_desc = sizeof(*kvm_stats_desc) + kvm_stats_header->name_size;

    /* Tally the total data size; read schema data */
    for (i = 0; i < kvm_stats_header->num_desc; ++i) {
        pdesc = (void *)kvm_stats_desc + i * size_desc;
        size_data += pdesc->size * sizeof(*stats_data);
    }

    stats_data = g_malloc0(size_data);
    ret = pread(stats_fd, stats_data, size_data, kvm_stats_header->data_offset);

    if (ret != size_data) {
        error_setg(errp, "KVM stats: failed to read data: "
                   "expected %zu actual %zu", size_data, ret);
        return;
    }

    for (i = 0; i < kvm_stats_header->num_desc; ++i) {
        uint64_t *stats;
        pdesc = (void *)kvm_stats_desc + i * size_desc;

        /* Add entry to the list */
        stats = (void *)stats_data + pdesc->offset;
        if (!apply_str_list_filter(pdesc->name, names)) {
            continue;
        }
        stats_list = add_kvmstat_entry(pdesc, stats, stats_list, errp);
    }

    if (!stats_list) {
        return;
    }

    switch (target) {
    case STATS_TARGET_VM:
        add_stats_entry(result, STATS_PROVIDER_KVM, NULL, stats_list);
        break;
    case STATS_TARGET_VCPU:
        add_stats_entry(result, STATS_PROVIDER_KVM,
                        current_cpu->parent_obj.canonical_path,
                        stats_list);
        break;
    default:
        g_assert_not_reached();
    }
}

static void query_stats_schema(StatsSchemaList **result, StatsTarget target,
                               int stats_fd, Error **errp)
{
    struct kvm_stats_desc *kvm_stats_desc;
    struct kvm_stats_header *kvm_stats_header;
    StatsDescriptors *descriptors;
    struct kvm_stats_desc *pdesc;
    StatsSchemaValueList *stats_list = NULL;
    size_t size_desc;
    int i;

    descriptors = find_stats_descriptors(target, stats_fd, errp);
    if (!descriptors) {
        return;
    }

    kvm_stats_header = &descriptors->kvm_stats_header;
    kvm_stats_desc = descriptors->kvm_stats_desc;
    size_desc = sizeof(*kvm_stats_desc) + kvm_stats_header->name_size;

    /* Tally the total data size; read schema data */
    for (i = 0; i < kvm_stats_header->num_desc; ++i) {
        pdesc = (void *)kvm_stats_desc + i * size_desc;
        stats_list = add_kvmschema_entry(pdesc, stats_list, errp);
    }

    add_stats_schema(result, STATS_PROVIDER_KVM, target, stats_list);
}

static void query_stats_vcpu(CPUState *cpu, run_on_cpu_data data)
{
    StatsArgs *kvm_stats_args = (StatsArgs *) data.host_ptr;
    int stats_fd = kvm_vcpu_ioctl(cpu, KVM_GET_STATS_FD, NULL);
    Error *local_err = NULL;

    if (stats_fd == -1) {
        error_setg_errno(&local_err, errno, "KVM stats: ioctl failed");
        error_propagate(kvm_stats_args->errp, local_err);
        return;
    }
    query_stats(kvm_stats_args->result.stats, STATS_TARGET_VCPU,
                kvm_stats_args->names, stats_fd, kvm_stats_args->errp);
    close(stats_fd);
}

static void query_stats_schema_vcpu(CPUState *cpu, run_on_cpu_data data)
{
    StatsArgs *kvm_stats_args = (StatsArgs *) data.host_ptr;
    int stats_fd = kvm_vcpu_ioctl(cpu, KVM_GET_STATS_FD, NULL);
    Error *local_err = NULL;

    if (stats_fd == -1) {
        error_setg_errno(&local_err, errno, "KVM stats: ioctl failed");
        error_propagate(kvm_stats_args->errp, local_err);
        return;
    }
    query_stats_schema(kvm_stats_args->result.schema, STATS_TARGET_VCPU, stats_fd,
                       kvm_stats_args->errp);
    close(stats_fd);
}

static void query_stats_cb(StatsResultList **result, StatsTarget target,
                           strList *names, strList *targets, Error **errp)
{
    KVMState *s = kvm_state;
    CPUState *cpu;
    int stats_fd;

    switch (target) {
    case STATS_TARGET_VM:
    {
        stats_fd = kvm_vm_ioctl(s, KVM_GET_STATS_FD, NULL);
        if (stats_fd == -1) {
            error_setg_errno(errp, errno, "KVM stats: ioctl failed");
            return;
        }
        query_stats(result, target, names, stats_fd, errp);
        close(stats_fd);
        break;
    }
    case STATS_TARGET_VCPU:
    {
        StatsArgs stats_args;
        stats_args.result.stats = result;
        stats_args.names = names;
        stats_args.errp = errp;
        CPU_FOREACH(cpu) {
            if (!apply_str_list_filter(cpu->parent_obj.canonical_path, targets)) {
                continue;
            }
            run_on_cpu(cpu, query_stats_vcpu, RUN_ON_CPU_HOST_PTR(&stats_args));
        }
        break;
    }
    default:
        break;
    }
}

void query_stats_schemas_cb(StatsSchemaList **result, Error **errp)
{
    StatsArgs stats_args;
    KVMState *s = kvm_state;
    int stats_fd;

    stats_fd = kvm_vm_ioctl(s, KVM_GET_STATS_FD, NULL);
    if (stats_fd == -1) {
        error_setg_errno(errp, errno, "KVM stats: ioctl failed");
        return;
    }
    query_stats_schema(result, STATS_TARGET_VM, stats_fd, errp);
    close(stats_fd);

    if (first_cpu) {
        stats_args.result.schema = result;
        stats_args.errp = errp;
        run_on_cpu(first_cpu, query_stats_schema_vcpu, RUN_ON_CPU_HOST_PTR(&stats_args));
    }
}
