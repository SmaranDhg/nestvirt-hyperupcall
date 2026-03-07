/*
 * DevNotify benchmark kernel module — measures device-notification latency
 * via MMIO doorbell write (writel to a mapped device register).
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod devnotify_bench.ko mmio_base=0xFEBD4000 [iters=N]; dmesg | tail
 *
 * To find a real MMIO address (e.g. virtio doorbell):
 *   lspci -v | grep -A5 "Virtio"    # look for "Memory at ..."
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <asm/msr.h>

#define MMIO_SIZE 0x1000

static unsigned long mmio_base = 0;
module_param(mmio_base, ulong, 0644);
MODULE_PARM_DESC(mmio_base, "MMIO base address of device doorbell (REQUIRED)");

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static void __iomem *mmio;

static int __init devnotify_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int i;

	if (!mmio_base) {
		pr_info("devnotify_bench: mmio_base is required\n");
		pr_info("  Find one with: lspci -v | grep 'Memory at'\n");
		return -EINVAL;
	}

	if (iters <= 0)
		iters = 1000;

	mmio = ioremap(mmio_base, MMIO_SIZE);
	if (!mmio) {
		pr_info("devnotify_bench: failed to ioremap 0x%lx\n", mmio_base);
		return -ENOMEM;
	}

	pr_info("devnotify_bench: MMIO doorbell write at 0x%lx, %d iterations\n",
		mmio_base, iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		writel(1, mmio);
		end = rdtsc_ordered();
		total += (end - start);
	}

	pr_info("devnotify_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit devnotify_bench_exit(void)
{
	if (mmio)
		iounmap(mmio);
	pr_info("devnotify_bench: module removed\n");
}

module_init(devnotify_bench_init);
module_exit(devnotify_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Device-notification latency benchmark (MMIO doorbell write, cycles)");
