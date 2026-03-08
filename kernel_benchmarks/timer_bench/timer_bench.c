/*
 * ProgramTimer benchmark kernel module — measures the cost of writing to
 * the APIC timer initial-count register (TMICT). This is the privileged
 * operation that programs a hardware timer.
 *
 * Uses direct MMIO to the local APIC (0xFEE00000) so we don't depend on
 * apic_write/apic_read symbols being exported.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod timer_bench.ko [iters=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <asm/msr.h>

#define APIC_BASE_PHYS   0xFEE00000UL
#define APIC_REG_LVTT    0x320
#define APIC_REG_TMICT   0x380
#define APIC_REG_TDCR    0x3E0
#define APIC_MMIO_SIZE   0x1000

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static void __iomem *apic_base;

static inline u32 apic_mmio_read(u32 reg)
{
	return readl(apic_base + reg);
}

static inline void apic_mmio_write(u32 reg, u32 val)
{
	writel(val, apic_base + reg);
}

static int __init timer_bench_init(void)
{
	unsigned long long start, end, total = 0;
	unsigned long flags;
	u32 saved_lvtt, saved_tdcr, saved_tmict;
	int i;

	if (iters <= 0)
		iters = 1000;

	apic_base = ioremap(APIC_BASE_PHYS, APIC_MMIO_SIZE);
	if (!apic_base) {
		pr_info("timer_bench: failed to ioremap APIC at 0x%lx\n",
			APIC_BASE_PHYS);
		return -ENOMEM;
	}

	pr_info("timer_bench: program APIC timer (MMIO), %d iterations\n", iters);

	local_irq_save(flags);

	saved_lvtt  = apic_mmio_read(APIC_REG_LVTT);
	saved_tdcr  = apic_mmio_read(APIC_REG_TDCR);
	saved_tmict = apic_mmio_read(APIC_REG_TMICT);

	apic_mmio_write(APIC_REG_TMICT, 0);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		apic_mmio_write(APIC_REG_TMICT, 1000000);
		end = rdtsc_ordered();
		total += (end - start);

		apic_mmio_write(APIC_REG_TMICT, 0);
	}

	apic_mmio_write(APIC_REG_LVTT,  saved_lvtt);
	apic_mmio_write(APIC_REG_TDCR,  saved_tdcr);
	apic_mmio_write(APIC_REG_TMICT, saved_tmict);

	local_irq_restore(flags);

	iounmap(apic_base);
	apic_base = NULL;

	pr_info("timer_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit timer_bench_exit(void)
{
	if (apic_base)
		iounmap(apic_base);
	pr_info("timer_bench: module removed\n");
}

module_init(timer_bench_init);
module_exit(timer_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Program-timer latency benchmark (APIC TMICT write, cycles)");
