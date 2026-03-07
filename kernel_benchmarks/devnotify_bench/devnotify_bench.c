/*
 * DevNotify benchmark kernel module — measures device-notification latency
 * using irq_work (self-IPI + handler callback). This is the in-kernel analog
 * of "notify a device backend": queue work on a target CPU via IPI and wait
 * for the handler to complete.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod devnotify_bench.ko [iters=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irq_work.h>
#include <linux/completion.h>
#include <asm/msr.h>

static DECLARE_COMPLETION(notify_done);

static void notify_handler(struct irq_work *work)
{
	complete(&notify_done);
}

static struct irq_work notify_work = {
	.func  = notify_handler,
	.flags = IRQ_WORK_HARD_IRQ,
};

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int __init devnotify_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int i;

	if (iters <= 0)
		iters = 1000;

	pr_info("devnotify_bench: device-notification latency (irq_work), %d iterations\n",
		iters);

	for (i = 0; i < iters; i++) {
		reinit_completion(&notify_done);

		barrier();
		start = rdtsc_ordered();
		irq_work_queue(&notify_work);
		wait_for_completion(&notify_done);
		end = rdtsc_ordered();

		total += (end - start);
	}

	pr_info("devnotify_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit devnotify_bench_exit(void)
{
	irq_work_sync(&notify_work);
	pr_info("devnotify_bench: module removed\n");
}

module_init(devnotify_bench_init);
module_exit(devnotify_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Device-notification latency benchmark (irq_work, cycles)");
