/*
 * ProgramTimer benchmark kernel module — measures the cost of programming
 * (and canceling) a high-resolution timer. This is the privileged operation
 * of setting up a hardware timer event.
 *
 * We measure hrtimer_start + hrtimer_cancel per iteration (the setup cost,
 * not waiting for the timer to fire).
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod timer_bench.ko [iters=N] [period_ns=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <asm/msr.h>

static enum hrtimer_restart timer_handler(struct hrtimer *timer)
{
	return HRTIMER_NORESTART;
}

static struct hrtimer bench_timer;

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static long period_ns = 1000000;
module_param(period_ns, long, 0644);
MODULE_PARM_DESC(period_ns, "Timer period in nanoseconds (default 1000000 = 1ms)");

static int __init timer_bench_init(void)
{
	unsigned long long start, end, total = 0;
	ktime_t period;
	int i;

	if (iters <= 0)
		iters = 1000;
	if (period_ns <= 0)
		period_ns = 1000000;

	period = ns_to_ktime(period_ns);

	hrtimer_init(&bench_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	bench_timer.function = timer_handler;

	pr_info("timer_bench: program-timer latency, period=%ld ns, %d iterations\n",
		period_ns, iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		hrtimer_start(&bench_timer, period, HRTIMER_MODE_REL);
		hrtimer_cancel(&bench_timer);
		end = rdtsc_ordered();
		total += (end - start);
	}

	pr_info("timer_bench: avg latency %llu cycles (program+cancel)\n",
		total / iters);

	return 0;
}

static void __exit timer_bench_exit(void)
{
	hrtimer_cancel(&bench_timer);
	pr_info("timer_bench: module removed\n");
}

module_init(timer_bench_init);
module_exit(timer_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Program-timer latency benchmark (hrtimer, cycles)");
