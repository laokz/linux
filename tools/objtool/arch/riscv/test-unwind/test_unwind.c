// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Printk a process ORC unwinder backtrace when do livepatching on RISC-V.
 *
 *   insmod ./test_unwind.ko
 *   journalctl -f
 *   load a livepatch module and watch backtrace in journal, module parameter
 *   can be used to change watched PID and arch_stack_walk_reliable address range
 *
 * Results example: vanilla kernel 6.10 + openEuler 24.03 RISC-V kconfig
 * PID	PROCESS						CALL CHAIN
 * 2	[kthreadd]					ret_from_fork->kthreadd->schedule
 * 3	[pool_workqueue_release]	ret_from_fork->kthread->kthread_worker_fn->schedule
 * 15	[ksoftirqd/0]				ret_from_fork->kthread->smpboot_thread_fn->schedule
 * 67	[kauditd]					ret_from_fork->kthread->kauditd_thread->schedule
 * 83	[watchdogd]					ret_from_fork->kthread->kthread_worker_fn->schedule
 * 92	[kswapd0]					ret_from_fork->kthread->kswapd->kswapd_try_to_sleep->schedule
 * 102	[hwrng]						ret_from_fork->kthread->hwrng_fillfn->schedule_timeout->schedule
 * 126	[kmemleak]					ret_from_fork->kthread->kmemleak_scan_thread->schedule_timeout->schedule
 * 208	[jbd2/vda2-8]				ret_from_fork->kthread->kjournald2->schedule
 * 451	[kworker/6:4-events]		ret_from_fork->kthread->worker_thread->schedule
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <asm/unwind.h>

/* PID watched */
static int pid=3;
module_param(pid, int, 0660);

/* arch_stack_walk_reliable address range */
static long start=0xffffffff80006070;
module_param(start, long, 0660);
static long end=0xffffffff8000611c;
module_param(end, long, 0660);

static void test_printk_unwind(unsigned long ip, unsigned long parent_ip,
			      struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	int bit;
	struct unwind_state *state;
	char namebuf[256];

	bit = ftrace_test_recursion_trylock(ip, parent_ip);
	if (bit < 0)
		return;

	state = (struct unwind_state*)fregs->a0;
	if (parent_ip >= start && parent_ip < end && state->task->pid == pid) {
		if (!sprint_symbol_no_offset(namebuf, state->ip))
			printk("orc-unwinder %lx\n", state->ip);
		else
			printk("orc-unwinder %s\n", namebuf);
	}

	ftrace_test_recursion_unlock(bit);
}

static struct ftrace_ops ops = {
	.func = test_printk_unwind,
};

static int test_unwind_init(void)
{
	int ret;

	ret = ftrace_set_filter(&ops, "unwind_next_frame", strlen("unwind_next_frame"), 0);
	if (ret < 0) {
		printk("error ftrace_set_filter");
		return -1;
	}

	ret = register_ftrace_function(&ops);
	if (ret < 0) {
		printk("error register_ftrace_function");
		return -1;
	}
	return 0;
}

static void test_unwind_exit(void)
{
	unregister_ftrace_function(&ops);
	ftrace_free_filter(&ops);
}

module_init(test_unwind_init);
module_exit(test_unwind_exit);
MODULE_LICENSE("GPL");
