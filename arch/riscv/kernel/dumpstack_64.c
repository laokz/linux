// SPDX-License-Identifier: GPL-2.0
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <asm/stacktrace.h>

static bool noinstr in_task_stack(unsigned long *stack, struct task_struct *task,
			   struct stack_info *info)
{
	unsigned long *begin = task_stack_page(task);
	unsigned long *end   = task_stack_page(task) + THREAD_SIZE;

	/* Assume stack not empty when these in_..._stack() called. */
	if (stack < begin || stack >= end)
		return false;

	info->type	= STACK_TYPE_TASK;
	info->begin	= begin;
	info->end	= end;

	return true;
}

#ifdef CONFIG_IRQ_STACKS
#include <linux/percpu-defs.h>
#include <asm/irq_stack.h>

static __always_inline bool in_irq_stack(unsigned long *stack, struct stack_info *info)
{
	unsigned long *begin = this_cpu_read(irq_stack_ptr);
	unsigned long *end = (void *)begin + IRQ_STACK_SIZE;

	if (stack < begin || stack >= end)
		return false;

	info->type	= STACK_TYPE_IRQ;
	info->begin	= begin;
	info->end	= end;

	return true;
}
#else
static __always_inline bool in_irq_stack(unsigned long *stack, struct stack_info *info)
{
	return false;
}
#endif

static bool noinstr get_stack_info_noinstr(unsigned long *stack, struct task_struct *task,
				    struct stack_info *info)
{
	if (in_task_stack(stack, task, info))
		return true;

	if (task != current)
		return false;

	if (in_irq_stack(stack, info))
		return true;

	return false;
}

int get_stack_info(unsigned long *stack, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask)
{
	task = task ? : current;

	if (!stack)
		goto unknown;

	if (!get_stack_info_noinstr(stack, task, info))
		goto unknown;

	/*
	 * Make sure we don't iterate through any given stack more than once.
	 * If it comes up a second time then there's something wrong going on:
	 * just break out and report an unknown stack type.
	 */
	if (visit_mask) {
		if (*visit_mask & (1UL << info->type)) {
			if (task == current)
				printk_deferred_once(KERN_WARNING "WARNING: stack recursion on stack type %d\n", info->type);
			goto unknown;
		}
		*visit_mask |= 1UL << info->type;
	}

	return 0;

unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return -EINVAL;
}
