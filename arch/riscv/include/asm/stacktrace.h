/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_STACKTRACE_H
#define _ASM_RISCV_STACKTRACE_H

#include <linux/sched.h>
#include <asm/ptrace.h>

struct stackframe {
	unsigned long fp;
	unsigned long ra;
};

extern void notrace walk_stackframe(struct task_struct *task, struct pt_regs *regs,
				    bool (*fn)(void *, unsigned long), void *arg);
extern void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
			   const char *loglvl);

static inline bool on_thread_stack(void)
{
	return !(((unsigned long)(current->stack) ^ current_stack_pointer) & ~(THREAD_SIZE - 1));
}


#ifdef CONFIG_VMAP_STACK
DECLARE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)], overflow_stack);
#endif /* CONFIG_VMAP_STACK */

#ifdef CONFIG_UNWINDER_ORC
enum stack_type {
	STACK_TYPE_UNKNOWN,
	STACK_TYPE_TASK,
	STACK_TYPE_IRQ,
};

struct stack_info {
	enum stack_type type;
	unsigned long *begin;	// inclusive
	unsigned long *end;		// non-inclusive
};

static inline unsigned long *
get_stack_pointer(struct task_struct *task, struct pt_regs *regs)
{
	if (regs)
		return (unsigned long *)regs->sp;

	if (task == NULL || task == current)
		return (unsigned long *)current_stack_pointer;

	return (unsigned long *)task->thread.sp;
}

static inline bool on_stack(struct stack_info *info, void *addr, size_t len)
{
	void *begin = info->begin;
	void *end   = info->end;

	return (info->type != STACK_TYPE_UNKNOWN &&
		addr >= begin && addr < end &&
		addr + len > begin && addr + len <= end);
}

int get_stack_info(unsigned long *stack, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask);
#endif /* CONFIG_UNWINDER_ORC */

#endif /* _ASM_RISCV_STACKTRACE_H */
