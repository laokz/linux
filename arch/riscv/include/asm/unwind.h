/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_UNWIND_H
#define _ASM_RISCV_UNWIND_H

#include <linux/sched.h>
#include <linux/ftrace.h>
#include <linux/rethook.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>

struct unwind_state {
	struct stack_info stack_info;
	unsigned long stack_mask;
	struct task_struct *task;
	int graph_idx;
#if defined(CONFIG_RETHOOK)
	struct llist_node *kr_cur;
#endif
	bool error;
	unsigned long sp, bp, ip, orig_ra;
	struct pt_regs *regs;
};

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame);
bool unwind_next_frame(struct unwind_state *state);
unsigned long unwind_get_return_address(struct unwind_state *state);

static inline bool unwind_done(struct unwind_state *state)
{
	return state->stack_info.type == STACK_TYPE_UNKNOWN;
}

static inline bool unwind_error(struct unwind_state *state)
{
	return state->error;
}

static inline
void unwind_start(struct unwind_state *state, struct task_struct *task,
		  struct pt_regs *regs, unsigned long *first_frame)
{
	first_frame = first_frame ? : get_stack_pointer(task, regs);

	if (task == NULL)
		task = current;
	__unwind_start(state, task, regs, first_frame);
}

static inline struct pt_regs *unwind_get_entry_regs(struct unwind_state *state)
{
	if (unwind_done(state))
		return NULL;

	return state->regs;
}

void unwind_init(void);
void unwind_module_init(struct module *mod, void *orc_ip, size_t orc_ip_size,
			void *orc, size_t orc_size);

static inline
unsigned long unwind_recover_rethook(struct unwind_state *state,
				     unsigned long addr, unsigned long *addr_p)
{
#ifdef CONFIG_RETHOOK
	if (is_rethook_trampoline(addr))
		return rethook_find_ret_addr(state->task, (unsigned long)addr_p,
					     &state->kr_cur);
#endif
	return addr;
}

/* Recover the return address modified by rethook and ftrace_graph. */
static inline
unsigned long unwind_recover_ret_addr(struct unwind_state *state,
				     unsigned long addr, unsigned long *addr_p)
{
	unsigned long ret;

	ret = ftrace_graph_ret_addr(state->task, &state->graph_idx,
				    addr, addr_p);
	return unwind_recover_rethook(state, ret, addr_p);
}

static inline bool task_on_another_cpu(struct task_struct *task)
{
#ifdef CONFIG_SMP
	return task != current && task->on_cpu;
#else
	return false;
#endif
}

#endif /* _ASM_RISCV_UNWIND_H */
