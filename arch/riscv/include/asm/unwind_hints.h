/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_UNWIND_HINTS_H
#define _ASM_RISCV_UNWIND_HINTS_H

#include <linux/objtool.h>
#include <asm/orc_types.h>

#ifdef __ASSEMBLY__

.macro UNWIND_HINT_UNDEFINED
	UNWIND_HINT type=UNWIND_HINT_TYPE_UNDEFINED
.endm

.macro UNWIND_HINT_END_OF_STACK
	UNWIND_HINT type=UNWIND_HINT_TYPE_END_OF_STACK
.endm

/*
 * Used at entry.S::handle_exception.
 *
 * Unwinder must detect RA whether is user or kernel address
 * then to terminate or continue the backtrace.
 */
.macro UNWIND_HINT_REGS base=ORC_REG_SP offset=0 indirect=0
	.if \base == ORC_REG_SP
		.if \indirect
			.set sp_reg, ORC_REG_SP_INDIRECT
		.else
			.set sp_reg, ORC_REG_SP
		.endif
	.elseif \base == ORC_REG_BP
		.set sp_reg, ORC_REG_BP
	.else
		.error "UNWIND_HINT_REGS: bad base register"
	.endif

	.set sp_offset, \offset

	.set type, UNWIND_HINT_TYPE_REGS

	UNWIND_HINT sp_reg=sp_reg sp_offset=sp_offset type=type
.endm

.macro UNWIND_HINT_FUNC
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=0 type=UNWIND_HINT_TYPE_FUNC
.endm

.macro UNWIND_HINT_SAVE
	UNWIND_HINT type=UNWIND_HINT_TYPE_SAVE
.endm

.macro UNWIND_HINT_RESTORE
	UNWIND_HINT type=UNWIND_HINT_TYPE_RESTORE
.endm

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_UNWIND_HINTS_H */
