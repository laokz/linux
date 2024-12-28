/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _RISCV_ARCH_SPECIAL_H
#define _RISCV_ARCH_SPECIAL_H

/* arch/riscv/include/asm/extable.h */
#define EX_ENTRY_SIZE		12
#define EX_ORIG_OFFSET		0
#define EX_NEW_OFFSET		4

/* include/linux/jump_label.h */
#define JUMP_ENTRY_SIZE		16
#define JUMP_ORIG_OFFSET	0
#define JUMP_NEW_OFFSET		4
#define JUMP_KEY_OFFSET		8

/* arch/riscv/include/asm/alternative.h::struct alt_entry */
#define ALT_ENTRY_SIZE		16
#define ALT_ORIG_OFFSET		0
#define ALT_NEW_OFFSET		4
/*
 * get_alt_entry() retrieve feature value as u16 though
 * it's actually u32. Fine as we not use it now.
 */
#define ALT_FEATURE_OFFSET	12
/*
 * The replacement size is exactly the same as orig, they are
 * represented as a single u16 field. get_alt_entry() retrieve
 * it as u8.
 * 
 * TODO:
 *   - support big-endian machine
 *   - support alternative block larger than 63 instructions
 */
#define ALT_ORIG_LEN_OFFSET 10
#define ALT_NEW_LEN_OFFSET	10

#endif /* _RISCV_ARCH_SPECIAL_H */
