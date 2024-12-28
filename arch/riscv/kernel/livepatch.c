/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_RISCV64_LIVEPATCH_H
#define _ASM_RISCV64_LIVEPATCH_H

#include <linux/livepatch.h>
#include <linux/elf.h>
/*
 * Per the RISC-V psABI:
 *
 *   In the linker relaxation optimization, we introduce a concept
 *   called relocation group; a relocation group consists of 1)
 *   relocations associated with the same target symbol and can be
 *   applied with the same relaxation, or 2) relocations with the
 *   linkage relationship (e.g. `R_RISCV_PCREL_LO12_S` linked with
 *   a `R_RISCV_PCREL_HI20`); all relocations in a single group must
 *   be present in the same section, otherwise will split into another
 *   relocation group.
 *
 * When patches reference external non-exported globals, their
 * R_RISCV_PCREL_HI20/R_RISCV_PCREL_LO12_I relocations target the same
 * symbol and must live in the same section.
 *
 *   R_RISCV_PCREL_HI20 entry should be moved to .klp.rela.xxx section
 *                      when making patch, and when loading livepatch
 *                      core will resolve the target symbol address
 *   R_RISCV_PCREL_LO12_I should also be moved to .klp.rela.xxx section
 *                      when making patch, but when loading livepatch
 *                      core MUST ignore it because R_RISCV_PCREL_LO12_I
 *                      indeed is just a link to the R_RISCV_PCREL_HI20
 */
bool arch_klp_resolve_symbols(unsigned int type)
{
	return (type == R_RISCV_PCREL_LO12_I || type == R_RISCV_PCREL_LO12_S);
}

#endif /* _ASM_RISCV64_LIVEPATCH_H */
