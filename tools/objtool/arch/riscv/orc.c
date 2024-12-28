// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/objtool_types.h>
#include <asm/orc_types.h>

#include <objtool/check.h>
#include <objtool/orc.h>
#include <objtool/warn.h>
#include <objtool/endianness.h>

int init_orc_entry(struct orc_entry *orc, struct cfi_state *cfi, struct instruction *insn)
{
	struct cfi_reg *bp = &cfi->regs[CFI_BP];
	struct cfi_reg *ra = &cfi->regs[CFI_RA];

	memset(orc, 0, sizeof(*orc));

	if (!cfi) {
		/*
		 * This is usually either unreachable nops/traps (which don't
		 * trigger unreachable instruction warnings), or
		 * STACK_FRAME_NON_STANDARD functions.
		 */
		orc->type = ORC_TYPE_UNDEFINED;
		return 0;
	}

	switch (cfi->type) {
	case UNWIND_HINT_TYPE_UNDEFINED:
		orc->type = ORC_TYPE_UNDEFINED;
		return 0;
	case UNWIND_HINT_TYPE_END_OF_STACK:
		orc->type = ORC_TYPE_END_OF_STACK;
		return 0;
	case UNWIND_HINT_TYPE_CALL:
		orc->type = ORC_TYPE_CALL;
		break;
	case UNWIND_HINT_TYPE_REGS:
		orc->type = ORC_TYPE_REGS;
		break;
	default:
		WARN_INSN(insn, "unknown unwind hint type %d", cfi->type);
		return -1;
	}

	switch (cfi->cfa.base) {
	case CFI_SP:
		orc->sp_reg = ORC_REG_SP;
		break;
	case CFI_SP_INDIRECT:
		orc->sp_reg = ORC_REG_SP_INDIRECT;
		break;
	case CFI_BP:
		orc->sp_reg = ORC_REG_BP;
		break;
	default:
		WARN_INSN(insn, "unknown CFA base reg %d", cfi->cfa.base);
		return -1;
	}

	switch (bp->base) {
	case CFI_UNDEFINED:
		orc->bp_reg = ORC_REG_UNDEFINED;
		break;
	case CFI_CFA:
		orc->bp_reg = ORC_REG_PREV_SP;
		break;
	case CFI_BP:
		orc->bp_reg = ORC_REG_BP;
		break;
	default:
		WARN_INSN(insn, "unknown BP base reg %d", bp->base);
		return -1;
	}

	switch (ra->base) {
	case CFI_UNDEFINED:
		orc->ra_reg = ORC_REG_UNDEFINED;
		break;
	case CFI_CFA:
		orc->ra_reg = ORC_REG_PREV_SP;
		break;
	case CFI_BP:
		orc->ra_reg = ORC_REG_BP;
		break;
	default:
		WARN_INSN(insn, "unknown RA base reg %d", ra->base);
		return -1;
	}

	orc->sp_offset = cfi->cfa.offset;
	orc->bp_offset = bp->offset;
	orc->ra_offset = ra->offset;

	return 0;
}

int write_orc_entry(struct elf *elf, struct section *orc_sec,
		    struct section *ip_sec, unsigned int idx,
		    struct section *insn_sec, unsigned long insn_off,
		    struct orc_entry *o)
{
	struct orc_entry *orc;

	/* populate ORC data */
	orc = (struct orc_entry *)orc_sec->data->d_buf + idx;
	memcpy(orc, o, sizeof(*orc));
	orc->sp_offset = bswap_if_needed(elf, orc->sp_offset);
	orc->bp_offset = bswap_if_needed(elf, orc->bp_offset);
	orc->ra_offset = bswap_if_needed(elf, orc->ra_offset);

	/* populate reloc for ip */
	if (!elf_init_reloc_text_sym(elf, ip_sec, idx * sizeof(int), idx,
				     insn_sec, insn_off))
		return -1;

	return 0;
}

static const char *reg_name(unsigned int reg)
{
	switch (reg) {
	case ORC_REG_PREV_SP:
		return "prevsp";
	case ORC_REG_BP:
		return "bp";
	case ORC_REG_SP:
		return "sp";
	case ORC_REG_RA:
		return "ra";
	case ORC_REG_SP_INDIRECT:
		return "sp(ind)";
	default:
		return "?";
	}
}

static const char *orc_type_name(unsigned int type)
{
	switch (type) {
	case ORC_TYPE_UNDEFINED:
		return "(und)";
	case ORC_TYPE_END_OF_STACK:
		return "end";
	case ORC_TYPE_CALL:
		return "call";
	case ORC_TYPE_REGS:
		return "regs";
	default:
		return "?";
	}
}

static void print_reg(unsigned int reg, int offset)
{
	if (reg == ORC_REG_SP_INDIRECT)
		printf("(sp)%+d", offset);
	else if (reg == ORC_REG_UNDEFINED)
		printf("(und)");
	else
		printf("%s%+d", reg_name(reg), offset);
}

void orc_print_dump(struct elf *dummy_elf, struct orc_entry *orc, int i)
{
	printf("type:%s", orc_type_name(orc[i].type));

	printf(" sp:");
	print_reg(orc[i].sp_reg, bswap_if_needed(dummy_elf, orc[i].sp_offset));

	printf(" bp:");
	print_reg(orc[i].bp_reg, bswap_if_needed(dummy_elf, orc[i].bp_offset));

	printf(" ra:");
	print_reg(orc[i].ra_reg, bswap_if_needed(dummy_elf, orc[i].ra_offset));

	printf("\n");
}
