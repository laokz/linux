// SPDX-License-Identifier: GPL-2.0-or-later
#include <objtool/special.h>
#include <objtool/warn.h>

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn, struct reloc *reloc)
{
	return true;
}

void arch_add_dead_ends(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	struct instruction *insn, *last_insn;

	for_each_sec(file, sec) {
		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;

		sec_for_each_sym(sec, func) {
			if (func->type != STT_FUNC)
				continue;

			last_insn = NULL;
			func_for_each_insn(file, func, insn) {
				if (insn->type == INSN_CALL_DYNAMIC && insn->_call_dest) {
					if (dead_end_function(file, insn->_call_dest))
						insn->dead_end = true;
					/* reset to avoid side effect */
					insn->_call_dest = NULL;
				}
				last_insn = insn;
			}

			/*
			 * Gcc(12.3) might insert ebreak at the end to capture div 0 bug.
			 * Unlike x86 UD2, RISC-V has no special instruction for this usage.
			 * And we cannot mark ebreak as INSN_BUG so to set dead_end, because
			 * in a lot of place it exists in the middle of a func to deal with
			 * recoverable error.
			 */
			if (last_insn && last_insn->type == INSN_TRAP)
				last_insn->dead_end = true;

			/*
			 * arch/riscv/lib/uaccess.S::__asm_copy_to_user share with
			 * fallback_scalar_usercopy's body. Mark dead_end to avoid
			 * "falls through to next function" warning.
			 */
			if (!strcmp(func->name, "__asm_copy_to_user"))
				last_insn->dead_end = true;
		}
	}
}

/* A switch jump table with ADD32/SUB32 relocations:

0000000000005b42 <handle_IPI>:
    5b64:   00000717       auipc   a4,0x0           <== .L4 is table base
               5b64: R_RISCV_PCREL_HI20    .L4          located at .rodata
    5b68:   00070713       mv      a4,a4            <== rd might not be a4
               5b68: R_RISCV_PCREL_LO12_I  .L0 
    ...
    5b72:   97ba           add     a5,a5,a4         <== might be `add a4,a4,a5`
    5b74:   8782           jr      a5                            `jr a4`

Relocation section '.rela.rodata':
00000000000017e8 0001ef3900000023 R_RISCV_ADD32 0000000000005b9e .L9 + 0 <== .text target0
00000000000017e8 0001eeb000000027 R_RISCV_SUB32 00000000000017e8 .L4 + 0
00000000000017ec 0001ef3a00000023 R_RISCV_ADD32 0000000000005bae .L8 + 0 <== .text target1
00000000000017ec 0001eeb000000027 R_RISCV_SUB32 00000000000017e8 .L4 + 0

Every .rodata entry stores the offset between target instruction
and the table base.

AUIPC+MV is consecutive pair, ADD is in-order before JR, but the two
parts can be in any order.


Sibling(tail) call is really a variant of `AUIPC+JALR` procedure call pair:
  48:   00000317        auipc   t1,0x0
  4c:   00030067        jr      t1
*/
static bool maybe_jump_table_add32(struct reloc *radd32, unsigned base_sym)
{
	struct reloc *rsub32 = radd32 + 1;

	return reloc_offset(radd32) == reloc_offset(rsub32) &&
			reloc_type(radd32) == R_RISCV_ADD32 &&
			reloc_type(rsub32) == R_RISCV_SUB32 &&
			reloc_addend(radd32) == 0 &&
			reloc_addend(rsub32) == 0 &&
			reloc_sym(rsub32) == base_sym;
}

struct reloc *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	struct reloc  *text_reloc, *rodata_reloc;
	struct section *table_sec;
	unsigned long table_offset;
	unsigned int base_sym;

	/* Look for a relocation which references .rodata */
	text_reloc = find_reloc_by_dest_range(file->elf, insn->sec,
					      insn->offset, insn->len);
	if (!text_reloc || !text_reloc->sym->sec->rodata)
		return NULL;

	table_offset = text_reloc->sym->offset;
	table_sec = text_reloc->sym->sec;

	rodata_reloc = find_reloc_by_dest(file->elf, table_sec, table_offset);
	if (!rodata_reloc)
		return NULL;

	switch (reloc_type(rodata_reloc)) {
	case R_RISCV_ADD32:
		base_sym = reloc_sym(rodata_reloc + 1);
		if (reloc_idx(rodata_reloc) == sec_num_entries(rodata_reloc->sec) - 1 ||
			!maybe_jump_table_add32(rodata_reloc, base_sym))
			return NULL;
		break;
	case R_RISCV_32:
		/*
		 * I saw another jump table pattern like x86:
		 * .rodata entries target .text labels directly.
		 */
		break;
	default:
		return NULL;
	}

	return rodata_reloc;
}

static struct reloc *find_jump_table(struct objtool_file *file,
				      struct symbol *func, struct instruction *jump_insn)
{
	struct reloc *table_reloc;
	struct instruction *insn, *dest_insn;
	unsigned base_reg, base_reg1;

	/* Find associated ADD of jump table pattern. */
	insn = jump_insn;
	while(1) {
		insn = prev_insn_same_sec(file, insn);
		if (!insn ||                                 // no previous insn
			insn->type != INSN_OTHER ||              // a special insn
			insn->arch_data == jump_insn->arch_data) // a sibling call
			return NULL;

		if (!insn->arch_data)
			continue;

		if (((insn->arch_data >> 8) & 0xff) == jump_insn->arch_data)
			break;
	}
	base_reg = insn->arch_data & 0xff;
	base_reg1 = (insn->arch_data >> 8) & 0xff;

	/* Find associated MV which carried on AUIPC insn. */
	func_for_each_insn(file, func, insn) {
		if(insn->type != INSN_OTHER || !insn->arch_data || !insn->_jump_table)
			continue;

		/* TODO: no other auipc use these two regs? */
		if (insn->arch_data != base_reg && insn->arch_data != base_reg1)
			continue;

		/* Find the real jump table. */
		table_reloc = arch_find_switch_table(file,
						(struct instruction *)insn->_jump_table);
		if (!table_reloc)
			continue;

		dest_insn = find_insn(file, table_reloc->sym->sec, table_reloc->sym->offset);
		if (!dest_insn || !insn_func(dest_insn) || insn_func(dest_insn)->pfunc != func)
			continue;

		/* TODO: only one jump can consume the jump table base? */
		insn->_jump_table = NULL;
		insn->arch_data = 0;
		return table_reloc;
	}

	return NULL;
}

void mark_func_jump_tables(struct objtool_file *file, struct symbol *func)
{
	struct instruction *insn;
	struct reloc *reloc;

	func_for_each_insn(file, func, insn) {
		if (insn->type != INSN_JUMP_DYNAMIC)
			continue;

		reloc = find_jump_table(file, func, insn);
		if (reloc)
			insn->_jump_table = reloc;
	}
}

struct instruction *arch_add_jump_table(struct objtool_file *file,
		struct reloc *reloc, struct symbol *pfunc, unsigned int prev_offset)
{
	/* Make sure the table entries are consecutive: */
	if (prev_offset && reloc_offset(reloc) != prev_offset + 4)
		return NULL;

	return find_insn(file, reloc->sym->sec, reloc->sym->offset);
}
