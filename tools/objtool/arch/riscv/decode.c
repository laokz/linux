// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <objtool/check.h>
#include <objtool/special.h>
#include <objtool/warn.h>
#include <asm/insn.h>
#include <asm/orc_types.h>
#include <linux/objtool_types.h>
#include <linux/bitops.h>

int arch_ftrace_match(char *name)
{
	return !strcmp(name, "_mcount");
}

/* NOTE: Not really callee saved, just for objtool. */
bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case CFI_RA:
	case CFI_BP:
		return true;

	default:
		return false;
	}
}

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

bool arch_pc_relative_reloc(struct reloc *reloc)
{
	/*
	 * All relocation types where P (the address of the target)
	 * is included in the computation.
	 */
	switch (reloc_type(reloc)) {
	case R_RISCV_BRANCH ... R_RISCV_PCREL_LO12_S:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_JUMP:
	case R_RISCV_32_PCREL:
	case R_RISCV_PLT32:
	/* These are not supported by C library yet.
	case R_RISCV_GOT32_PCREL:
	case R_RISCV_TLSDESC_HI20 ... R_RISCV_TLSDESC_ADD_LO12:*/
		return true;

	default:
		break;
	}

	return false;
}

#define GET_INSN_LENGTH(insn)								\
({															\
	u8 __len;												\
	__len = (((insn) & __INSN_LENGTH_MASK) == 0x3) ? 4 : 2;	\
	__len;													\
})

#define RVG_OPCODE_LOAD			0x03
#define RVG_OPCODE_OP_IMM		0x13
#define RVG_OPCODE_OP_IMM_32	0x1b
#define RVG_OPCODE_STORE		0x23
#define RVG_OPCODE_OP			0x33
#define RVG_OPCODE_LUI			0x37
#define RVG_OPCODE_OP_32		0x3b

#define RVG_FUNCT3_ADDI			0x0
#define RVG_FUNCT3_SD			0x3
#define RVG_FUNCT3_LD			0x3
#define RVG_FUNCT3_ADD			0x0
#define RVG_FUNCT3_ANDI			0x7

#define RVG_FUNCT7_ADD			0x0
#define RVG_FUNCT7_EBREAK		0x1

#define RV_INSN_FUNCT7_OPOFF	25
#define RV_INSN_FUNCT7_MASK		GENMASK(6, 0)

#define RV_EXTRACT_FUNCT3(x)	(((x) & RV_INSN_FUNCT3_MASK) >> RV_INSN_FUNCT3_OPOFF)
#define RV_EXTRACT_FUNCT7(x)	RV_X((x), RV_INSN_FUNCT7_OPOFF, RV_INSN_FUNCT7_MASK)

#define RV_EXTRACT_RS2_REG(x) \
	({typeof(x) x_ = (x); \
	RV_X(x_, RVG_RS2_OPOFF, GENMASK(4, 0)); })

#define RV_EXTRACT_STYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ >> 7) & 0x1f) | ((x_ & 0xfe000000) >> 20) | \
	(RV_IMM_SIGN(x_) << RV_I_IMM_SIGN_OFF); })

#define RVC_OPCODE_ADDI4SPN	0x0000
#define RVC_OPCODE_ADDI		0x0001
#define RVC_OPCODE_ADDIW	0x2001
#define RVC_OPCODE_LI		0x4001
#define RVC_OPCODE_ADDI16SP	0x6001
#define RVC_OPCODE_J		0xa001
#define RVC_OPCODE_BEQZ		0xc001
#define RVC_OPCODE_BNEZ		0xe001
#define RVC_OPCODE_SLLI		0x0002
#define RVC_OPCODE_LWSP		0x4002
#define RVC_OPCODE_LDSP		0x6002
#define RVC_OPCODE_JR		0x8002
#define RVC_OPCODE_SDSP		0xe002

#define RVC_EXTRACT_OPCODE(x) \
	({typeof(x) x_ = (x); \
	(x_ & RVC_INSN_FUNCT3_MASK) | (x_ & 0x3); })

#define RVC_EXTRACT_C0_RD_REG(x) \
	({typeof(x) x_ = (x); \
	RV_X(x_, RVC_C0_RD_OPOFF, GENMASK(2, 0)) + 8; })

#define RVC_EXTRACT_CI_RD_REG(x) \
	({typeof(x) x_ = (x); \
	RV_X(x_, 7, GENMASK(4, 0)); })

#define RVC_EXTRACT_C2_RS2_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVC_C2_RS2_OPOFF, GENMASK(4, 0))); })

#define RVC_EXTRACT_ADDI4SPN_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ & 0x1800) >> 7) | ((x_ & 0x780) >> 1) | \
	((x_ & 0x40) >> 4) | ((x_ & 0x20) >> 2); })

#define RVC_EXTRACT_ADDI_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ >> 2) & 0x1f) | (RVC_IMM_SIGN(x_) << 5); })

#define RVC_EXTRACT_ADDI16SP_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ & 0x40) >> 2) | ((x_ & 0x4) << 3) | ((x_ & 0x20) << 1) | \
	((x_ & 0x18) << 4) | (RVC_IMM_SIGN(x_) << 9); })

#define RVC_EXTRACT_LDSP_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ & 0x1c) << 4) | ((x_ & 0x1000) >> 7) | ((x_ & 0x60) >> 2); })

#define RVC_EXTRACT_SDSP_IMM(x) \
	({typeof(x) x_ = (x); \
	((x_ & 0x1c00) >> 7) | ((x_ & 0x380) >> 1); })

enum {
	RV_CODE_UNDEFINE,
	RV_CODE_SP_ADDI,
	RV_CODE_SP_ADDI_TO_FP,
	RV_CODE_FP_ADDI_TO_SP,
	RV_CODE_SP_ANDI,
	RV_CODE_SP_HINT,
	RV_CODE_RA_FP_LOAD,
	RV_CODE_RA_FP_STORE,
	RV_CODE_BRANCH,
	RV_CODE_JUMP,
	RV_CODE_JUMP_INDIRECT,
	RV_CODE_CALL,
	RV_CODE_CALL_INDIRECT,
	RV_CODE_RETURN,
	RV_CODE_CONTEXT_SWITCH,
	RV_CODE_NOP,
	RV_CODE_EBREAK,
	RV_CODE_AUIPC,
	RV_CODE_ADDI_MV,
	RV_CODE_C_ADD,
};

struct insn {
	u8 len;
	u8 code;
	/*
	 * Special usage:
	 *
	 * auipc ==> rd
	 * mv    ==> rd
	 * add   ==> (rd << 8) | rs
	 * jr    ==> rs
	 * 
	 * jump table:   jr.rs == add.rd && add.rs/rd == mv.rd && mv auipc consecutive
	 * sibling call: jr.rs == auipc.rd && insns consecutive
	 */
	u16 reg;
	s32 imm;
};

static void insn_decode4(struct insn *ins, u32 code, 
					const struct section *sec, unsigned long offset)
{
	int rd, rs;
	struct symbol *func;

	/*
	 * All 0 code -- illegal instruction, might appeared as a placeholder
	 * for embedded data, or text section alignment fill-in.
	 * Treat it as nop to avoid "unreachable instruction" warning.
	 */
	if (code == 0) {
		ins->code = RV_CODE_NOP;
		return;
	}

	switch (code & __INSN_OPCODE_MASK) {
	/* mainly sp, fp op pattern: addi, andi */
	case RVG_OPCODE_OP_IMM:
		rd = RV_EXTRACT_RD_REG(code);
		rs = RV_EXTRACT_RS1_REG(code);
		ins->imm = RV_EXTRACT_ITYPE_IMM(code);
		if (RV_EXTRACT_FUNCT3(code) == RVG_FUNCT3_ADDI) {
			if (rd == CFI_SP && rs == CFI_SP) {
				ins->code = RV_CODE_SP_ADDI;
			} else if (rd == CFI_BP && rs == CFI_SP) {
				ins->code = RV_CODE_SP_ADDI_TO_FP;
			} else if (rd == CFI_SP && rs == CFI_BP) {
				ins->code = RV_CODE_FP_ADDI_TO_SP;
				func = find_func_containing((struct section *)sec, offset);
				if (func)
					func->frame_pointer = true;
				else
					WARN("%s:%lx decode: not found containing function",
											sec->name, offset);
			} else if (rd && rs && !ins->imm) {
				ins->code = RV_CODE_ADDI_MV;
				ins->reg = (rd << 8) | rs;
			} else if (!rd && !rs && !ins->imm) {
				ins->code = RV_CODE_NOP;
			} else if (rd == CFI_SP || rd == CFI_BP) {
				ins->code = RV_CODE_SP_HINT;
				ins->reg = rd;
			}
		} else if (RV_EXTRACT_FUNCT3(code) == RVG_FUNCT3_ANDI &&
					rd == CFI_SP && rs == CFI_SP) {
			/* stack alignment: and sp, sp, imm */
			ins->code = RV_CODE_SP_ANDI;
		} else if (rd == CFI_SP || rd == CFI_BP) {
			/* entry.S::handle_exception: srl sp,sp,0xe */
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;

	/* ra, fp store pattern: sd ra, imm(sp) */
	case RVG_OPCODE_STORE:
		rs = RV_EXTRACT_RS2_REG(code);
		if (RV_EXTRACT_FUNCT3(code) == RVG_FUNCT3_SD &&
			(rs == CFI_RA || rs == CFI_BP) &&
			RV_EXTRACT_RS1_REG(code) == CFI_SP) {
			ins->imm = RV_EXTRACT_STYPE_IMM(code);
			ins->code = RV_CODE_RA_FP_STORE;
			ins->reg = rs;
		}
		break;

	/* ra, fp load pattern: ld ra, imm(sp) */
	case RVG_OPCODE_LOAD:
		rd = RV_EXTRACT_RD_REG(code);
		if (RV_EXTRACT_FUNCT3(code) == RVG_FUNCT3_LD &&
			(rd == CFI_RA || rd == CFI_BP) &&
			RV_EXTRACT_RS1_REG(code) == CFI_SP) {
			ins->imm = RV_EXTRACT_ITYPE_IMM(code);
			ins->code = RV_CODE_RA_FP_LOAD;
			ins->reg =rd;
		} else if (rd == CFI_SP || rd == CFI_BP) {
			/* in context switch assembly: ld sp,16(a0) */
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;

	case RVG_OPCODE_BRANCH:
		ins->imm = RV_EXTRACT_BTYPE_IMM(code);
		ins->code = RV_CODE_BRANCH;
		break;

	/* direct jump/call */
	case RVG_OPCODE_JAL:
		ins->imm = RV_EXTRACT_JTYPE_IMM(code);
		if (RV_EXTRACT_RD_REG(code) == 0)
			ins->code = RV_CODE_JUMP;
		else
			ins->code = RV_CODE_CALL;
		break;

	/* indirect jump/call */
	case RVG_OPCODE_JALR:
		rd = RV_EXTRACT_RD_REG(code);
		rs = RV_EXTRACT_RS1_REG(code);
		ins->imm = RV_EXTRACT_ITYPE_IMM(code);
		if (rd == 0) {
			if ((ins->imm == 0) && (rs == CFI_RA)) {
				ins->code = RV_CODE_RETURN;
			} else {
				ins->code = RV_CODE_JUMP_INDIRECT;
				ins->reg = rs;
			}
		} else if (rd == CFI_RA) {
			ins->code = RV_CODE_CALL_INDIRECT;
		} else {
			WARN("%s:%lx decode: unknown jalr return", sec->name, offset);
		}
		break;

	/* auipc --  might associated with an indirect jump/call destination */
	case RVG_OPCODE_AUIPC:
		rd = RV_EXTRACT_RD_REG(code);
		ins->imm = RV_EXTRACT_UTYPE_IMM(code);
		if (rd && rd != CFI_SP) {
			ins->code = RV_CODE_AUIPC;
			ins->reg = rd;
		} else if (rd == CFI_SP || rd == CFI_BP) {
			/* head.S::_start_kernel: la sp, init_thread_union + THREAD_SIZE */
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;

	/* add rd, rs1, rs2  -- might be part of jump table pattern */
	case RVG_OPCODE_OP:
		rd = RV_EXTRACT_RD_REG(code);
		rs = RV_EXTRACT_RS2_REG(code);
		if (RV_EXTRACT_FUNCT3(code) == RVG_FUNCT3_ADD &&
			RV_EXTRACT_FUNCT7(code) == RVG_FUNCT7_ADD &&
			rd && rd != CFI_SP && rs != 0) {
			ins->code = RV_CODE_C_ADD;
			ins->reg = (rd << 8) | rs;
		} else if (rd == CFI_SP) {
			/*
			 * entry.S::call_on_irq_stack: add sp,t0,t1
			 * traps.c::do_trap_ecall_u: sub sp,sp,a5
			 */
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;
	
	/* ignore ecall as we don't care/know other privilege spaces */
	case RVG_OPCODE_SYSTEM:
		if (riscv_insn_is_sret(code))
			ins->code = RV_CODE_CONTEXT_SWITCH;
		else if (RV_EXTRACT_FUNCT7(code) == RVG_FUNCT7_EBREAK)
			ins->code = RV_CODE_EBREAK;
		break;

	case RVG_OPCODE_OP_IMM_32:
	case RVG_OPCODE_LUI:
	case RVG_OPCODE_OP_32:
		rd = RV_EXTRACT_RD_REG(code);
		if (rd == CFI_SP || rd == CFI_BP) {
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
	}
}

static void insn_decode2(struct insn *ins, u16 code, 
					const struct section *sec, unsigned long offset)
{
	int rd, rs, b12;

	if (code == 0) {
		ins->code = RV_CODE_NOP;
		return;
	}

	switch (RVC_EXTRACT_OPCODE(code)) {
	/* sp op pattern 1/2: c.addi sp, imm */
	case RVC_OPCODE_ADDI:
		rd = RVC_EXTRACT_CI_RD_REG(code);
		ins->imm = RVC_EXTRACT_ADDI_IMM(code);
		if (rd == CFI_SP && ins->imm)
			ins->code = RV_CODE_SP_ADDI;
		else if (rd == CFI_BP && ins->imm) {
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		} else if (rd == 0)
			ins->code = RV_CODE_NOP;
		break;

	/* sp op pattern 2/2: c.addi16sp */
	case RVC_OPCODE_ADDI16SP:
		if (RVC_EXTRACT_CI_RD_REG(code) == CFI_SP) {
			ins->imm = RVC_EXTRACT_ADDI16SP_IMM(code);
			ins->code = RV_CODE_SP_ADDI;
		}
		break;

	/* c.addi4spn fp, sp, imm */
	case RVC_OPCODE_ADDI4SPN:
		ins->imm = RVC_EXTRACT_ADDI4SPN_IMM(code);
		if (RVC_EXTRACT_C0_RD_REG(code) == CFI_BP && ins->imm)
			ins->code = RV_CODE_SP_ADDI_TO_FP;
		break;

	/* ra, fp store pattern: sd ra, imm(sp) */
	case RVC_OPCODE_SDSP:
		rs = RVC_EXTRACT_C2_RS2_REG(code);
		if (rs == CFI_RA || rs == CFI_BP) {
			ins->imm = RVC_EXTRACT_SDSP_IMM(code);
			ins->code = RV_CODE_RA_FP_STORE;
			ins->reg = rs;
		}
		break;

	/* ra, fp load pattern: ld ra, imm(sp) */
	case RVC_OPCODE_LDSP:
		rd = RVC_EXTRACT_C2_RS1_REG(code);
		if (rd == CFI_RA || rd == CFI_BP) {
			ins->imm = RVC_EXTRACT_LDSP_IMM(code);
			ins->code = RV_CODE_RA_FP_LOAD;
			ins->reg = rd;
		} else if (rd == CFI_SP) {
			/* entry.S::ret_from_exception: ld sp,16(sp) */
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;

	case RVC_OPCODE_BEQZ:
	case RVC_OPCODE_BNEZ:
		ins->imm = RVC_EXTRACT_BTYPE_IMM(code);
		ins->code = RV_CODE_BRANCH;
		break;
	
	/* direct jump */
	case RVC_OPCODE_J:
		ins->imm = RVC_EXTRACT_JTYPE_IMM(code);
		ins->code = RV_CODE_JUMP;
		break;
	
	/*
	 * indirect jump/call
	 * add rd, rs1, rs2  -- might be part of jump table pattern
	 */
	case RVC_OPCODE_JR:
		rd = RVC_EXTRACT_C2_RS1_REG(code);
		rs = RVC_EXTRACT_C2_RS2_REG(code);
		b12 = code & 0x1000;
		if (!b12 && rd && !rs) {	// c.jr
			if (rd == CFI_RA) {
				ins->code = RV_CODE_RETURN;
			} else {
				ins->code = RV_CODE_JUMP_INDIRECT;
				ins->reg = rd;
			}
		} else if (!b12 && rd && rs) {	// c.mv
			if (rd == CFI_SP || rd == CFI_BP) {
				ins->code = RV_CODE_SP_HINT;
				ins->reg = rd;
			}
		} else if (b12 && !rd && !rs) {	// c.ebreak
			ins->code = RV_CODE_EBREAK;
		} else if (b12 && rd && !rs) {	// c.jalr
			ins->code = RV_CODE_CALL_INDIRECT;
		} else if (b12 && rd && rs) {	// c.add
			if (rd != CFI_SP) {	// TODO: if rd==fp then fp is a scratch?
				ins->code = RV_CODE_C_ADD;
				ins->reg = (rd << 8) | rs;
			} else {
				/* entry.S::handle_kernel_stack_overflow: asm_per_cpu sp, overflow_stack, x31 */
				ins->code = RV_CODE_SP_HINT;
				ins->reg = rd;
			}
		}
		break;

	/* TODO: ld lui srli srai andi and or xor sub */
	case RVC_OPCODE_ADDIW:
	case RVC_OPCODE_LI:
	case RVC_OPCODE_SLLI:
	case RVC_OPCODE_LWSP:
		rd = RVC_EXTRACT_CI_RD_REG(code);
		if (rd == CFI_SP || rd == CFI_BP) {
			ins->code = RV_CODE_SP_HINT;
			ins->reg = rd;
		}
		break;
	}
}

static int insn_decode(struct insn *ins, const u32 *kaddr, 
					const struct section *sec, unsigned long offset)
{
	u32 code = *kaddr;

	ins->len = GET_INSN_LENGTH(code);
	ins->imm = 0;
	ins->code = RV_CODE_UNDEFINE;

	if (ins->len == 4)
		insn_decode4(ins, code, sec, offset);
	else
		insn_decode2(ins, code, sec, offset);

	return 0;
}

#define ADD_OP(op) \
	if (!(op = calloc(1, sizeof(*op)))) \
		return -1; \
	else for (*ops_list = op, ops_list = &op->next; op; op = NULL)

/*
 * Function general prologue and epilogue. They contain all the 7
 * CFI ops patterns.
 * no.
 * 	1	add sp, sp, -256
 * 	2	sd ra, 248(sp)
 * 		sd s0, 240(sp)
 * 	3	add s0, sp, 256
 * 	4	and sp, sp, -64
 * 		...
 * 	5	add sp, s0, -256
 * 	6	ld ra, 248(sp)
 * 		ld s0, 240(sp)
 * 		add sp, sp, 256
 * 		ret
 * 
 *  The 7th is the following RV_CODE_SP_HINT case. 
 */
int arch_decode_instruction(struct objtool_file *file, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    struct instruction *insn)
{
	struct stack_op **ops_list = &insn->stack_ops;
	struct insn ins;
	int ret;
	struct stack_op *op = NULL;
	struct instruction *tmp;
	struct reloc *text_reloc, *r;

	ret = insn_decode(&ins, sec->data->d_buf + offset, sec, offset);
	if (ret < 0) {
		WARN("can't decode instruction at %s:0x%lx", sec->name, offset);
		return -1;
	}
	
	insn->len = ins.len;
	insn->immediate = ins.imm;

	switch (ins.code) {
	case RV_CODE_SP_ADDI:
		ADD_OP(op) {
			op->src.type = OP_SRC_ADD;
			op->src.reg = CFI_SP;
			op->src.offset = ins.imm;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = CFI_SP;
		}
		insn->type = INSN_OTHER;
		break;

	case RV_CODE_SP_ADDI_TO_FP:
		ADD_OP(op) {
			op->src.type = OP_SRC_ADD;
			op->src.reg = CFI_SP;
			op->src.offset = ins.imm;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = CFI_BP;
		}
		insn->type = INSN_OTHER;
		break;

	case RV_CODE_FP_ADDI_TO_SP:
		ADD_OP(op) {
			op->src.type = OP_SRC_ADD;
			op->src.reg = CFI_BP;
			op->src.offset = ins.imm;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = CFI_SP;
		}
		insn->type = INSN_OTHER;
		break;

	case RV_CODE_SP_ANDI:
		ADD_OP(op) {
			op->src.type = OP_SRC_AND;
			op->src.reg = CFI_SP;
			op->src.offset = ins.imm;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = CFI_SP;
		}
		insn->type = INSN_OTHER;
		break;

	case RV_CODE_RA_FP_LOAD:
		ADD_OP(op) {
			op->src.type = OP_SRC_REG_INDIRECT;
			op->src.reg = CFI_SP;
			op->src.offset = ins.imm;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = ins.reg;
		}
		insn->type = INSN_OTHER;
		break;

	case RV_CODE_RA_FP_STORE:
		ADD_OP(op) {
			op->src.type = OP_SRC_REG;
			op->src.reg = ins.reg;
			op->dest.type = OP_DEST_REG_INDIRECT;
			op->dest.reg = CFI_SP;
			op->dest.offset = ins.imm;
		}
		insn->type = INSN_OTHER;
		break;
	
	case RV_CODE_BRANCH:
		insn->type = INSN_JUMP_CONDITIONAL;
		break;

	case RV_CODE_JUMP:
		insn->type = INSN_JUMP_UNCONDITIONAL;
		break;

	case RV_CODE_JUMP_INDIRECT:
		insn->type = INSN_JUMP_DYNAMIC;
		insn->arch_data = ins.reg;
		break;

	case RV_CODE_CALL:
		insn->type = INSN_CALL;
		break;

	/*
	 * Part of `AUIPC+JALR` procedure call pair.
	 * Take over AUIPC info for dead_end detection later.
	 */
	case RV_CODE_CALL_INDIRECT:
		tmp = prev_insn_same_sec(file, insn);
		if (tmp && tmp->_call_dest) {
			insn->_call_dest = tmp->_call_dest;
			tmp->_call_dest = NULL;
		}
		insn->type = INSN_CALL_DYNAMIC;
		break;

	case RV_CODE_RETURN:
		insn->type = INSN_RETURN;
		break;

	case RV_CODE_CONTEXT_SWITCH:
		insn->type = INSN_CONTEXT_SWITCH;
		break;

	case RV_CODE_NOP:
		insn->type = INSN_NOP;
		break;

	case RV_CODE_EBREAK:
		insn->type = INSN_TRAP;
		break;

	case RV_CODE_AUIPC:
		text_reloc = find_reloc_by_dest(file->elf, insn->sec, insn->offset);
		if (text_reloc) {
			if (text_reloc->sym->sec->rodata) {
				/* Later we use the AUIPC insn to find jump table. */
				insn->_jump_table = (struct reloc *)insn;
				insn->arch_data = ins.reg;
			} else if (text_reloc->sym->type == STT_FUNC ||
						text_reloc->sym->type == STT_NOTYPE) {
				insn->_call_dest = text_reloc->sym;
			}
		}
		insn->type = INSN_OTHER;
		break;

	/*
	 * Maybe part of switch jump table pattern:
	 *   auipc rs, 0x0		R_RISCV_PCREL_HI20
	 *   mv rd, rs			R_RISCV_PCREL_LO12_I
	 *
	 * Take over AUIPC info for find_jump_table later.
	 */
	case RV_CODE_ADDI_MV:
		text_reloc = find_reloc_by_dest(file->elf, insn->sec, insn->offset);
		if (text_reloc && reloc_type(text_reloc) == R_RISCV_PCREL_LO12_I) {
			tmp = prev_insn_same_sec(file, insn);
			if (tmp && tmp->arch_data) {
				/* hi20.r_offset == lo12.symbol.st_value */
				r = find_reloc_by_dest(file->elf, tmp->sec, tmp->offset);
				if (r && reloc_offset(r) == text_reloc->sym->offset &&
					(ins.reg & 0xff) == tmp->arch_data) {
					insn->_jump_table = tmp->_jump_table;
					insn->arch_data = (ins.reg >> 8) & 0xff;
					tmp->_jump_table = NULL;
					tmp->arch_data = 0;
				}
			}
		}
		insn->type = INSN_OTHER;
		break;

	/*
	 * Maybe part of switch jump table pattern.
	 * Record for find_jump_table later.
	 */
	case RV_CODE_C_ADD:
		insn->arch_data = ins.reg;
		insn->type = INSN_OTHER;
		break;

	/*
	 * Unusual SP/FP operations. If SP/FP is the current CFI
	 * base register, then enforce next instruction must have
	 * manually annotated hints, otherwise objtool would
	 * warn. Thus we can capture unexpected CFI ops pattern.
	 */
	case RV_CODE_SP_HINT:
		ADD_OP(op) {
			op->src.type = OP_SRC_ADD;
			op->src.reg = CFI_RA;// must not be SP or BP
			op->dest.type = OP_DEST_REG;
			op->dest.reg = ins.reg;
		}
		insn->type = INSN_OTHER;
		break;

	default:
		insn->type = INSN_OTHER;
		break;
	}

	return 0;
}

void arch_initial_func_cfi_state(struct cfi_init_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (Canonical Frame Address) */
	state->cfa.base = CFI_SP;
	state->cfa.offset = 0;

	/* initial RA (return address) not in stack at func entry */
}

const char *arch_nop_insn(int len)
{
	static const char nops[2][4] = {
		{ 0x13, 0x00, 0x00, 0x00 },	/* nop */
		{ 0x01, 0x00 },				/* c.nop */
	};

	if ((len != 2) && (len != 4)) {
		WARN("invalid NOP size: %d\n", len);
		return NULL;
	}

	return (len == 4) ? nops[0] : nops[1];
}

const char *arch_ret_insn(int len)
{
	static const char ret[2][4] = {
		{ 0x67, 0x80, 0x00, 0x00 },	/* jalr x0, 0(x1) */
		{ 0x82, 0x80 },				/* c.jr x0, 0(x1) */
	};

	if ((len != 2) && (len != 4)) {
		WARN("invalid RET size: %d\n", len);
		return NULL;
	}

	return (len == 4) ? ret[0] : ret[1];
}

int arch_decode_hint_reg(u8 sp_reg, int *base)
{
	switch (sp_reg) {
	case ORC_REG_UNDEFINED:
		*base = CFI_UNDEFINED;
		break;
	case ORC_REG_SP:
		*base = CFI_SP;
		break;
	case ORC_REG_BP:
		*base = CFI_BP;
		break;
	default:
		return -1;
	}

	return 0;
}
