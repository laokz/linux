/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _OBJTOOL_CFI_REGS_H
#define _OBJTOOL_CFI_REGS_H

/* CFI related registers */
#define CFI_RA		1
#define CFI_SP		2
/* Use BP as FP name to be in line with objtool */
#define CFI_BP		8
/* others unused */
#define CFI_NUM_REGS	9

#endif /* _OBJTOOL_CFI_REGS_H */
