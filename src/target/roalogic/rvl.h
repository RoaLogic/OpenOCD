/***************************************************************************
 *   Copyright (C) 2021 by Richard Herveille                               *
 *   richard.herveille@roalogic.com                                        *
 *                                                                         *
 *   Copyright (C) 2021 by Bjorn Schouteten                                *
 *   bjorn.schouteten@roalogic.com                                         *
 *                                                                         * 
 *   Based on the OR1K version                                             *
 *                                                                         *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifndef OPENOCD_TARGET_ROALOGIC_RVL_H
#define OPENOCD_TARGET_ROALOGIC_RVL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <target/target.h>
#include <target/riscv/encoding.h>

/* Debug Register Access Groups Start Addresses 
 * INTERNAL = Debug Unit internal registers
 * GPRS = INR_RF, FP_RF, NPC, PPC
 * CSRS = RISC-V State CSRs
 * */
#define GROUP_DBG	(0 << 12)
#define GROUP_GPRS	(1 << 12)
#define GROUP_CSR 	(2 << 12)

/* Integer Register File
 * Floating Point Register File
 * NPC
 * PPC
 */ 
#define GROUP_RF	(GROUP_GPRS +        0)
#define GROUP_FPRF	(GROUP_GPRS + (1 << 8))


/* RVL registers */
/* gdb's register list is defined in riscv_gdb_reg_names gdb/riscv-tdep.c in
 * its source tree. We must interpret the numbers the same here. */
enum gdb_regno {
	GDB_REGNO_ZERO = 0,        /* Read-only register, always 0.  */
	GDB_REGNO_RA = 1,          /* Return Address.  */
	GDB_REGNO_SP = 2,          /* Stack Pointer.  */
	GDB_REGNO_GP = 3,          /* Global Pointer.  */
	GDB_REGNO_TP = 4,          /* Thread Pointer.  */
	GDB_REGNO_T0,
	GDB_REGNO_T1,
	GDB_REGNO_T2,
	GDB_REGNO_S0 = 8,
	GDB_REGNO_FP = 8,          /* Frame Pointer.  */
	GDB_REGNO_S1,
	GDB_REGNO_A0 = 10,         /* First argument.  */
	GDB_REGNO_A1 = 11,         /* Second argument.  */
	GDB_REGNO_A2,
	GDB_REGNO_A3,
	GDB_REGNO_A4,
	GDB_REGNO_A5,
	GDB_REGNO_XPR15 = GDB_REGNO_A5,
	GDB_REGNO_A6,
	GDB_REGNO_A7,
	GDB_REGNO_S2,
	GDB_REGNO_S3,
	GDB_REGNO_S4,
	GDB_REGNO_S5,
	GDB_REGNO_S6,
	GDB_REGNO_S7,
	GDB_REGNO_S8,
	GDB_REGNO_S9,
	GDB_REGNO_S10,
	GDB_REGNO_S11,
	GDB_REGNO_T3,
	GDB_REGNO_T4,
	GDB_REGNO_T5,
	GDB_REGNO_T6,
	GDB_REGNO_XPR31 = GDB_REGNO_T6,

	GDB_REGNO_PC = 32,
	GDB_REGNO_FPR0 = 33,
	GDB_REGNO_FT0 = GDB_REGNO_FPR0,
	GDB_REGNO_FT1,
	GDB_REGNO_FT2,
	GDB_REGNO_FT3,
	GDB_REGNO_FT4,
	GDB_REGNO_FT5,
	GDB_REGNO_FT6,
	GDB_REGNO_FT7,
	GDB_REGNO_FS0,
	GDB_REGNO_FS1,
	GDB_REGNO_FA0,
	GDB_REGNO_FA1,
	GDB_REGNO_FA2,
	GDB_REGNO_FA3,
	GDB_REGNO_FA4,
	GDB_REGNO_FA5,
	GDB_REGNO_FA6,
	GDB_REGNO_FA7,
	GDB_REGNO_FS2,
	GDB_REGNO_FS3,
	GDB_REGNO_FS4,
	GDB_REGNO_FS5,
	GDB_REGNO_FS6,
	GDB_REGNO_FS7,
	GDB_REGNO_FS8,
	GDB_REGNO_FS9,
	GDB_REGNO_FS10,
	GDB_REGNO_FS11,
	GDB_REGNO_FT8,
	GDB_REGNO_FT9,
	GDB_REGNO_FT10,
	GDB_REGNO_FT11,
	GDB_REGNO_FPR31 = GDB_REGNO_FT11,
	GDB_REGNO_CSR0 = 65,
	GDB_REGNO_VSTART = CSR_VSTART + GDB_REGNO_CSR0,
	GDB_REGNO_VXSAT = CSR_VXSAT + GDB_REGNO_CSR0,
	GDB_REGNO_VXRM = CSR_VXRM + GDB_REGNO_CSR0,
	GDB_REGNO_VLENB = CSR_VLENB + GDB_REGNO_CSR0,
	GDB_REGNO_VL = CSR_VL + GDB_REGNO_CSR0,
	GDB_REGNO_VTYPE = CSR_VTYPE + GDB_REGNO_CSR0,
	GDB_REGNO_TSELECT = CSR_TSELECT + GDB_REGNO_CSR0,
	GDB_REGNO_TDATA1 = CSR_TDATA1 + GDB_REGNO_CSR0,
	GDB_REGNO_TDATA2 = CSR_TDATA2 + GDB_REGNO_CSR0,
	GDB_REGNO_MISA = CSR_MISA + GDB_REGNO_CSR0,
	GDB_REGNO_DPC = CSR_DPC + GDB_REGNO_CSR0,
	GDB_REGNO_DCSR = CSR_DCSR + GDB_REGNO_CSR0,
	GDB_REGNO_DSCRATCH0 = CSR_DSCRATCH0 + GDB_REGNO_CSR0,
	GDB_REGNO_MSTATUS = CSR_MSTATUS + GDB_REGNO_CSR0,
	GDB_REGNO_MEPC = CSR_MEPC + GDB_REGNO_CSR0,
	GDB_REGNO_MCAUSE = CSR_MCAUSE + GDB_REGNO_CSR0,
	GDB_REGNO_SATP = CSR_SATP + GDB_REGNO_CSR0,
	GDB_REGNO_CSR4095 = GDB_REGNO_CSR0 + 4095,
	GDB_REGNO_PRIV = 4161,
	/* It's still undecided what register numbers GDB will actually use for
	 * these. See
	 * https://groups.google.com/a/groups.riscv.org/d/msg/sw-dev/7lQYiTUN9Ms/gTxGhzaYBQAJ
	 */
	GDB_REGNO_V0, GDB_REGNO_V1, GDB_REGNO_V2, GDB_REGNO_V3,
	GDB_REGNO_V4, GDB_REGNO_V5, GDB_REGNO_V6, GDB_REGNO_V7,
	GDB_REGNO_V8, GDB_REGNO_V9, GDB_REGNO_V10, GDB_REGNO_V11,
	GDB_REGNO_V12, GDB_REGNO_V13, GDB_REGNO_V14, GDB_REGNO_V15,
	GDB_REGNO_V16, GDB_REGNO_V17, GDB_REGNO_V18, GDB_REGNO_V19,
	GDB_REGNO_V20, GDB_REGNO_V21, GDB_REGNO_V22, GDB_REGNO_V23,
	GDB_REGNO_V24, GDB_REGNO_V25, GDB_REGNO_V26, GDB_REGNO_V27,
	GDB_REGNO_V28, GDB_REGNO_V29, GDB_REGNO_V30, GDB_REGNO_V31,
	GDB_REGNO_COUNT
};

const char *gdb_regno_name(enum gdb_regno regno);


struct rl_jtag {
	struct  jtag_tap *tap;
	int     rl_jtag_inited;
	int     rl_jtag_module_selected;
	int     rl_jtag_cpu_selected;
	int     rl_jtag_address_size;
	uint8_t *current_reg_idx;
	struct  rl_tap_ip *tap_ip;
	struct  rl_du *du_core;
	struct  target *target;
};


struct rvl_common {
	struct   rl_jtag jtag;
	struct   reg_cache *core_cache;
	uint32_t core_regs[GDB_REGNO_COUNT];
	int      nb_regs;
	struct   rvl_core_reg *arch_info;
};

static inline struct rvl_common *
target_to_rvl(struct target *target)
{
	return (struct rvl_common *)target->arch_info;
}

struct rvl_core_reg {
	const char *name;
	uint32_t list_num;   /* Index in register cache */
	uint32_t spr_num;    /* Number in architecture's SPR space */
	struct target *target;
	struct rvl_common *rvl_common;
	const char *feature; /* feature name in XML tdesc file */
	const char *group;   /* register group in XML tdesc file */
};

struct rvl_core_reg_init {
	const char *name;
	uint32_t spr_num;    /* Number in architecture's SPR space */
	const char *feature; /* feature name in XML tdesc file */
	const char *group;   /* register group in XML tdesc file */
};

/* RISC-V EBREAK instruction */
#define RV_EBREAK_INSTR  0x00100073
#define RV_EBREAK16_INSTR 0x9002

enum rvl_debug_reg_nums {
	RVL_DEBUG_REG_CTRL = 0,
	RVL_DEBUG_REG_HIT,
	RVL_DEBUG_REG_IE,
	RVL_DEBUG_REG_CAUSE,
	RVL_DEBUG_REG_BPCTRL0 = 0x10,
	RVL_DEBUG_REG_BPDATA0,
	RVL_DEBUG_REG_BPCTRL1,
	RVL_DEBUG_REG_BPDATA1,
	RVL_DEBUG_REG_BPCTRL2,
	RVL_DEBUG_REG_BPDATA2
};

#define RVL_JTAG_DBG_REGS 10

#define NO_SINGLE_STEP		0
#define SINGLE_STEP		1


// DBG CTRL
//Bit definitions
#define DBG_CTRL_SINGLE_STEP_TRACE	0x01       /* Enable single-step trace                        */
#define DBG_CTRL_BRANCH_TRACE		0x02       /* Enable branch-trace                             */

//#define DBG_HIT_SINGLE_STEP		0x01       /* Single-Step caused breakpoint                   */
//#define DBG_HIT_BRANCH			0x02       /* Branch-trace caused breakpoint                  */
//#define DBG_HIT_BP(N)			(0x10 <<N) /* BreakPoint(n) caused breakpoint             */
//#define DBG_HIT_MASK			0xFF3      /* Masks all HIT bits                              */
//#define DBG_HIT_BP_MASK			0xFF0      /* Masks all BP HIT bits                           */

//#define DBG_BPCTRL_IMPLEMENTED		0x01
//#define DBG_BPCTRL_ENABLED		0x02
//#define DBG_BPCTRL_CC_INST_FETCH	(0x0 << 4)
//#define DBG_BPCTRL_CC_LD_ADR 		(0x1 << 4)
//#define DBG_BPCTRL_CC_ST_ADR		(0x2 << 4)
//#define DBG_BPCTRL_CC_LDST_ADR		(0x3 << 4)
//#define DBG_BPCTRL_CC_MASK              (0x7 << 4)

#define DBG_CSR_MSTASUS_MIE         0x08

#define DBG_IE_INST_MISALIGNED		0x00001
#define DBG_IE_INST_ACCESS_FAULT	0x00002
#define DBG_IE_ILLEGAL			0x00004
#define DBG_IE_BREAKPOINT		0x00008
#define DBG_IE_LOAD_MISALIGNED		0x00010
#define DBG_IE_LOAD_ACCESS_FAULT	0x00020
#define DBG_IE_AMO_MISALIGNED		0x00040
#define DBG_IE_STORE_ACCESS_FAULT	0x00080
#define DBG_IE_UMODE_ECALL		0x00100
#define DBG_IE_SMODE_ECALL		0x00200
#define DBG_IE_HMODE_ECALL		0x00400
#define DBG_IE_MMODE_ECALL		0x00800
#define DBG_IE_SOFTWARE_INT		0x10000
#define DBG_IE_TIMER_INT		0x20000
#define DBG_IE_UART			0x40000


#endif /* OPENOCD_TARGET_ROALOGIC_RVL_H */
