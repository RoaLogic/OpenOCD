/***************************************************************************
 *   Copyright (C) 2021 by Richard Herveille                               *
 *   richard.herveille@roalogic.com                                        *
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

/* Debug Register Access Groups Start Addresses 
 * INTERNAL = Debug Unit internal registers
 * GPRS = INR_RF, FP_RF, NPC, PPC
 * CSRS = RISC-V State CSRs
 * */
#define GROUP_INTERNAL	(0 << 12)
#define GROUP_GPRS	(1 << 12)
#define GROUP_CSRS	(2 << 12)

/* Integer Register File
 * Floating Point Register File
 * NPC
 * PPC
 */ 
#define GROUP_INT_RF	(GROUP_GPRS +        0)
#define GROUP_FP_RF	(GROUP_GPRS + (1 << 8))
#define GROUP_PC	(GROUP_GRPS + (1 << 9))


/* RVL registers */
enum rvl_reg_nums {
	RVL_REG_X0 = 0,
	RVL_REG_X1,
	RVL_REG_X2,
	RVL_REG_X3,
	RVL_REG_X4,
	RVL_REG_X5,
	RVL_REG_X6,
	RVL_REG_X7,
	RVL_REG_X8,
	RVL_REG_X9,
	RVL_REG_X10,
	RVL_REG_X11,
	RVL_REG_X12,
	RVL_REG_X13,
	RVL_REG_X14,
	RVL_REG_X15,
	RVL_REG_X16,
	RVL_REG_X17,
	RVL_REG_X18,
	RVL_REG_X19,
	RVL_REG_X20,
	RVL_REG_X21,
	RVL_REG_X22,
	RVL_REG_X23,
	RVL_REG_X24,
	RVL_REG_X25,
	RVL_REG_X26,
	RVL_REG_X27,
	RVL_REG_X28,
	RVL_REG_X29,
	RVL_REG_X30,
	RVL_REG_X31,
	RVL_REG_PPC,
	RVL_REG_NPC,
	RVLNUMCOREREGS
};

struct rvl_jtag {
	struct jtag_tap *tap;
	int rvl_jtag_inited;
	int rvl_jtag_module_selected;
	uint8_t *current_reg_idx;
	struct rl_tap_ip *tap_ip;
	struct rvl_du *du_core;
	struct target *target;
};

struct rvl_common {
	struct rvl_jtag jtag;
	struct reg_cache *core_cache;
	uint32_t core_regs[RVLNUMCOREREGS];
	int nb_regs;
	struct rvl_core_reg *arch_info;
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
	RVL_DEBUG_REG_BPDATA2,
	RVL_DEBUG_REG_BPCTRL3,
	RVL_DEBUG_REG_BPDATA3,
	RVL_DEBUG_REG_BPCTRL4,
	RVL_DEBUG_REG_BPDATA4
};

#define NO_SINGLE_STEP		0
#define SINGLE_STEP		1

/* OR1K Debug registers and bits needed for resuming */
#define OR1K_DEBUG_REG_BASE	GROUP6                     /* Debug registers Base address */
#define OR1K_DMR1_CPU_REG_ADD	(OR1K_DEBUG_REG_BASE + 16) /* Debug Mode Register 1 0x3010 */
#define OR1K_DMR1_ST		0x00400000                 /* Single-step trace */
#define OR1K_DMR1_BT		0x00800000                 /* Branch trace */
#define OR1K_DMR2_WGB		0x003ff000                 /* Watchpoints generating breakpoint */
#define OR1K_DSR_TE		0x00002000                 /* Trap exception */

#endif /* OPENOCD_TARGET_ROALOGIC_RVL_H */
