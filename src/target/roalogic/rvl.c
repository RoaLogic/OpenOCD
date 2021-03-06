/***************************************************************************
 *   Copyright (C) 2021 by Richard Herveille                               *
 *   richard.herveille@roalogic.com                                        *
 *                                                                         *
 *   Copyright (C) 2021 by Bjorn Schouteten                                *
 *   bjorn.schouteten@roalogic.com                                         *
 *                                                                         * 
 *   Based on OR1K version                                                 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/register.h>
#include <target/target.h>
#include <target/breakpoints.h>
#include <target/target_type.h>
#include <helper/time_support.h>
#include <helper/fileio.h>
#include "rl_tap.h"
#include "rvl.h"
#include "rl_dbg_adv.h"



LIST_HEAD(rl_tap_list);
LIST_HEAD(rl_du_list);

static int rvl_remove_breakpoint(struct target *target,
			         struct breakpoint *breakpoint);

static int rvl_read_core_reg(struct target *target, int num);
static int rvl_write_core_reg(struct target *target, int num);

static struct rvl_core_reg *rvl_core_reg_list_arch_info;

/* Combination of RISC-V and RVL names
 * until RVL uses RISC-V debug spec */
static const struct rvl_core_reg_init rvl_init_reg_list[] = {
	/* Integer Register File */
	{"zero",          GROUP_RF   +  0,             "org.gnu.gdb.riscv.cpu", NULL},
	{"ra",            GROUP_RF   +  1,             "org.gnu.gdb.riscv.cpu", NULL},
	{"sp",            GROUP_RF   +  2,             "org.gnu.gdb.riscv.cpu", NULL},
	{"gp",            GROUP_RF   +  3,             "org.gnu.gdb.riscv.cpu", NULL},
	{"tp",            GROUP_RF   +  4,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t0",            GROUP_RF   +  5,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t1",            GROUP_RF   +  6,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t2",            GROUP_RF   +  7,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s0",            GROUP_RF   +  8,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s1",            GROUP_RF   +  9,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a0",            GROUP_RF   + 10,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a1",            GROUP_RF   + 11,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a2",            GROUP_RF   + 12,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a3",            GROUP_RF   + 13,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a4",            GROUP_RF   + 14,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a5",            GROUP_RF   + 15,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a6",            GROUP_RF   + 16,             "org.gnu.gdb.riscv.cpu", NULL},
	{"a7",            GROUP_RF   + 17,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s2",            GROUP_RF   + 18,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s3",            GROUP_RF   + 19,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s4",            GROUP_RF   + 20,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s5",            GROUP_RF   + 21,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s6",            GROUP_RF   + 22,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s7",            GROUP_RF   + 23,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s8",            GROUP_RF   + 24,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s9",            GROUP_RF   + 25,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s10",           GROUP_RF   + 26,             "org.gnu.gdb.riscv.cpu", NULL},
	{"s11",           GROUP_RF   + 27,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t3",            GROUP_RF   + 28,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t4",            GROUP_RF   + 29,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t5",            GROUP_RF   + 30,             "org.gnu.gdb.riscv.cpu", NULL},
	{"t6",            GROUP_RF   + 31,             "org.gnu.gdb.riscv.cpu", NULL},


	/* PC */
        {"pc",            GROUP_GPRS + 0x201,          "org.gnu.gdb.rvl.dbg",   NULL},


	/* Floating Point Register File */
	

	/* CSRs */
        {"ustatus",       GROUP_CSR  + CSR_USTATUS,    "org.gnu.gdb.riscv.csr", NULL},
        {"uie",           GROUP_CSR  + CSR_UIE,        "org.gnu.gdb.riscv.csr", NULL},
        {"utvec",         GROUP_CSR  + CSR_UTVEC,      "org.gnu.gdb.riscv.csr", NULL},
        {"uscratch",      GROUP_CSR  + CSR_USCRATCH,   "org.gnu.gdb.riscv.csr", NULL},
        {"uepc",          GROUP_CSR  + CSR_UEPC,       "org.gnu.gdb.riscv.csr", NULL},
        {"ucause",        GROUP_CSR  + CSR_UCAUSE,     "org.gnu.gdb.riscv.csr", NULL},
        {"utval",         GROUP_CSR  + CSR_UTVAL,      "org.gnu.gdb.riscv.csr", NULL},
        {"uip",           GROUP_CSR  + CSR_UIP,        "org.gnu.gdb.riscv.csr", NULL},
        {"fflags",        GROUP_CSR  + CSR_FFLAGS,     "org.gnu.gdb.riscv.csr", NULL},
        {"frm",           GROUP_CSR  + CSR_FRM,        "org.gnu.gdb.riscv.csr", NULL},
        {"fcsr",          GROUP_CSR  + CSR_FCSR,       "org.gnu.gdb.riscv.csr", NULL},
        {"cycle",         GROUP_CSR  + CSR_CYCLE,      "org.gnu.gdb.riscv.csr", NULL},
        {"time",          GROUP_CSR  + CSR_TIME,       "org.gnu.gdb.riscv.csr", NULL},
        {"instret",       GROUP_CSR  + CSR_INSTRET,    "org.gnu.gdb.riscv.csr", NULL},
        {"cycleh",        GROUP_CSR  + CSR_CYCLEH,     "org.gnu.gdb.riscv.csr", NULL},
        {"timeh",         GROUP_CSR  + CSR_TIMEH,      "org.gnu.gdb.riscv.csr", NULL},
        {"instreth",      GROUP_CSR  + CSR_INSTRETH,   "org.gnu.gdb.riscv.csr", NULL},

        {"sstatus",       GROUP_CSR  + CSR_SSTATUS,    "org.gnu.gdb.riscv.csr", NULL},
        {"sedeleg",       GROUP_CSR  + CSR_SEDELEG,    "org.gnu.gdb.riscv.csr", NULL},
        {"sideleg",       GROUP_CSR  + CSR_SIDELEG,    "org.gnu.gdb.riscv.csr", NULL},
        {"sie",           GROUP_CSR  + CSR_SIE,        "org.gnu.gdb.riscv.csr", NULL},
        {"stvec",         GROUP_CSR  + CSR_STVEC,      "org.gnu.gdb.riscv.csr", NULL},
        {"scounteren",    GROUP_CSR  + CSR_SCOUNTEREN, "org.gnu.gdb.riscv.csr", NULL},
        {"sscratch",      GROUP_CSR  + CSR_SSCRATCH,   "org.gnu.gdb.riscv.csr", NULL},
        {"sepc",          GROUP_CSR  + CSR_SEPC,       "org.gnu.gdb.riscv.csr", NULL},
        {"scause",        GROUP_CSR  + CSR_SCAUSE,     "org.gnu.gdb.riscv.csr", NULL},
        {"stval",         GROUP_CSR  + CSR_STVAL,      "org.gnu.gdb.riscv.csr", NULL},
        {"sip",           GROUP_CSR  + CSR_SIP,        "org.gnu.gdb.riscv.csr", NULL},
        {"satp",          GROUP_CSR  + CSR_SATP,       "org.gnu.gdb.riscv.csr", NULL},

        {"mvendorid",     GROUP_CSR  + CSR_MVENDORID,  "org.gnu.gdb.riscv.csr", NULL},
        {"marchid",       GROUP_CSR  + CSR_MARCHID,    "org.gnu.gdb.riscv.csr", NULL},
        {"mimpid",        GROUP_CSR  + CSR_MIMPID,     "org.gnu.gdb.riscv.csr", NULL},
        {"mhartid",       GROUP_CSR  + CSR_MHARTID,    "org.gnu.gdb.riscv.csr", NULL},
        {"mstatus",       GROUP_CSR  + CSR_MSTATUS,    "org.gnu.gdb.riscv.csr", NULL},
        {"misa",          GROUP_CSR  + CSR_MISA,       "org.gnu.gdb.riscv.csr", NULL},
        {"medeleg",       GROUP_CSR  + CSR_MEDELEG,    "org.gnu.gdb.riscv.csr", NULL},
        {"mideleg",       GROUP_CSR  + CSR_MIDELEG,    "org.gnu.gdb.riscv.csr", NULL},
        {"mie",           GROUP_CSR  + CSR_MIE,        "org.gnu.gdb.riscv.csr", NULL},
        {"mnmivec",       GROUP_CSR  + CSR_MNMIVEC,    "org.gnu.gdb.riscv.csr", NULL},
        {"mtvec",         GROUP_CSR  + CSR_MTVEC,      "org.gnu.gdb.riscv.csr", NULL},
        {"mcounteren",    GROUP_CSR  + CSR_MCOUNTEREN, "org.gnu.gdb.riscv.csr", NULL},
        {"mscratch",      GROUP_CSR  + CSR_MSCRATCH,   "org.gnu.gdb.riscv.csr", NULL},
        {"mepc",          GROUP_CSR  + CSR_MEPC,       "org.gnu.gdb.riscv.csr", NULL},
        {"mcause",        GROUP_CSR  + CSR_MCAUSE,     "org.gnu.gdb.riscv.csr", NULL},
        {"mtval",         GROUP_CSR  + CSR_MTVAL,      "org.gnu.gdb.riscv.csr", NULL},
        {"mip",           GROUP_CSR  + CSR_MIP,        "org.gnu.gdb.riscv.csr", NULL},

        {"pmpcfg0",       GROUP_CSR  + CSR_PMPCFG0,    "org.gnu.gdb.riscv.csr", NULL},
        {"pmpcfg1",       GROUP_CSR  + CSR_PMPCFG1,    "org.gnu.gdb.riscv.csr", NULL},
        {"pmpcfg2",       GROUP_CSR  + CSR_PMPCFG2,    "org.gnu.gdb.riscv.csr", NULL},
        {"pmpcfg3",       GROUP_CSR  + CSR_PMPCFG3,    "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr0",       GROUP_CSR  + CSR_PMPADDR0,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr1",       GROUP_CSR  + CSR_PMPADDR1,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr2",       GROUP_CSR  + CSR_PMPADDR2,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr3",       GROUP_CSR  + CSR_PMPADDR3,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr4",       GROUP_CSR  + CSR_PMPADDR4,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr5",       GROUP_CSR  + CSR_PMPADDR5,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr6",       GROUP_CSR  + CSR_PMPADDR6,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr7",       GROUP_CSR  + CSR_PMPADDR7,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr8",       GROUP_CSR  + CSR_PMPADDR8,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr9",       GROUP_CSR  + CSR_PMPADDR9,   "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr10",      GROUP_CSR  + CSR_PMPADDR10,  "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr11",      GROUP_CSR  + CSR_PMPADDR11,  "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr12",      GROUP_CSR  + CSR_PMPADDR12,  "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr13",      GROUP_CSR  + CSR_PMPADDR13,  "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr14",      GROUP_CSR  + CSR_PMPADDR14,  "org.gnu.gdb.riscv.csr", NULL},
        {"pmpadr15",      GROUP_CSR  + CSR_PMPADDR15,  "org.gnu.gdb.riscv.csr", NULL},

        {"mcycle",        GROUP_CSR  + CSR_MCYCLE,     "org.gnu.gdb.riscv.csr", NULL},
        {"minstret",      GROUP_CSR  + CSR_MINSTRET,   "org.gnu.gdb.riscv.csr", NULL},
        {"mcycleh",       GROUP_CSR  + CSR_MCYCLEH,    "org.gnu.gdb.riscv.csr", NULL},
        {"minstreth",     GROUP_CSR  + CSR_MINSTRETH,  "org.gnu.gdb.riscv.csr", NULL},


	/* Debug Unit Internals */
	{"npc",           GROUP_GPRS + 0x200,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbgctrl",       GROUP_DBG  +  0x00,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbghit",        GROUP_DBG  +  0x01,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbgie",         GROUP_DBG  +  0x02,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbgcause",      GROUP_DBG  +  0x03,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbg.bpctrl0",   GROUP_DBG  +  0x10,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbg.bpdata0",   GROUP_DBG  +  0x11,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbg.bpctrl1",   GROUP_DBG  +  0x12,          "org.gnu.gbd.rvl.dbg", NULL},
	{"dbg.bpdata1",   GROUP_DBG  +  0x13,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbg.bpctrl2",   GROUP_DBG  +  0x14,          "org.gnu.gdb.rvl.dbg", NULL},
	{"dbg.bpdata2",   GROUP_DBG  +  0x15,          "org.gnu.gdb.rvl.dbg", NULL},
};

static int rvl_add_reg(struct target *target, struct rvl_core_reg *new_reg)
{
	struct rvl_common *rvl = target_to_rvl(target);
	int reg_list_size = rvl->nb_regs * sizeof(struct rvl_core_reg);

	rvl_core_reg_list_arch_info = realloc(rvl_core_reg_list_arch_info,
				reg_list_size + sizeof(struct rvl_core_reg));

	memcpy(&rvl_core_reg_list_arch_info[rvl->nb_regs], new_reg,
		sizeof(struct rvl_core_reg));

	rvl_core_reg_list_arch_info[rvl->nb_regs].list_num = rvl->nb_regs;

	rvl->nb_regs++;

	return ERROR_OK;
}

static int rvl_create_reg_list(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);

	LOG_DEBUG("-");

	rvl_core_reg_list_arch_info = malloc(ARRAY_SIZE(rvl_init_reg_list) *
				       sizeof(struct rvl_core_reg));

	for (int i = 0; i < (int)ARRAY_SIZE(rvl_init_reg_list); i++) {
		rvl_core_reg_list_arch_info[i].name        = rvl_init_reg_list[i].name;
		rvl_core_reg_list_arch_info[i].spr_num     = rvl_init_reg_list[i].spr_num;
		rvl_core_reg_list_arch_info[i].group       = rvl_init_reg_list[i].group;
		rvl_core_reg_list_arch_info[i].feature     = rvl_init_reg_list[i].feature;
		rvl_core_reg_list_arch_info[i].list_num    = i;
		rvl_core_reg_list_arch_info[i].target      = NULL;
		rvl_core_reg_list_arch_info[i].rvl_common = NULL;
	}

	rvl->nb_regs = ARRAY_SIZE(rvl_init_reg_list);

	return ERROR_OK;
}

static int rvl_jtag_read_regs(struct rvl_common *rvl, uint32_t *regs)
{
	struct rl_du *du_core = rl_jtag_to_du(&rvl->jtag);

	LOG_DEBUG("-");

	return du_core->rl_jtag_read_cpu(&rvl->jtag,
			rvl->arch_info[GDB_REGNO_ZERO].spr_num, GDB_REGNO_XPR31 + 1,
			regs + GDB_REGNO_ZERO);
}

static int rvl_jtag_write_regs(struct rvl_common *rvl, uint32_t *regs)
{
	struct rl_du *du_core = rl_jtag_to_du(&rvl->jtag);

	LOG_DEBUG("-");

	return du_core->rl_jtag_write_cpu(&rvl->jtag,
			rvl->arch_info[GDB_REGNO_ZERO].spr_num, GDB_REGNO_XPR31 + 1,
			&regs[GDB_REGNO_ZERO]);
}

static int rvl_save_context(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	int regs_read = 0;
	int retval;

	LOG_DEBUG("-");

	for (int i = 0; i < GDB_REGNO_FPR0; i++) 
    	{
		if (!rvl->core_cache->reg_list[i].valid) 
		{
			// Read the PC for the PPC
			if (i == GDB_REGNO_PC) 
	    	{
				// Read the PPC register
				retval = du_core->rl_jtag_read_cpu(&rvl->jtag,
						(GROUP_GPRS + 0x201), 1,
						&rvl->core_regs[i]);

                LOG_DEBUG("Read PC: Value: %08x\n", rvl->core_regs[i]);
				if (retval != ERROR_OK)
					return retval;
			} 
            else if (!regs_read) 
            {
				/* read gpr registers at once (but only one time in this loop) */
				retval = rvl_jtag_read_regs(rvl, rvl->core_regs);
				if (retval != ERROR_OK)
					return retval;
				/* prevent next reads in this loop */
				regs_read = 1;
			}
			/* We've just updated the core_reg[i], now update
			   the core cache */
			rvl_read_core_reg(target, i);
		}
	}

	return ERROR_OK;
}

static int rvl_restore_context(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	int reg_write = 0;
	int retval;

	LOG_DEBUG("-");

	for (int i = 0; i < GDB_REGNO_FPR0; i++) 
    {
		if (rvl->core_cache->reg_list[i].dirty) 
        {
			rvl_write_core_reg(target, i);

			if (i == GDB_REGNO_PC) 
            {
				retval = du_core->rl_jtag_write_cpu(&rvl->jtag,
                        // Write the PC to the NPC reg
						(GROUP_GPRS + 0x200), 1,
						&rvl->core_regs[i]);
				if (retval != ERROR_OK) 
                {
					LOG_ERROR("Error while restoring context");
					return retval;
			    }
			} 
            else
				reg_write = 1;
		}
	}

	if (reg_write) 
    {
		/* read gpr registers at once (but only one time in this loop) */
		retval = rvl_jtag_write_regs(rvl, rvl->core_regs);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while restoring context");
			return retval;
		}
	}

	return ERROR_OK;
}

static int rvl_read_core_reg(struct target *target, int num)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	uint32_t reg_value;

	LOG_DEBUG("-");

	if ((num < 0) || (num >= rvl->nb_regs))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if ((num >= 0) && (num < GDB_REGNO_COUNT)) 
    {
		reg_value = rvl->core_regs[num];
		buf_set_u32(rvl->core_cache->reg_list[num].value, 0, 32, reg_value);
		LOG_DEBUG("Read core reg %i value 0x%08" PRIx32, num, reg_value);
		rvl->core_cache->reg_list[num].valid = true;
		rvl->core_cache->reg_list[num].dirty = false;
	} 
    else 
    {
		/* This is an spr, always read value from HW */
		int retval = du_core->rl_jtag_read_cpu(&rvl->jtag,
							 rvl->arch_info[num].spr_num, 1, &reg_value);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while reading spr 0x%08" PRIx32, rvl->arch_info[num].spr_num);
			return retval;
		}
		buf_set_u32(rvl->core_cache->reg_list[num].value, 0, 32, reg_value);
		LOG_DEBUG("Read spr reg %i value 0x%08" PRIx32, num, reg_value);
	}

	return ERROR_OK;
}

static int rvl_write_core_reg(struct target *target, int num)
{
	struct rvl_common *rvl = target_to_rvl(target);

	LOG_DEBUG("-");

	if ((num < 0) || (num >= GDB_REGNO_COUNT))
		return ERROR_COMMAND_SYNTAX_ERROR;

	uint32_t reg_value = buf_get_u32(rvl->core_cache->reg_list[num].value, 0, 32);
	rvl->core_regs[num] = reg_value;
	LOG_DEBUG("Write core reg %i value 0x%08" PRIx32, num, reg_value);
	rvl->core_cache->reg_list[num].valid = true;
	rvl->core_cache->reg_list[num].dirty = false;

	return ERROR_OK;
}

static int rvl_get_core_reg(struct reg *reg)
{
	struct rvl_core_reg *rvl_reg = reg->arch_info;
	struct target *target = rvl_reg->target;

	LOG_DEBUG("-");

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

    // First get the register before returning the values
    int retval = rvl_save_context(target);

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rvl_save_context");
		return retval;
	}

	return rvl_read_core_reg(target, rvl_reg->list_num);
}

static int rvl_set_core_reg(struct reg *reg, uint8_t *buf)
{
	struct rvl_core_reg *rvl_reg = reg->arch_info;
	struct target *target = rvl_reg->target;
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	uint32_t value = buf_get_u32(buf, 0, 32);

	LOG_DEBUG("-");
    LOG_DEBUG("Set core reg: %u, value: %08x\n", rvl_reg->list_num, value);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

    // If the register is lower then the Floating Point registers, write it to the cache
    // At the moment a continue or a step is provoked, it shall be written to the CPU
    if (rvl_reg->list_num < GDB_REGNO_FPR0) 
    {

        buf_set_u32(rvl->core_cache->reg_list[rvl_reg->list_num].value, 0, 32, value);
		rvl->core_cache->reg_list[rvl_reg->list_num].dirty = true;
		rvl->core_cache->reg_list[rvl_reg->list_num].valid = true;
	} 
    else 
    {
		/* Non cached register, so write to CPU immediately */
        int retval = du_core->rl_jtag_write_cpu(&rvl->jtag, rvl_reg->spr_num, 1, &value);
        
        if (retval != ERROR_OK) 
        {
            LOG_ERROR("Error while writing spr 0x%08" PRIx32, rvl_reg->spr_num);
            return retval;
        }
	}

	return ERROR_OK;
}

static const struct reg_arch_type rvl_reg_type = {
	.get = rvl_get_core_reg,
	.set = rvl_set_core_reg,
};

static struct reg_cache *rvl_build_reg_cache(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(rvl->nb_regs, sizeof(struct reg));
	struct rvl_core_reg *arch_info = malloc((rvl->nb_regs) * sizeof(struct rvl_core_reg));
	struct reg_feature *feature;

	LOG_DEBUG("-");

	/* Build the process context cache */
	cache->name = "Roa Logic RISC-V Registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = rvl->nb_regs;
	(*cache_p) = cache;
	rvl->core_cache = cache;
	rvl->arch_info = arch_info;

	for (int i = 0; i < rvl->nb_regs; i++) 
    {
		arch_info[i] = rvl_core_reg_list_arch_info[i];
		arch_info[i].target = target;
		arch_info[i].rvl_common = rvl;
		reg_list[i].name = rvl_core_reg_list_arch_info[i].name;

		feature = malloc(sizeof(struct reg_feature));
		feature->name = rvl_core_reg_list_arch_info[i].feature;
		reg_list[i].feature = feature;

		reg_list[i].group = rvl_core_reg_list_arch_info[i].group;
		reg_list[i].size = 32;
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = false;
		reg_list[i].valid = false;
		reg_list[i].type = &rvl_reg_type;
		reg_list[i].arch_info = &arch_info[i];
		reg_list[i].number = i;
		reg_list[i].exist = true;
	}

	return cache;
}

static int rvl_debug_entry(struct target *target)
{
	LOG_DEBUG("-");
    uint32_t value = 0;

	int retval = rvl_save_context(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rvl_save_context");
		return retval;
	}

	struct rvl_common *rvl = target_to_rvl(target);
    struct rl_du *du_core = rl_to_du(rvl);
	uint32_t addr = rvl->core_regs[GDB_REGNO_PC];

    //value |= DBG_IE_INST_MISALIGNED | DBG_IE_ILLEGAL | DBG_IE_BREAKPOINT | DBG_IE_LOAD_MISALIGNED | DBG_IE_AMO_MISALIGNED;
    value |= DBG_IE_BREAKPOINT;

    // printf("Set DBG IE with value: %08x\n", value);
    if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_DBG + 0x02), 1, &value) != ERROR_OK)
    {
        LOG_ERROR("Error: cannot set DBG IE reg\n");
        return ERROR_FAIL;
    }

	if (breakpoint_find(target, addr))
    {
        buf_set_u32(rvl->core_cache->reg_list[GDB_REGNO_PC].value, 0, 32, addr);
		rvl->core_cache->reg_list[GDB_REGNO_PC].dirty = true;
		rvl->core_cache->reg_list[GDB_REGNO_PC].valid = true;
    }

	return retval;
}

static int rvl_halt(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("target->state: %s", target_state_name(target));

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("Target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("Target was in unknown state when halt was requested");

	if (target->state == TARGET_RESET) {
		if ((jtag_get_reset_config() & RESET_SRST_PULLS_TRST) && jtag_get_srst()) 
        {
			LOG_ERROR("Can't request a halt while in reset if nSRST pulls nTRST");
			return ERROR_TARGET_FAILURE;
		} 
        else 
        {
			target->debug_reason = DBG_REASON_DBGRQ;
			return ERROR_OK;
		}
	}

	int retval = du_core->rl_cpu_stall(&rvl->jtag, CPU_STALL);
	if (retval != ERROR_OK) 
    {
		LOG_ERROR("Impossible to stall the CPU");
		return retval;
	}

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int rl_is_cpu_running(struct target *target, int *running)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	int retval;
	int tries = 0;
	const int RETRIES_MAX = 5;

	/* Have a retry loop to determine of the CPU is running.
	   If target has been hard reset for any reason, it might take a couple
	   of goes before it's ready again.
	*/
	while (tries < RETRIES_MAX) {

		tries++;

		retval = du_core->rl_is_cpu_running(&rvl->jtag, running);
		if (retval != ERROR_OK) {
			LOG_WARNING("Debug IF CPU control reg read failure.");
			/* Try once to restart the JTAG infrastructure -
			   quite possibly the board has just been reset. */
			LOG_WARNING("Resetting JTAG TAP state and reconnecting to debug IF.");
			du_core->rl_jtag_init(&rvl->jtag);

			LOG_WARNING("...attempt %d of %d", tries, RETRIES_MAX);

			alive_sleep(2);

			continue;
		} else
			return ERROR_OK;
	}

	LOG_ERROR("Could not re-establish communication with target");
	return retval;
}

static int rvl_poll(struct target *target)
{
	int retval;
	int running;

	retval = rl_is_cpu_running(target, &running);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rl_is_cpu_running");
		return retval;
	}

	/* check for processor halted */
	if (!running) 
    {
		/* It's actually stalled, so update our software's state */
		if ((target->state == TARGET_RUNNING) ||
		    (target->state == TARGET_RESET)) 
        {

			target->state = TARGET_HALTED;

			retval = rvl_debug_entry(target);
			if (retval != ERROR_OK) 
            {
				LOG_ERROR("Error while calling rvl_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target, TARGET_EVENT_HALTED);
		} 
        else if (target->state == TARGET_DEBUG_RUNNING) 
        {
			target->state = TARGET_HALTED;

			retval = rvl_debug_entry(target);
			if (retval != ERROR_OK) 
            {
				LOG_ERROR("Error while calling rvl_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
		}
	} 
    else 
    { /* ... target is running */

		/* If target was supposed to be stalled, stall it again */
		if  (target->state == TARGET_HALTED) 
        {
			target->state = TARGET_RUNNING;

			retval = rvl_halt(target);
			if (retval != ERROR_OK) 
            {
				LOG_ERROR("Error while calling rvl_halt");
				return retval;
			}

			retval = rvl_debug_entry(target);
			if (retval != ERROR_OK) 
            {
				LOG_ERROR("Error while calling rvl_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
		}

		target->state = TARGET_RUNNING;

	}

	return ERROR_OK;
}

static int rvl_assert_reset(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("Assert reset \n");

	int retval = du_core->rl_cpu_reset(&rvl->jtag, CPU_RESET);

	if (retval != ERROR_OK) {
	 	LOG_ERROR("Error while asserting RESET");
	 	return retval;
	}

	return ERROR_OK;
}

static int rvl_deassert_reset(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("-");

	int retval = du_core->rl_cpu_reset(&rvl->jtag, CPU_NOT_RESET);
	if (retval != ERROR_OK) 
    {
	 	LOG_ERROR("Error while deasserting RESET");
	 	return retval;
	}

    // Set the correpsponding debug flags again, since those are cleared
    retval = rvl_debug_entry(target);
    if (retval != ERROR_OK) 
    {
        LOG_ERROR("Error while calling rvl_debug_entry");
        return retval;
    }

	return ERROR_OK;
}

static int rvl_soft_reset_halt(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("Soft reset \n");

	int retval = du_core->rl_cpu_stall(&rvl->jtag, CPU_STALL);

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while stalling the CPU");
		return retval;
	}

	retval = rvl_assert_reset(target);
	if (retval != ERROR_OK)
		return retval;

	retval = rvl_deassert_reset(target);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

// static bool is_any_soft_breakpoint(struct target *target)
// {
// 	struct breakpoint *breakpoint = target->breakpoints;

// 	LOG_DEBUG("-");

// 	while (breakpoint)
// 		if (breakpoint->type == BKPT_SOFT)
// 			return true;

// 	return false;
// }

//static int rvl_

static int rvl_resume_or_step(struct target *target, int current,
			       uint32_t address, int handle_breakpoints,
			       int debug_execution, int step)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	struct breakpoint *breakpoint = NULL;
	uint32_t resume_pc = 0;
    uint32_t tempReg = 0;
    uint32_t tempMStatusReg = 0;
    bool globalInterruptActive = false;
    int retval;

	LOG_DEBUG("Addr: 0x%" PRIx32 ", stepping: %s, handle breakpoints %s\n",
		  address, step ? "yes" : "no", handle_breakpoints ? "yes" : "no");

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

    // Free memory
	if (!debug_execution)
		target_free_all_working_areas(target);

	/* current ? continue on current pc : continue at <address> */
	if (!current)
    {
        buf_set_u32(rvl->core_cache->reg_list[GDB_REGNO_PC].value, 0, 32, address);

    }

    retval = rvl_restore_context(target);
    if (retval != ERROR_OK) {
        LOG_ERROR("Error while calling rvl_restore_context");
        return retval;
    }
       
    // Clear DBG HIT reg
    tempReg = 0;

    if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_DBG + 0x01), 1, &tempReg) != ERROR_OK)
    {
        printf("Error: cannot clear HIT reg\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_DBG + 0x00), 1, &tempReg) != ERROR_OK)
    {
        printf("Error: cannot read DBG ctrl reg\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_CSR  + CSR_MSTATUS), 1, &tempMStatusReg) != ERROR_OK)
    {
        printf("Error: cannot read MSTATUS reg\n");
        return ERROR_FAIL;
    }

    if(tempMStatusReg & DBG_CSR_MSTASUS_MIE)
    {
        globalInterruptActive = true;
    }

	if (step)
    {
		/* Set the single step trigger in Debug Mode Register 1 (DMR1) */
		tempReg |= DBG_CTRL_SINGLE_STEP_TRACE;

        if(globalInterruptActive)
        {
            tempMStatusReg &= ~DBG_CSR_MSTASUS_MIE;

            if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_CSR  + CSR_MSTATUS), 1, &tempMStatusReg) != ERROR_OK)
            {
                printf("Error: cannot read MSTATUS reg\n");
                return ERROR_FAIL;
            }
        }
    }
    else
    {
    	/* Clear the single step trigger in Debug Mode Register 1 (DMR1) */
		tempReg &= ~DBG_CTRL_SINGLE_STEP_TRACE;
    }



    if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_DBG + 0x00), 1, &tempReg) != ERROR_OK)
    {
        printf("Error: cannot write DBG ctrl reg\n");
        return ERROR_FAIL;
    }


	resume_pc = buf_get_u32(rvl->core_cache->reg_list[GDB_REGNO_PC].value, 0, 32);

	/* The front-end may request us not to handle breakpoints */
	if (handle_breakpoints) 
    {
		/* Single step past breakpoint at current address */
		breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) 
        {
			LOG_DEBUG("Unset breakpoint at 0x%08" TARGET_PRIxADDR, breakpoint->address);
			retval = rvl_remove_breakpoint(target, breakpoint);
			if (retval != ERROR_OK)
				return retval;
		}
	}

	/* Unstall time */
	retval = du_core->rl_cpu_stall(&rvl->jtag, CPU_UNSTALL);
	if (retval != ERROR_OK) 
    {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}

	if (step)
    {
        target->debug_reason = DBG_REASON_SINGLESTEP;

        if(globalInterruptActive)
        {
            if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_CSR  + CSR_MSTATUS), 1, &tempMStatusReg) != ERROR_OK)
            {
                printf("Error: cannot read MSTATUS reg\n");
                return ERROR_FAIL;
            }
            tempMStatusReg |= DBG_CSR_MSTASUS_MIE;

            if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_CSR  + CSR_MSTATUS), 1, &tempMStatusReg) != ERROR_OK)
            {
                printf("Error: cannot read MSTATUS reg\n");
                return ERROR_FAIL;
            }
        }
    }
	else
		target->debug_reason = DBG_REASON_NOTHALTED;

    // Invalidate current registers in local cache
    // Nothing to do with CPU cache
    register_cache_invalidate(rvl->core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("Target resumed at 0x%08" PRIx32, resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("Target debug resumed at 0x%08" PRIx32, resume_pc);
	}

	return ERROR_OK;
}

static int rvl_resume(struct target *target, int current,
		       target_addr_t address, int handle_breakpoints,
		       int debug_execution)
{
	return rvl_resume_or_step(target, current, address,
				   handle_breakpoints,
				   debug_execution,
				   NO_SINGLE_STEP);
}

static int rvl_step(struct target *target, int current,
		     target_addr_t address, int handle_breakpoints)
{
	return rvl_resume_or_step(target, current, address,
				   handle_breakpoints,
				   0,
				   SINGLE_STEP);

}

static int rvl_add_breakpoint(struct target *target,
			       struct breakpoint *breakpoint)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	uint32_t data;
    int retval;

	LOG_DEBUG("Adding breakpoint: addr 0x%08" TARGET_PRIxADDR ", len %d, type %d, set: %d, id: %" PRIu32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

     /* Only support SW breakpoints for now. */
    if(breakpoint->type != BKPT_SOFT)
    {
        LOG_ERROR("HW breakpoints not supported for now\n");
        return ERROR_FAIL;
    }

    if(breakpoint->length != 2 && breakpoint->length != 4)
    {
        LOG_ERROR("Breakpoint unsupported length\n");
        return ERROR_FAIL;
    }


    if(breakpoint->length == 2)
    {
        /* Read and save the instruction */
        retval = du_core->rl_jtag_read_memory(&rvl->jtag,
                        breakpoint->address,
                        2,
                        1,
                        (uint8_t*)&data);
    }
    else
    {
        /* Read and save the instruction */
        retval = du_core->rl_jtag_read_memory(&rvl->jtag,
                        breakpoint->address,
                        4,
                        1,
                        (uint8_t*)&data);
    }

	if (retval != ERROR_OK) 
    {
		LOG_ERROR("Error while reading the instruction at 0x%08" TARGET_PRIxADDR,
			   breakpoint->address);
		return retval;
	}
   
	free(breakpoint->orig_instr);

	breakpoint->orig_instr = malloc(breakpoint->length);
	memcpy(breakpoint->orig_instr, &data, breakpoint->length);

    if(breakpoint->length == 2)
    {
        uint16_t rvl_trap_insn16 = RV_EBREAK16_INSTR;
        //target_buffer_set_u32(target, rvl_trap_insn, RV_EBREAK16_INSTR);
        retval = du_core->rl_jtag_write_memory(&rvl->jtag,
                        breakpoint->address,
                        2,
                        1,
                        (uint8_t*)&rvl_trap_insn16);
    }
    else
    {
        uint32_t rvl_trap_insn = RV_EBREAK_INSTR;
        //target_buffer_set_u32(target, rvl_trap_insn, RV_EBREAK_INSTR);
        retval = du_core->rl_jtag_write_memory(&rvl->jtag,
                        breakpoint->address,
                        4,
                        1,
                        (uint8_t*)&rvl_trap_insn);
    }

    // Instruction invalidate is in the DU_FLUSH

	return ERROR_OK;
}

static int rvl_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
    int retval;

	LOG_DEBUG("Removing breakpoint: addr 0x%08" TARGET_PRIxADDR ", len %d, type %d, set: %d, id: %" PRIu32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

    /* Only support SW breakpoints for now. */
    if(breakpoint->type != BKPT_SOFT)
    {
        LOG_ERROR("HW breakpoints not supported for now\n");
        return ERROR_FAIL;
    }

    if(breakpoint->length != 2 && breakpoint->length != 4)
    {
        LOG_ERROR("Breakpoint unsupported length\n");
        return ERROR_FAIL;
    }

    if(breakpoint->length == 2)
    {
        /* Replace the removed instruction */
        retval = du_core->rl_jtag_write_memory(&rvl->jtag,
                        breakpoint->address,
                        2,
                        1,
                        breakpoint->orig_instr);
    }
    else
    {
        /* Replace the removed instruction */
        retval = du_core->rl_jtag_write_memory(&rvl->jtag,
                        breakpoint->address,
                        4,
                        1,
                        breakpoint->orig_instr);
    }


	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing back the instruction at 0x%08" TARGET_PRIxADDR,
			   breakpoint->address);
		return retval;
	}

    
    // Instruction invalidate is in the DU_FLUSH

	return ERROR_OK;
}

static int rvl_add_watchpoint(struct target *target,
			       struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int rvl_remove_watchpoint(struct target *target,
				  struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int rvl_read_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("Read memory at 0x%08" TARGET_PRIxADDR ", size: %" PRIu32 ", count: 0x%08" PRIx32, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}


	//TODO: 64bit accesses (for 64bit CPU)
	/* Sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !buffer) {
		LOG_ERROR("Bad arguments");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("Unaligned memory access not supported");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return du_core->rl_jtag_read_memory(&rvl->jtag, address, size, count, buffer);
}

static int rvl_write_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	LOG_DEBUG("Write memory at 0x%08" TARGET_PRIxADDR ", size: %" PRIu32 ", count: 0x%08" PRIx32, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}


	//TODO: 64bit accesses for 64bit CPU
	/* Sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !buffer) {
		LOG_ERROR("Bad arguments");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("Unaligned memory access not supported");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return du_core->rl_jtag_write_memory(&rvl->jtag, address, size, count, buffer);
}

static int rvl_init_target(struct command_context *cmd_ctx,
		struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	struct rl_jtag *jtag = &rvl->jtag;

	if (!du_core) {
		LOG_ERROR("No debug unit selected");
		return ERROR_FAIL;
	}

	if (!jtag->tap_ip) {
		LOG_ERROR("No tap selected");
		return ERROR_FAIL;
	}

	rvl->jtag.tap = target->tap;
	rvl->jtag.rl_jtag_inited = 0;
	rvl->jtag.rl_jtag_module_selected = -1;
	rvl->jtag.target = target;

	rvl_build_reg_cache(target);

	return ERROR_OK;
}

static int rvl_target_create(struct target *target, Jim_Interp *interp)
{
	if (!target->tap)
		return ERROR_FAIL;

	struct rvl_common *rvl = calloc(1, sizeof(struct rvl_common));

	target->arch_info = rvl;

	rvl_create_reg_list(target);

	rl_universal_tap_register();

	rl_dbg_adv_register();

	return ERROR_OK;
}

static int rvl_examine(struct target *target)
{
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);

	if (!target_was_examined(target)) {

		target_set_examined(target);

		int running;

		int retval = du_core->rl_is_cpu_running(&rvl->jtag, &running);
		if (retval != ERROR_OK) {
			LOG_ERROR("Couldn't read the CPU state");
			return retval;
		} else {
			if (running)
				target->state = TARGET_RUNNING;
			else {
				LOG_DEBUG("Target is halted");

				/* This is the first time we examine the target,
				 * it is stalled and we don't know why. Let's
				 * assume this is because of a debug reason.
				 */
				if (target->state == TARGET_UNKNOWN)
					target->debug_reason = DBG_REASON_DBGRQ;

				target->state = TARGET_HALTED;
			}
		}
	}

	return ERROR_OK;
}

static int rvl_arch_state(struct target *target)
{
	return ERROR_OK;
}

static int rvl_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
			  int *reg_list_size, enum target_register_class reg_class)
{
	struct rvl_common *rvl = target_to_rvl(target);

	if (reg_class == REG_CLASS_GENERAL) {
		/* We will have this called whenever GDB connects. */
		int retval = rvl_save_context(target);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while calling rvl_save_context");
			return retval;
		}

		//TODO Load FPR when the CPU has a FPU
		*reg_list_size = GDB_REGNO_FPR0;
		/* this is free()'d back in gdb_server.c's gdb_get_register_packet() */
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < GDB_REGNO_FPR0; i++)
			(*reg_list)[i] = &rvl->core_cache->reg_list[i];
	} else {
		*reg_list_size = rvl->nb_regs;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < rvl->nb_regs; i++)
			(*reg_list)[i] = &rvl->core_cache->reg_list[i];
	}

	return ERROR_OK;

}

static int rvl_get_gdb_fileio_info(struct target *target, struct gdb_fileio_info *fileio_info)
{
	return ERROR_FAIL;
}

static int rvl_checksum_memory(struct target *target, target_addr_t address,
		uint32_t count, uint32_t *checksum)
{
	return ERROR_FAIL;
}

static int rvl_profiling(struct target *target, uint32_t *samples,
		uint32_t max_num_samples, uint32_t *num_samples, uint32_t seconds)
{
	struct timeval timeout, now;
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_du *du_core = rl_to_du(rvl);
	int retval = ERROR_OK;

	gettimeofday(&timeout, NULL);
	timeval_add_time(&timeout, seconds, 0);

	LOG_INFO("Starting rvl profiling. Sampling npc as fast as we can...");

	/* Make sure the target is running */
	target_poll(target);
	if (target->state == TARGET_HALTED)
		retval = target_resume(target, 1, 0, 0, 0);

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while resuming target");
		return retval;
	}

	uint32_t sample_count = 0;

	for (;;) {
		uint32_t reg_value;
		retval = du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x201) /* PPC */, 1, &reg_value);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while reading NPC");
			return retval;
		}

		samples[sample_count++] = reg_value;

		gettimeofday(&now, NULL);
		if ((sample_count >= max_num_samples) || timeval_compare(&now, &timeout) > 0) {
			LOG_INFO("Profiling completed. %" PRIu32 " samples.", sample_count);
			break;
		}
	}

	*num_samples = sample_count;
	return retval;
}

static int rvl_soc_test_sram(struct target *target)
{
    uint32_t baseAddress = 0x00010000;
    uint32_t ins;
    uint32_t insn[9];
    uint32_t address;

    insn[0] = 0x11112222;
    insn[1] = 0x33334444;
    insn[2] = 0x55556666;
    insn[3] = 0x77778888;
    insn[4] = 0x9999aaaa;
    insn[5] = 0xbbbbcccc;
    insn[6] = 0xddddeeee;
    insn[7] = 0xffff0000;
    insn[8] = 0xdedababa;

    if(rvl_poll(target) != ERROR_OK)
    {
        printf("Error while polling target\n");
        return ERROR_FAIL;
    }

    for(int i = 0; i < 9; i++)
    {
        address = baseAddress + (i * 4);

        printf("Write address: %08x, with: %08x\n",address, insn[i]);
        if(rvl_write_memory(target, address, 4, 1, (uint8_t*)&insn[i]) !=ERROR_OK)
        {
            printf("Error: Cannot write memory\n");
            return ERROR_FAIL;
        } 
    }

    for(int i = 0; i < 9; i++)
    {
        address = baseAddress + (i * 4);

        printf("Read address: %08x\n",address);
        if(rvl_read_memory(target, address, 4, 1, (uint8_t*)&ins) == ERROR_OK)
        {
            if(ins != insn[i])
            {
                printf("Error: Expected: %08x, received: %08x\n", insn[i], ins);
                return ERROR_FAIL;
            }
        }
        else
        {
            printf("Error: Reading memory\n");
            return ERROR_FAIL;
        }
    }

    return ERROR_OK;
}

static int rvl_soc_test_cpu(struct target *target)
{
    uint32_t baseAddress = 0x00010000;
    uint32_t insn[11];
    uint32_t illIns = 0x00000000;    
    uint32_t address;
    uint32_t r1, npc, ppc;
    int state;
    //uint32_t insRead;

    struct rvl_common *rvl = target_to_rvl(target);
    struct rl_du *du_core = rl_jtag_to_du(&rvl->jtag);

    printf("\n-- Testing RVL-SoC CPU\n");
    printf("writing instructions\n");

    insn[0]  = 0x00004033; /* xor   x0,x0,x0               */
    insn[1]  = 0x00000093; /* addi  x1,x0,0x0              */
    insn[2]  = 0x00010137; /* lui   x2,0x00010  (RAM_BASE) */
    insn[3]  = 0x03016113; /* ori   x2,x2,0x30             */
    insn[4]  = 0x00108093; /* addi  x1,x1,1                */
    insn[5]  = 0x00108093; /* addi  x1,x1,1                */
    insn[6]  = 0x00112023; /* sw    0(x2),x1               */
    insn[7]  = 0x00108093; /* addi  x1,x1,1                */
    insn[8]  = 0x00012183; /* lw    x3,0(x2)               */
    insn[9]  = 0x003080b3; /* add   x1,x1,x3               */
    insn[10] = 0xfe9ff06f; /* j     (base+0x10)            */

    if(rvl_poll(target) != ERROR_OK)
    {
        printf("Error while polling target\n");
    }


    for(int i = 0; i < 11; i++)
    {
        address = baseAddress + (i * 4);
        if(rvl_write_memory(target, address, 4, 1, (uint8_t*)&insn[i]) !=ERROR_OK)
        {
            printf("Error: Cannot write memory\n");
            return ERROR_FAIL;
        } 
    }

    //Fill rest of memory with 0x00 (C.ILLEGAL). Avoid CPU going nuts on 0xxxxxx
    for (uint32_t i = baseAddress+0x2c; i < baseAddress+0x4c; i=i+4)
    {
        if(rvl_write_memory(target, i, 4, 1, (uint8_t*)&illIns) !=ERROR_OK)
        {
            printf("Error: Cannot write memory\n");
            return ERROR_FAIL;
        }
    }

    printf("Setting up CPU\n");

    /*
    * Test 1
    */
    printf("- Test 1, save context\n");

    if(rvl_save_context(target) == ERROR_OK)
    {
        printf("Success: Saved context\n");
        for (int i = 0; i < GDB_REGNO_FPR0; i++) 
    	{
            printf("reg: %s, value: %08x\n",rvl_init_reg_list[i].name, rvl->core_regs[i]);
        }
    }
    else
    {
        printf("Error: cannot save context\n");
        return ERROR_FAIL;
    }
    
    /*
     * Test 2
     */
    printf("- Test 2, Single stepping\n");

    printf("Write NPC: %08x\n", baseAddress);
    if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_GPRS + 0x200), 1, &baseAddress) != ERROR_OK)
    {
        printf("Error: cannot set NPC\n");
        return ERROR_FAIL;
    }

    for(int i = 0; i < 11; i++)
    {            
        if(rvl_poll(target) != ERROR_OK)
        {
            printf("Error while polling target\n");
            return ERROR_FAIL;
        }

        printf("Starting CPU, waiting for breakpoint... \n");

        if(rvl_step(target, 1, 0x00, 0) != ERROR_OK)
        {
            printf("Error: stepping\n");
            return ERROR_FAIL;
        }

        do
        {
            if (rl_is_cpu_running(target, &state) != ERROR_OK) {
                LOG_ERROR("Error while calling rl_is_cpu_running");
                return ERROR_FAIL;
            }
            
        } while(!state);

        printf("Got breakpoint \n");
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x200), 1, &npc) != ERROR_OK)
    {
        printf("Error: cannot read NPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x201), 1, &ppc) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_RF   +  1), 1, &r1) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }
    printf("Read:     npc: %08x, ppc: %08x, r1: %08x\n", npc, ppc, r1);
    printf("Expected: npc: %08x, ppc: %08x, r1: %08x\n", 0x00010010, 0x00010028, 5);

    if(npc != 0x00010010 || ppc !=  0x00010028 || r1 != 5)
    {
        return ERROR_FAIL;
    }

    printf("Passed test 2\n");

    /*
     * Test 3
     */
    printf("- Test 3, Breakpoint hit\n");

    struct breakpoint testBreakPoint = {0};

    testBreakPoint.type = BKPT_SOFT;
    testBreakPoint.address = (baseAddress + 0x24);
    testBreakPoint.length = 4;

    printf("Add breakpoint\n");
    rvl_add_breakpoint(target, &testBreakPoint);

    if(rvl_poll(target) != ERROR_OK)
    {
        printf("Error while polling target\n");
        return ERROR_FAIL;
    }

    if(rvl_read_memory(target, (baseAddress + 0x24), 4, 1, (uint8_t*)&r1) !=ERROR_OK)
    {
        printf("Cannot read back memory!\n");
        return ERROR_FAIL;
    } 

    if(r1 != RV_EBREAK_INSTR)
    {
        printf("SW breakpoint not set!\n");
        return ERROR_FAIL;
    }

    printf("Resuming target\n");
    rvl_resume(target,1, 0, 0, 0);    
    
    do
    {
        if (rl_is_cpu_running(target, &state) != ERROR_OK) {
            LOG_ERROR("Error while calling rl_is_cpu_running");
            return ERROR_FAIL;
        }
        
    } while(!state);

    printf("Remove breakpoint\n");
    rvl_remove_breakpoint(target, &testBreakPoint);

    if(rvl_poll(target) != ERROR_OK)
    {
        printf("Error while polling target\n");
        return ERROR_FAIL;
    }

    if(rvl_read_memory(target, (baseAddress + 0x24), 4, 1, (uint8_t*)&r1) != ERROR_OK)
    {
        printf("Cannot read back memory!\n");
        return ERROR_FAIL;
    }

    if(r1 != insn[9])
    {
        printf("Breakpoing not removed: Expected: %08x, Received: %08x\n", insn[9], r1);
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x200), 1, &npc) != ERROR_OK)
    {
        printf("Error: cannot read NPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x201), 1, &ppc) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_RF   +  1), 1, &r1) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }

    printf("Read:     npc: %08x, ppc: %08x, r1: %08x\n", npc, ppc, r1);
    printf("Expected: npc: %08x, ppc: %08x, r1: %08x\n", 0x00010028, 0x00010024, 8);

    if(ppc !=  0x00010024 || r1 != 8)
    {
        return ERROR_FAIL;
    }


    printf("Passed test 3\n");

    printf("- Test 4, Breakpoint hit2\n");

    testBreakPoint.type = BKPT_SOFT;
    testBreakPoint.address = (baseAddress + 0x28);
    testBreakPoint.length = 4;

    printf("Add breakpoint\n");
    rvl_add_breakpoint(target, &testBreakPoint);

    if(rvl_poll(target) != ERROR_OK)
    {
        printf("Error while polling target\n");
        return ERROR_FAIL;
    }

    ppc = (baseAddress + 0x10);
    printf("Write NPC: %08x\n", ppc);
    if(du_core->rl_jtag_write_cpu(&rvl->jtag, (GROUP_GPRS + 0x200), 1, &ppc) != ERROR_OK)
    {
        printf("Error: cannot set NPC\n");
        return ERROR_FAIL;
    }

    printf("Resuming target\n");
    rvl_resume(target,1, 0, 0, 0);    
    
    do
    {
        if (rl_is_cpu_running(target, &state) != ERROR_OK) {
            LOG_ERROR("Error while calling rl_is_cpu_running");
            return ERROR_FAIL;
        }
        
    } while(!state);

    printf("Remove breakpoint\n");
    rvl_remove_breakpoint(target, &testBreakPoint);

        if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x200), 1, &npc) != ERROR_OK)
    {
        printf("Error: cannot read NPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_GPRS + 0x201), 1, &ppc) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }

    if(du_core->rl_jtag_read_cpu(&rvl->jtag, (GROUP_RF   +  1), 1, &r1) != ERROR_OK)
    {
        printf("Error: cannot read PPC\n");
        return ERROR_FAIL;
    }

    printf("Read:     npc: %08x, ppc: %08x, r1: %08x\n", npc, ppc, r1);
    printf("Expected: npc: %08x, ppc: %08x, r1: %08x\n", 0x0001002C, 0x00010028, 21);

    if(ppc !=  0x00010028 || r1 != 21)
    {
        return ERROR_FAIL;
    }


    printf("Passed test 4\n");

    return ERROR_OK;
}

COMMAND_HANDLER(rl_tap_select_command_handler)
{
	struct target *target = get_current_target(CMD_CTX);
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_jtag *jtag = &rvl->jtag;
	struct rl_tap_ip *rl_tap;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rl_tap, &rl_tap_list, list) {
		if (rl_tap->name) {
			if (!strcmp(CMD_ARGV[0], rl_tap->name)) {
				jtag->tap_ip = rl_tap;
				LOG_INFO("%s tap selected", rl_tap->name);
				return ERROR_OK;
			}
		}
	}

	LOG_ERROR("%s unknown, no tap selected", CMD_ARGV[0]);
	return ERROR_COMMAND_SYNTAX_ERROR;
}

COMMAND_HANDLER(rl_tap_list_command_handler)
{
	struct rl_tap_ip *rl_tap;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rl_tap, &rl_tap_list, list) {
		if (rl_tap->name)
			command_print(CMD, "%s", rl_tap->name);
	}

	return ERROR_OK;
}

COMMAND_HANDLER(rl_du_select_command_handler)
{
	struct target *target = get_current_target(CMD_CTX);
	struct rvl_common *rvl = target_to_rvl(target);
	struct rl_jtag *jtag = &rvl->jtag;
	struct rl_du *rl_du;

	if (CMD_ARGC > 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rl_du, &rl_du_list, list) {
		if (rl_du->name) {
			if (!strcmp(CMD_ARGV[0], rl_du->name)) {
				jtag->du_core = rl_du;
				LOG_INFO("%s debug unit selected", rl_du->name);

				if (CMD_ARGC == 2) {
					int options;
					COMMAND_PARSE_NUMBER(int, CMD_ARGV[1], options);
					rl_du->options = options;
					LOG_INFO("Option %x is passed to %s debug unit"
						 , options, rl_du->name);
				}

				return ERROR_OK;
			}
		}
	}

	LOG_ERROR("%s unknown, no debug unit selected", CMD_ARGV[0]);
	return ERROR_COMMAND_SYNTAX_ERROR;
}

COMMAND_HANDLER(rl_du_list_command_handler)
{
	struct rl_du *rl_du;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rl_du, &rl_du_list, list) {
		if (rl_du->name)
			command_print(CMD, "%s", rl_du->name);
	}

	return ERROR_OK;
}

COMMAND_HANDLER(rvl_addreg_command_handler)
{
	struct target *target = get_current_target(CMD_CTX);
	struct rvl_core_reg new_reg;

	if (CMD_ARGC != 4)
		return ERROR_COMMAND_SYNTAX_ERROR;

	new_reg.target = NULL;
	new_reg.rvl_common = NULL;

	uint32_t addr;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], addr);

	new_reg.name = strdup(CMD_ARGV[0]);
	new_reg.spr_num = addr;
	new_reg.feature = strdup(CMD_ARGV[2]);
	new_reg.group = strdup(CMD_ARGV[3]);

	rvl_add_reg(target, &new_reg);

	LOG_DEBUG("Add reg \"%s\" @ 0x%08" PRIx32 ", group \"%s\", feature \"%s\"",
		  new_reg.name, addr, new_reg.group, new_reg.feature);

	return ERROR_OK;
}

COMMAND_HANDLER(rvl_test_handler)
{
    struct target *target = get_current_target(CMD_CTX);

    if (CMD_ARGC == 0 || CMD_ARGC > 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    int options;
	COMMAND_PARSE_NUMBER(int, CMD_ARGV[0], options);

    printf("Rvl Test\n");

    printf("Testing options: %u\n", options);

    printf("\n RVL-SoC Stalling CPU\n");

    if(rvl_halt(target) == ERROR_OK)
    {
        printf("Success: CPU(s) stalled\n");
    }
    else
    {
        printf("Error: CPU(s) not stalled!\n");
        return ERROR_FAIL;
    }

    if((options & 0x00000001) >  0)
    {
        printf("\n RVL SoC on-chip SRAM test: \n");

        if(rvl_soc_test_sram(target) == ERROR_OK)
        {
            printf("Success: sram test success\n");
        }
        else
        {
            printf("Error: sram test failed!\n");
            return ERROR_FAIL;
        }
    }
    else
    {
        printf("\n RVL SoC SRAM test disabled\n");
    }

    if((options & 0x00000002) > 0)
    {      
        if(rvl_soc_test_cpu(target) == ERROR_OK)
        {
            printf("Success: CPU test Passed\n");
        }
        else
        {
            printf("Error: CPU test failed!\n");
            return ERROR_FAIL;
        }
    }


    printf("Succesfully passed given tests\n");

    return ERROR_OK;
}

static const struct command_registration rvl_hw_ip_command_handlers[] = {
	{
		.name = "rl_tap_select",
		.handler = rl_tap_select_command_handler,
		.mode = COMMAND_ANY,
		.usage = "name",
		.help = "Select the TAP core to use",
	},
	{
		.name = "rl_tap_list",
		.handler = rl_tap_list_command_handler,
		.mode = COMMAND_ANY,
		.usage = "",
		.help = "Display available TAP core",
	},
	{
		.name = "rl_du_select",
		.handler = rl_du_select_command_handler,
		.mode = COMMAND_ANY,
		.usage = "name",
		.help = "Select the Debug Unit core to use",
	},
	{
		.name = "rl_du_list",
		.handler = rl_du_list_command_handler,
		.mode = COMMAND_ANY,
		.usage = "select_tap name",
		.help = "Display available Debug Unit core",
	},
    {
        .name = "rvl_test",
        .handler = rvl_test_handler,
        .mode = COMMAND_ANY,
        .usage = "Test the RVL SoC",
        .help = "Test the RvL SoC implementation",
    },
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration rvl_reg_command_handlers[] = {
	{
		.name = "addreg",
		.handler = rvl_addreg_command_handler,
		.mode = COMMAND_ANY,
		.usage = "name addr feature group",
		.help = "Add a register to the register list",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration rvl_command_handlers[] = {
	{
		.chain = rvl_reg_command_handlers,
	},
	{
		.chain = rvl_hw_ip_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};


struct target_type rvl_target = {
	.name = "rvl",

	.poll = rvl_poll,
	.arch_state = rvl_arch_state,

	.target_request_data = NULL,

	.halt = rvl_halt,
	.resume = rvl_resume,
	.step = rvl_step,

	.assert_reset = rvl_assert_reset,
	.deassert_reset = rvl_deassert_reset,
	.soft_reset_halt = rvl_soft_reset_halt,

	.get_gdb_reg_list = rvl_get_gdb_reg_list,

	.read_memory = rvl_read_memory,
	.write_memory = rvl_write_memory,
	.checksum_memory = rvl_checksum_memory,

	.commands = rvl_command_handlers,
	.add_breakpoint = rvl_add_breakpoint,
	.remove_breakpoint = rvl_remove_breakpoint,
	.add_watchpoint = rvl_add_watchpoint,
	.remove_watchpoint = rvl_remove_watchpoint,

	.target_create = rvl_target_create,
	.init_target = rvl_init_target,
	.examine = rvl_examine,

	.get_gdb_fileio_info = rvl_get_gdb_fileio_info,

	.profiling = rvl_profiling,
};
