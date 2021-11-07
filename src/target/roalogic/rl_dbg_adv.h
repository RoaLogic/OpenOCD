/***************************************************************************
 *   Copyright (C) 2021 Richard Herveille                                  *
 *   richard.herveille@roalogic.com                                        *
 *                                                                         *
 *   Copyright (C) 2021 by Bjorn Schouteten                                *
 *   bjorn.schouteten@roalogic.com                                         *
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

#ifndef OPENOCD_TARGET_ROALOGIC_DBG_ADV_H
#define OPENOCD_TARGET_ROALOGIC_DBG_ADV_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#define JSP_BANNER "\n\r" \
		   "******************************\n\r" \
		   "**     JTAG Serial Port     **\n\r" \
		   "******************************\n\r" \
		   "\n\r"

#define NO_OPTION			0

/* This an option to the adv debug unit.
 * If this is defined, status bits will be skipped on burst
 * reads and writes to improve download speeds.
 * This option must match the RTL configured option.
 */
#define USE_HISPEED			1


/* This an option to the adv debug unit.
 * If this is defined, the JTAG Serial Port Server is started.
 * This option must match the RTL configured option.
 */
#define ENABLE_JSP_SERVER		2


/* Define this if you intend to use the JSP in a system with multiple
 * devices on the JTAG chain
 */
#define ENABLE_JSP_MULTI		4


/* Definitions for the top-level debug unit.  This really just consists
 * of a single register, used to select the active debug module ("chain").
 */
#define DBG_MODULE_SELECT_REG_SIZE	2
#define DBG_MAX_MODULES			4

#define DC_NONE				-1
#define DC_SYSBUS   			0
#define DC_CPU				1
#define DC_JSP				2


/* CPU control register bits mask */
#define DBG_CPU_CR_STALL		0x01
#define DBG_CPU_CR_RESET		0x02


/* Polynomial for the CRC calculation
 * Yes, it's backwards.  Yes, this is on purpose.
 * The hardware is designed this way to save on logic and routing,
 * and it's really all the same to us here.
 */
#define ADBG_CRC_POLY			0xedb88320


/* These are for the internal registers in the SystemBus module
 * The first is the length of the index register,
 * the indexes of the various registers are defined after that.
 */
#define DBG_SYSBUS_REG_SEL_LEN		1
#define DBG_SYSBUS_REG_ERROR		0


/* Opcode definitions for the SystemBus module. */
#define DBG_SYSBUS_OPCODE_LEN		4
#define DBG_SYSBUS_CMD_NOP		0x0
#define DBG_SYSBUS_CMD_BWRITE8		0x1
#define DBG_SYSBUS_CMD_BWRITE16		0x2
#define DBG_SYSBUS_CMD_BWRITE32		0x3
#define DBG_SYSBUS_CMD_BWRITE64		0x4
#define DBG_SYSBUS_CMD_BREAD8		0x5
#define DBG_SYSBUS_CMD_BREAD16		0x6
#define DBG_SYSBUS_CMD_BREAD32		0x7
#define DBG_SYSBUS_CMD_BREAD64		0x8
#define DBG_SYSBUS_CMD_IREG_WR		0x9
#define DBG_SYSBUS_CMD_IREG_SEL		0xd


/* Internal register definitions for the CP module. */
#define DBG_CPU_REG_SEL_LEN		1
#define DBG_CPU_REG_STATUS		0


/* CPU Select */
#define DBG_CPU_CPUSEL_LEN		4


/* Opcode definitions for the CPU module. */
#define DBG_CPU_OPCODE_LEN		4
#define DBG_CPU_CMD_NOP			0x0
#define DBG_CPU_CMD_BWRITE32		0x3
#define DBG_CPU_CMD_BREAD32		0x7
#define DBG_CPU_CMD_IREG_WR		0x9
#define DBG_CPU_CMD_IREG_SEL		0xd


#define MAX_READ_STATUS_WAIT		10
#define MAX_READ_BUSY_RETRY		2
#define MAX_READ_CRC_RETRY		2
#define MAX_WRITE_CRC_RETRY		2
#define BURST_READ_READY		1
#define MAX_BUS_ERRORS			2

#define MAX_BURST_SIZE			(4 * 1024)

#define STATUS_BYTES			1
#define CRC_LEN				4



#define CPU_STALL	0
#define CPU_UNSTALL	1

#define CPU_RESET	0
#define CPU_NOT_RESET	1


// struct rl_jtag {
// 	struct  jtag_tap *tap;
// 	int     rl_jtag_inited;
// 	int     rl_jtag_module_selected;
// 	int     rl_jtag_cpu_selected;
// 	int     rl_jtag_address_size;
// 	uint8_t *current_reg_idx;
// 	struct  rl_tap_ip *tap_ip;
// 	struct  rl_du *du_core;
// 	struct  target *target;
// };


int rl_dbg_adv_register(void);

/* Linear list over all available or1k debug unit */
extern struct list_head rl_du_list;

struct rl_du {
	const char *name;
	struct list_head list;
	int options;

	int (*rl_jtag_init)(struct rl_jtag *jtag_info);

	int (*rl_is_cpu_running)(struct rl_jtag *jtag_info, int *running);

	int (*rl_cpu_stall)(struct rl_jtag *jtag_info, int action);

	int (*rl_cpu_reset)(struct rl_jtag *jtag_info, int action);
    
	int (*rl_jtag_read_cpu)(struct rl_jtag *jtag_info,
				uint32_t addr, int count, uint32_t *value);

	int (*rl_jtag_write_cpu)(struct rl_jtag *jtag_info,
				 uint32_t addr, int count, const uint32_t *value);

	int (*rl_jtag_read_memory)(struct rl_jtag *jtag_info, uint32_t addr, uint32_t size,
				   int count, uint8_t *buffer);

	int (*rl_jtag_write_memory)(struct rl_jtag *jtag_info, uint32_t addr, uint32_t size,
				    int count, const uint8_t *buffer);
};

static inline struct rl_du *rl_jtag_to_du(struct rl_jtag *jtag_info)
{
	return (struct rl_du *)jtag_info->du_core;
}

static inline struct rl_du *rl_to_du(struct rvl_common *rvl)
{
	struct rl_jtag *jtag = &rvl->jtag;
	return (struct rl_du *)jtag->du_core;
}

int rl_adv_jtag_jsp_xfer(struct rl_jtag *jtag_info,
			 int *out_len, unsigned char *out_buffer,
			 int *in_len, unsigned char *in_buffer);

#endif /* OPENOCD_TARGET_ROALOGIC_DBG_ADV_H */
