/***************************************************************************
 *   Copyright (C) 2021 Richard Herveille                                  *
 *   richard.herveille@roalogic.com                                        *
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

#define CPU_STALL	0
#define CPU_UNSTALL	1

#define CPU_RESET	0
#define CPU_NOT_RESET	1


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


int rl_dbg_adv_register(void);

/* Linear list over all available or1k debug unit */
extern struct list_head du_list;

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
