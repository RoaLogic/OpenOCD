/***************************************************************************
 *   Copyright (C) 2021 by Richard Herveille                               *
 *   richard.herveille@roalogic.com                                        *
 *                                                                         *
 *   Copyright (C) 2021 by Bjorn Schouteten                                *
 *   bjorn.schouteten@roalogic.com                                         *
 *                                                                         * 
 *                                                                         *
 *   Based on OR1k Version                                                 *
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

#include "rl_tap.h"
#include "rvl.h"

#include <jtag/jtag.h>

#define RL_TAP_INST_DEBUG	0x8

static int rl_universal_tap_init(struct rl_jtag *jtag_info)
{
	LOG_DEBUG("Initialising Roa Logic Universal JTAG TAP");

	/* Put TAP into state where it can talk to the debug interface
	 * by shifting in correct value to IR.
	 */

	/* Ensure TAP is reset - maybe not necessary*/
	jtag_add_tlr();

	struct jtag_tap *tap = jtag_info->tap;
	struct scan_field field;
	uint8_t ir_value = RL_TAP_INST_DEBUG;

	field.num_bits = tap->ir_length;
	field.out_value = &ir_value;
	field.in_value = NULL;

	jtag_add_ir_scan(tap, &field, TAP_IDLE);

	return jtag_execute_queue();
}

static struct rl_tap_ip universal_tap = {
	.name = "rl_universal_tap",
	.init = rl_universal_tap_init,
};

int rl_universal_tap_register(void)
{
	list_add_tail(&universal_tap.list, &rl_tap_list);
	return 0;
}
