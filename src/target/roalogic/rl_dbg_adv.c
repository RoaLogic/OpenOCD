/***************************************************************************
 *   Copyright (C) 2021 by Richard Herveille                               *
 *   richard.herveille@roalogic.com                                        *
 *                                                                         *
 *   Copyright (C) 2021 by Bjorn Schouteten                                *
 *   bjorn.schouteten@roalogic.com                                         *
 *                                                                         * 
 *   Based on OR1K version                                                 *
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
#include "rl_dbg_adv.h"
#include "jsp_server.h"

#include <target/target.h>
#include <jtag/jtag.h>


static struct rl_du rl_dbg_adv;

static const char * const chain_name[] = {"SYSBUS", "CPU", "JSP"};

static int rl_adv_jtag_write_cpu(struct rl_jtag *jtag_info,
		uint32_t addr, int count, const uint32_t *value);

static uint32_t adbg_compute_crc(uint32_t crc, uint32_t data_in,
				 int length_bits)
{
	for (int i = 0; i < length_bits; i++) {
		uint32_t d, c;
		d = ((data_in >> i) & 0x1) ? 0xffffffff : 0;
		c = (crc & 0x1) ? 0xffffffff : 0;
		crc = crc >> 1;
		crc = crc ^ ((d ^ c) & ADBG_CRC_POLY);
	}

	return crc;
}

static int find_status_bit(void *_buf, int len)
{
	int i = 0;
	int count = 0;
	int ret = -1;
	uint8_t *buf = _buf;

	while (!(buf[i] & (1 << count++)) && (i < len)) {
		if (count == 8) {
			count = 0;
			i++;
		}
	}

	if (i < len)
		ret = (i * 8) + count;

	return ret;
}

static int rl_adv_jtag_init(struct rl_jtag *jtag_info)
{
	struct rl_tap_ip *tap_ip = jtag_info->tap_ip;

	int retval = tap_ip->init(jtag_info);
	if (retval != ERROR_OK) {
		LOG_ERROR("TAP initialization failed");
		return retval;
	}

	/* TAP is now configured to communicate with debug interface */
	jtag_info->rl_jtag_inited = 1;

	/* TODO hardcoded HW parameters */
    jtag_info->rl_jtag_address_size = 32;
//	jtag_info->cpu_size = 4;
	jtag_info->rl_jtag_cpu_selected = 0;
	
	/* TAP reset - not sure what state debug module chain is in now */
	jtag_info->rl_jtag_module_selected = DC_NONE;

	jtag_info->current_reg_idx = malloc(DBG_MAX_MODULES * sizeof(uint8_t));
	memset(jtag_info->current_reg_idx, 0, DBG_MAX_MODULES * sizeof(uint8_t));

	if (rl_dbg_adv.options & USE_HISPEED)
		LOG_INFO("Roa Logic adv debug unit is configured with option USE_HISPEED");

	if (rl_dbg_adv.options & ENABLE_JSP_SERVER) {
		if (rl_dbg_adv.options & ENABLE_JSP_MULTI)
			LOG_INFO("Roa Logic adv debug unit is configured with option ENABLE_JSP_MULTI");
		LOG_INFO("Roa Logic adv debug unit is configured with option ENABLE_JSP_SERVER");
		retval = jsp_init(jtag_info, JSP_BANNER);
		if (retval != ERROR_OK) {
			LOG_ERROR("Couldn't start the JSP server");
			return retval;
		}
	}

	LOG_DEBUG("Init done");

	return ERROR_OK;

}

/* Selects one of the modules in the debug unit
 * (e.g. SYSBUS, CPU, JSP)
 */
static int adbg_select_module(struct rl_jtag *jtag_info, int chain)
{
	if (jtag_info->rl_jtag_module_selected == chain)
		return ERROR_OK;

	/* MSB of the data out must be set to 1, indicating a module
	 * select command
	 */
	uint8_t data = chain | (1 << DBG_MODULE_SELECT_REG_SIZE);

	LOG_DEBUG("Select module: %s", chain_name[chain]);

	struct scan_field field;

	field.num_bits = (DBG_MODULE_SELECT_REG_SIZE + 1);
	field.out_value = &data;
	field.in_value = NULL;
	jtag_add_dr_scan(jtag_info->tap, 1, &field, TAP_IDLE);

	int retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		return retval;

	jtag_info->rl_jtag_module_selected = chain;

	return ERROR_OK;
}

/* Set the index of the desired register in the currently selected module
 * 1 bit module select command
 * 4 bits opcode
 * n bits index
 */
static int adbg_select_ctrl_reg(struct rl_jtag *jtag_info, uint8_t regidx)
{
	int      index_len;
	uint32_t opcode;
	uint32_t opcode_len;

	/* If this reg is already selected, don't do a JTAG transaction */
	if (jtag_info->current_reg_idx[jtag_info->rl_jtag_module_selected] == regidx)
		return ERROR_OK;

	switch (jtag_info->rl_jtag_module_selected) {
	case DC_SYSBUS:
		index_len  = DBG_SYSBUS_REG_SEL_LEN;
		opcode     = DBG_SYSBUS_CMD_IREG_SEL;
		opcode_len = DBG_SYSBUS_OPCODE_LEN;
		break;
	case DC_CPU:
		index_len  = DBG_CPU_REG_SEL_LEN;
		opcode     = DBG_CPU_CMD_IREG_SEL;
		opcode_len = DBG_CPU_OPCODE_LEN;
		break;
	default:
		LOG_ERROR("Illegal debug chain selected (%i) while selecting control register",
			  jtag_info->rl_jtag_module_selected);
		return ERROR_FAIL;
	}

	/* MSB must be 0 to access modules */
	uint32_t data = (opcode & ~(1 << opcode_len)) << index_len;
	data |= regidx;

	struct scan_field field;

	field.num_bits = (opcode_len + 1) + index_len;
	field.out_value = (uint8_t *)&data;
	field.in_value = NULL;
	jtag_add_dr_scan(jtag_info->tap, 1, &field, TAP_IDLE);

	int retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		return retval;

	jtag_info->current_reg_idx[jtag_info->rl_jtag_module_selected] = regidx;

	return ERROR_OK;
}

/* Write control register (internal to the debug unit) */
static int adbg_ctrl_write(struct rl_jtag *jtag_info, uint8_t regidx,
			   uint32_t *cmd_data, int length_bits)
{
	int      index_len;
	int      cpusel_len;
	int      cpusel;
	uint32_t opcode;
	uint32_t opcode_len;

	LOG_DEBUG("Write control register %" PRId8 ": 0x%08" PRIx32, regidx, cmd_data[0]);

	int retval = adbg_select_ctrl_reg(jtag_info, regidx);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling adbg_select_ctrl_reg");
		return retval;
	}

	switch (jtag_info->rl_jtag_module_selected) {
	case DC_SYSBUS:
		index_len  = DBG_SYSBUS_REG_SEL_LEN;
		cpusel     = 0;
		cpusel_len = 0;
		opcode     = DBG_SYSBUS_CMD_IREG_WR;
		opcode_len = DBG_SYSBUS_OPCODE_LEN;
		break;
	case DC_CPU:
		index_len  = DBG_CPU_REG_SEL_LEN;
		cpusel     = jtag_info->rl_jtag_cpu_selected;
		cpusel_len = DBG_CPU_CPUSEL_LEN;
		opcode     = DBG_CPU_CMD_IREG_WR;
		opcode_len = DBG_CPU_OPCODE_LEN;
		break;
	default:
		LOG_ERROR("Illegal debug chain selected (%i) while doing control write",
			  jtag_info->rl_jtag_module_selected);
		return ERROR_FAIL;
	}

	struct scan_field field[2];

	/* MSB must be 0 to access modules */
	uint32_t data = ~(1 << (opcode_len + cpusel_len + index_len));
	data &= (((opcode << cpusel_len) | cpusel ) << index_len);
	data |= regidx;

	field[0].num_bits  = length_bits;
	field[0].out_value = (uint8_t *)cmd_data;
	field[0].in_value  = NULL;

	field[1].num_bits  = 1+ opcode_len + cpusel_len + index_len;
	field[1].out_value = (uint8_t *)&data;
	field[1].in_value  = NULL;

	jtag_add_dr_scan(jtag_info->tap, 2, field, TAP_IDLE);

	return jtag_execute_queue();
}

/* Reads control register (internal to the debug unit) */
static int adbg_ctrl_read(struct rl_jtag *jtag_info, uint32_t regidx,
			  uint32_t *data, int length_bits)
{

	int retval = adbg_select_ctrl_reg(jtag_info, regidx);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling adbg_select_ctrl_reg");
		return retval;
	}

	int      cpusel = 0;
	int      cpusel_len;
	int      opcode_len;
	uint32_t opcode;

	/* There is no 'read' command, We write a NOP to read */
	switch (jtag_info->rl_jtag_module_selected) {
	case DC_SYSBUS:
		cpusel_len = 0;
		opcode     = DBG_SYSBUS_CMD_NOP;
		opcode_len = DBG_SYSBUS_OPCODE_LEN;
		break;
	case DC_CPU:
		cpusel     = jtag_info->rl_jtag_cpu_selected;
		cpusel_len = DBG_CPU_CPUSEL_LEN;
		opcode     = DBG_CPU_CMD_NOP;
		opcode_len = DBG_CPU_OPCODE_LEN;
		break;
	default:
		LOG_ERROR("Illegal debug chain selected (%i) while doing control read",
			  jtag_info->rl_jtag_module_selected);
		return ERROR_FAIL;
	}

	/* Zero MSB = op for module, not top-level debug unit */
	uint32_t outdata = ~(1 << (opcode_len + cpusel_len));
	outdata &= (opcode << cpusel_len) | cpusel;

	struct scan_field field[2];

	field[0].num_bits  = length_bits;
	field[0].out_value = NULL;
	field[0].in_value  = (uint8_t *)data;

	field[1].num_bits  = opcode_len + cpusel_len + 1;
	field[1].out_value = (uint8_t *)&outdata;
	field[1].in_value  = NULL;

	jtag_add_dr_scan(jtag_info->tap, 2, field, TAP_IDLE);

	return jtag_execute_queue();
}

/* sends out a burst command to the selected module in the debug unit (MSB to LSB):
 * 1-bit module command
 * 4-bit opcode
 * 4-bit CPU (optional)
 * 32/64-bit address
 * 16-bit length (of the burst, in words)
 */
static int adbg_burst_command(struct rl_jtag *jtag_info,
			      uint32_t opcode, uint8_t opcode_len,
			      uint64_t address, uint8_t address_len,
			      uint32_t cpusel, uint8_t cpusel_len,
			      uint16_t length_words)
{
	uint32_t bitcount;
	uint32_t data[3];


	/* Total bitcount */
	bitcount  = 1;            //1bit module command
	bitcount += opcode_len;   //4bit opcode
	bitcount += cpusel_len;   //4bit CPU select
	bitcount += address_len;  //Address
	bitcount += 16;           //Burst Length

	
	/* Set up the data */
	switch (address_len) {
	case 32: 
		data[0] = (address << 16) | length_words;
		data[1] = opcode;
		if (cpusel_len) {
			data[1] = (data[1] << cpusel_len) | cpusel;
		}
		data[1] = (data[1] << 16) | (address >> 16);

		/* MSB must be 0 to access modules */		
		data[1] &= ~(1 << (16 + cpusel_len + opcode_len));
		break;
	case 64:
		data[0] = (address << 16) | length_words;
		data[1] = address >> 16;
		data[2] = opcode;
		if (cpusel_len) {
			data[2] = (data[2] << cpusel_len) | cpusel;
		}
		data[2] = (data[2] << 16) | (address >> 48);
		
		data[2] &= ~(1 << (16 + cpusel_len + opcode_len));
		break;
	default:
		LOG_ERROR("Unsupported address-length (%i)", address_len);
		return ERROR_FAIL;
	}
	
	struct scan_field field;

	field.num_bits  = bitcount;
	field.out_value = (uint8_t *)&data[0];
	field.in_value  = NULL;

	jtag_add_dr_scan(jtag_info->tap, 1, &field, TAP_IDLE);

	return jtag_execute_queue();
}

static int adbg_sysbus_burst_read(struct rl_jtag *jtag_info, int size,
			          int count, uint32_t start_address, uint8_t *data)
{
	int retry_full_crc = 0;
	int retry_full_busy = 0;
	int retval;

	uint8_t opcode;
	uint8_t opcode_len;
	uint8_t cpusel = 0;
	uint8_t cpusel_len;
	uint8_t address_len;


	LOG_DEBUG("Doing burst read, word size %d, word count %d, start address 0x%08" PRIx32,
		  size, count, start_address);

	/* Select the appropriate opcode */
	switch (jtag_info->rl_jtag_module_selected) {
	case DC_SYSBUS:
		if (size == 1)
			opcode = DBG_SYSBUS_CMD_BREAD8;
		else if (size == 2)
			opcode = DBG_SYSBUS_CMD_BREAD16;
		else if (size == 4)
			opcode = DBG_SYSBUS_CMD_BREAD32;
		else if (size == 8)
			opcode = DBG_SYSBUS_CMD_BREAD64;
		else {
			LOG_WARNING("Tried burst read with invalid word size (%d),"
				  "defaulting to 4-byte words", size);
			opcode = DBG_SYSBUS_CMD_BREAD32;
		}
		opcode_len = DBG_SYSBUS_OPCODE_LEN;
		cpusel_len = 0;
		break;
	case DC_CPU:
		if (size == 4)
			opcode = DBG_CPU_CMD_BREAD32;
		else {
			LOG_WARNING("Tried burst read with invalid word size (%d),"
				  "defaulting to 4-byte words", size);
			opcode = DBG_CPU_CMD_BREAD32;
		}
		opcode_len = DBG_CPU_OPCODE_LEN;
		cpusel     = jtag_info->rl_jtag_cpu_selected;
                cpusel_len = DBG_CPU_CPUSEL_LEN;
		break;
	default:
		LOG_ERROR("Illegal debug chain selected (%i) while doing burst read",
			  jtag_info->rl_jtag_module_selected);
		return ERROR_FAIL;
	}
	address_len = jtag_info->rl_jtag_address_size;


	int total_size_bytes = count * size;
	struct scan_field field;
	uint8_t *in_buffer = malloc(total_size_bytes + CRC_LEN + STATUS_BYTES);

retry_read_full:

	/* Send the BURST READ command, returns TAP to idle state */
//	retval = adbg_burst_command(jtag_info, opcode, start_address, count);
	retval = adbg_burst_command(jtag_info, opcode, opcode_len,
		       		    start_address, address_len, cpusel, cpusel_len, count);

	if (retval != ERROR_OK)
		goto out;

	field.num_bits = (total_size_bytes + CRC_LEN + STATUS_BYTES) * 8;
	field.out_value = NULL;
	field.in_value = in_buffer;

	jtag_add_dr_scan(jtag_info->tap, 1, &field, TAP_IDLE);

	retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		goto out;

	/* Look for the start bit in the first (STATUS_BYTES * 8) bits */
	int shift = find_status_bit(in_buffer, STATUS_BYTES);

	/* We expect the status bit to be in the first byte */
	if (shift < 0) {
		if (retry_full_busy++ < MAX_READ_BUSY_RETRY) {
			LOG_WARNING("Burst read timed out");
			goto retry_read_full;
		} else {
			LOG_ERROR("Burst read failed");
			retval = ERROR_FAIL;
			goto out;
		}
	}

	buffer_shr(in_buffer, total_size_bytes + CRC_LEN + STATUS_BYTES, shift);

	uint32_t crc_read;
	memcpy(data, in_buffer, total_size_bytes);
	memcpy(&crc_read, &in_buffer[total_size_bytes], 4);

	uint32_t crc_calc = 0xffffffff;
	for (int i = 0; i < total_size_bytes; i++)
		crc_calc = adbg_compute_crc(crc_calc, data[i], 8);

	if (crc_calc != crc_read) {
		LOG_WARNING("CRC ERROR! Computed 0x%08" PRIx32 ", read CRC 0x%08" PRIx32, crc_calc, crc_read);
		if (retry_full_crc++ < MAX_READ_CRC_RETRY)
			goto retry_read_full;
		else {
			LOG_ERROR("Burst read failed");
			retval = ERROR_FAIL;
			goto out;
		}
	} else
		LOG_DEBUG("CRC OK!");

	/* Now, read the error register, and retry/recompute as necessary */
	if (jtag_info->rl_jtag_module_selected == DC_SYSBUS &&
	    !(rl_dbg_adv.options & USE_HISPEED)) {

		uint32_t err_data[2] = {0, 0};
		uint32_t addr;
		int bus_error_retries = 0;

		/* First, just get 1 bit...read address only if necessary */
		retval = adbg_ctrl_read(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 1);
		if (retval != ERROR_OK)
			goto out;

		/* Then we have a problem */
		if (err_data[0] & 0x1) {

			retval = adbg_ctrl_read(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 33);
			if (retval != ERROR_OK)
				goto out;

			addr = (err_data[0] >> 1) | (err_data[1] << 31);
			LOG_WARNING("SYSBUS bus error during burst read, address 0x%08" PRIx32 ", retrying!", addr);

			bus_error_retries++;
			if (bus_error_retries > MAX_BUS_ERRORS) {
				LOG_ERROR("Max SYSBUS bus errors reached during burst read");
				retval = ERROR_FAIL;
				goto out;
			}

			/* Don't call retry_do(), a JTAG reset won't help a SYSBUS bus error */
			/* Write 1 bit, to reset the error register */
			err_data[0] = 1;
			retval = adbg_ctrl_write(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 1);
			if (retval != ERROR_OK)
				goto out;

			goto retry_read_full;
		}
	}

out:
	free(in_buffer);

	return retval;
}

/* Set up and execute a burst write to a contiguous set of addresses */
static int adbg_sysbus_burst_write(struct rl_jtag *jtag_info, const uint8_t *data, int size,
				    int count, unsigned long start_address)
{
	int retry_full_crc = 0;
	int retval;

	uint8_t opcode;
	uint8_t opcode_len;
	uint8_t cpusel = 0;
	uint8_t cpusel_len;
	uint8_t address_len;


	LOG_DEBUG("Doing burst write, word size %d, word count %d,"
		  "start address 0x%08lx", size, count, start_address);

	/* Select the appropriate opcode */
	switch (jtag_info->rl_jtag_module_selected) {
	case DC_SYSBUS:
		if (size == 1)
			opcode = DBG_SYSBUS_CMD_BWRITE8;
		else if (size == 2)
			opcode = DBG_SYSBUS_CMD_BWRITE16;
		else if (size == 4)
			opcode = DBG_SYSBUS_CMD_BWRITE32;
		else if (size == 8)
			opcode = DBG_SYSBUS_CMD_BWRITE64;
		else {
			LOG_DEBUG("Tried SYSBUS burst write with invalid word size (%d),"
				  "defaulting to 4-byte words", size);
			opcode = DBG_SYSBUS_CMD_BWRITE32;
		}
		opcode_len = DBG_SYSBUS_OPCODE_LEN;
		cpusel_len = 0;
		break;
	case DC_CPU:
		if (size == 4)
			opcode = DBG_CPU_CMD_BWRITE32;
		else {
			LOG_DEBUG("Tried CPU burst write with invalid word size (%d),"
				  "defaulting to 4-byte words", size);
			opcode = DBG_CPU_CMD_BWRITE32;
		}
		opcode_len = DBG_CPU_OPCODE_LEN;
		cpusel     = jtag_info->rl_jtag_cpu_selected;
		cpusel_len = DBG_CPU_CPUSEL_LEN;
		break;
	default:
		LOG_ERROR("Illegal debug chain selected (%i) while doing burst write",
			  jtag_info->rl_jtag_module_selected);
		return ERROR_FAIL;
	}
	address_len = jtag_info->rl_jtag_address_size;


retry_full_write:

	/* Send the BURST WRITE command, returns TAP to idle state */
//	retval = adbg_burst_command(jtag_info, opcode, start_address, count);
	retval = adbg_burst_command(jtag_info, opcode, opcode_len,
				    start_address, address_len, cpusel, cpusel_len, count);

	if (retval != ERROR_OK)
		return retval;

	struct scan_field field[3];

	/* Write a start bit so it knows when to start counting */
	uint8_t value = 1;
	field[0].num_bits = 1;
	field[0].out_value = &value;
	field[0].in_value = NULL;

	uint32_t crc_calc = 0xffffffff;
	for (int i = 0; i < (count * size); i++)
		crc_calc = adbg_compute_crc(crc_calc, data[i], 8);

	field[1].num_bits = count * size * 8;
	field[1].out_value = data;
	field[1].in_value = NULL;

	field[2].num_bits = 32;
	field[2].out_value = (uint8_t *)&crc_calc;
	field[2].in_value = NULL;

	jtag_add_dr_scan(jtag_info->tap, 3, field, TAP_DRSHIFT);

	/* Read the 'CRC match' bit, and go to idle */
	field[0].num_bits = 1;
	field[0].out_value = NULL;
	field[0].in_value = &value;
	jtag_add_dr_scan(jtag_info->tap, 1, field, TAP_IDLE);

	retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		return retval;

	if (!value) {
		LOG_WARNING("CRC ERROR! match bit after write is %" PRIi8 " (computed CRC 0x%08" PRIx32 ")", value, crc_calc);
		if (retry_full_crc++ < MAX_WRITE_CRC_RETRY)
			goto retry_full_write;
		else
			return ERROR_FAIL;
	} else
		LOG_DEBUG("CRC OK!\n");

	/* Now, read the error register, and retry/recompute as necessary */
	if (jtag_info->rl_jtag_module_selected == DC_SYSBUS &&
	    !(rl_dbg_adv.options & USE_HISPEED)) {
		uint32_t addr;
		int bus_error_retries = 0;
		uint32_t err_data[2] = {0, 0};

		/* First, just get 1 bit...read address only if necessary */
		retval = adbg_ctrl_read(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 1);
		if (retval != ERROR_OK)
			return retval;

		/* Then we have a problem */
		if (err_data[0] & 0x1) {

			retval = adbg_ctrl_read(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 33);
			if (retval != ERROR_OK)
				return retval;

			addr = (err_data[0] >> 1) | (err_data[1] << 31);
			LOG_WARNING("SYSBUS bus error during burst write, address 0x%08" PRIx32 ", retrying!", addr);

			bus_error_retries++;
			if (bus_error_retries > MAX_BUS_ERRORS) {
				LOG_ERROR("Max SYSBUS bus errors reached during burst read");
				retval = ERROR_FAIL;
				return retval;
			}

			/* Don't call retry_do(), a JTAG reset won't help a SYSBUS bus error */
			/* Write 1 bit, to reset the error register */
			err_data[0] = 1;
			retval = adbg_ctrl_write(jtag_info, DBG_SYSBUS_REG_ERROR, err_data, 1);
			if (retval != ERROR_OK)
				return retval;

			goto retry_full_write;
		}
	}

	return ERROR_OK;
}

/* Currently hard set in functions to 32-bits */
static int rl_adv_jtag_read_cpu(struct rl_jtag *jtag_info,
		uint32_t addr, int count, uint32_t *value)
{
	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	return adbg_sysbus_burst_read(jtag_info, 4, count, addr, (uint8_t *)value);
}

static int rl_adv_jtag_write_cpu(struct rl_jtag *jtag_info,
		uint32_t addr, int count, const uint32_t *value)
{
	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	return adbg_sysbus_burst_write(jtag_info, (uint8_t *)value, 4, count, addr);
}

static int rl_adv_cpu_stall(struct rl_jtag *jtag_info, int action)
{
	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	//TODO: the '2' length should be NumberOfCPU
	uint32_t cpu_cr;
	retval = adbg_ctrl_read(jtag_info, DBG_CPU_REG_STATUS, &cpu_cr, 2);
	if (retval != ERROR_OK)
		return retval;

	if (action == CPU_STALL)
		cpu_cr |= DBG_CPU_CR_STALL;
	else
		cpu_cr &= ~DBG_CPU_CR_STALL;

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

        //TODO: the '2' length should be number of CPUs
	return adbg_ctrl_write(jtag_info, DBG_CPU_REG_STATUS, &cpu_cr, 2);
}

static int rl_adv_is_cpu_running(struct rl_jtag *jtag_info, int *running)
{
	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	int current = jtag_info->rl_jtag_module_selected;

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	uint32_t cpu_cr = 0;
	retval = adbg_ctrl_read(jtag_info, DBG_CPU_REG_STATUS, &cpu_cr, 2);
	if (retval != ERROR_OK)
		return retval;

	if (cpu_cr & DBG_CPU_CR_STALL)
		*running = 0;
	else
		*running = 1;

	if (current != DC_NONE) {
		retval = adbg_select_module(jtag_info, current);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static int rl_adv_cpu_reset(struct rl_jtag *jtag_info, int action)
{
	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	uint32_t cpu_cr;
	retval = adbg_ctrl_read(jtag_info, DBG_CPU_REG_STATUS, &cpu_cr, 2);
	if (retval != ERROR_OK)
		return retval;

	if (action == CPU_RESET)
		cpu_cr |= DBG_CPU_CR_RESET;
	else
		cpu_cr &= ~DBG_CPU_CR_RESET;

	retval = adbg_select_module(jtag_info, DC_CPU);
	if (retval != ERROR_OK)
		return retval;

	return adbg_ctrl_write(jtag_info, DBG_CPU_REG_STATUS, &cpu_cr, 2);
}

static int rl_adv_jtag_read_memory(struct rl_jtag *jtag_info,
			    uint32_t addr, uint32_t size, int count, uint8_t *buffer)
{
	LOG_DEBUG("Reading SYSBUS%" PRIu32 " at 0x%08" PRIx32, size * 8, addr);

	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_SYSBUS);
	if (retval != ERROR_OK)
		return retval;

	int block_count_left = count;
	uint32_t block_count_address = addr;
	uint8_t *block_count_buffer = buffer;

	while (block_count_left) {

		int blocks_this_round = (block_count_left > MAX_BURST_SIZE) ?
			MAX_BURST_SIZE : block_count_left;

		retval = adbg_sysbus_burst_read(jtag_info, size, blocks_this_round,
				 	        block_count_address, block_count_buffer);
		if (retval != ERROR_OK)
			return retval;

		block_count_left    -= blocks_this_round;
		block_count_address += size * MAX_BURST_SIZE;
		block_count_buffer  += size * MAX_BURST_SIZE;
	}

	/* The adv_debug_if always return words and half words in
	 * little-endian order no matter what the target endian is.
	 * So if the target endian is big, change the order.
	 */

	struct target *target = jtag_info->target;
	if ((target->endianness == TARGET_BIG_ENDIAN) && (size != 1)) {
		switch (size) {
		// case 8:
		// 	buf_bswap64(buffer, buffer, size * count);
		// 	break;
		case 4:
			buf_bswap32(buffer, buffer, size * count);
			break;
		case 2:
			buf_bswap16(buffer, buffer, size * count);
			break;
		}
	}

	return ERROR_OK;
}

static int rl_adv_jtag_write_memory(struct rl_jtag *jtag_info,
			     uint32_t addr, uint32_t size, int count, const uint8_t *buffer)
{
	LOG_DEBUG("Writing SYSBUS%" PRIu32 " at 0x%08" PRIx32, size * 8, addr);

	int retval;
	if (!jtag_info->rl_jtag_inited) {
		retval = rl_adv_jtag_init(jtag_info);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = adbg_select_module(jtag_info, DC_SYSBUS);
	if (retval != ERROR_OK)
		return retval;

	/* The adv_debug_if wants words and half words in little-endian
	 * order no matter what the target endian is. So if the target
	 * endian is big, change the order.
	 */

	void *t = NULL;
	struct target *target = jtag_info->target;
	if ((target->endianness == TARGET_BIG_ENDIAN) && (size != 1)) {
		t = malloc(count * size * sizeof(uint8_t));
		if (!t) {
			LOG_ERROR("Out of memory");
			return ERROR_FAIL;
		}

		switch (size) {
		// case 8:
		// 	bus_bswap64(t, buffer, size * count);
		// 	break;
		case 4:
			buf_bswap32(t, buffer, size * count);
			break;
		case 2:
			buf_bswap16(t, buffer, size * count);
			break;
		}
		buffer = t;
	}

	int block_count_left = count;
	uint32_t block_count_address = addr;
	uint8_t *block_count_buffer = (uint8_t *)buffer;

	while (block_count_left) {

		int blocks_this_round = (block_count_left > MAX_BURST_SIZE) ?
			MAX_BURST_SIZE : block_count_left;

		retval = adbg_sysbus_burst_write(jtag_info, block_count_buffer,
					         size, blocks_this_round,
					         block_count_address);
		if (retval != ERROR_OK) {
			free(t);
			return retval;
		}

		block_count_left    -= blocks_this_round;
		block_count_address += size * MAX_BURST_SIZE;
		block_count_buffer  += size * MAX_BURST_SIZE;
	}

	free(t);
	return ERROR_OK;
}

int rl_adv_jtag_jsp_xfer(struct rl_jtag *jtag_info,
				  int *out_len, unsigned char *out_buffer,
				  int *in_len, unsigned char *in_buffer)
{
	LOG_DEBUG("JSP transfer");

	int retval;
	if (!jtag_info->rl_jtag_inited)
		return ERROR_OK;

	retval = adbg_select_module(jtag_info, DC_JSP);
	if (retval != ERROR_OK)
		return retval;

	/* return nb char xmit */
	int xmitsize;
	if (*out_len > 8)
		xmitsize = 8;
	else
		xmitsize = *out_len;

	uint8_t out_data[10];
	uint8_t in_data[10];
	struct scan_field field;
	int startbit, stopbit, wrapbit;

	memset(out_data, 0, 10);

	if (rl_dbg_adv.options & ENABLE_JSP_MULTI) {

		startbit = 1;
		wrapbit = (xmitsize >> 3) & 0x1;
		out_data[0] = (xmitsize << 5) | 0x1;  /* set the start bit */

		int i;
		/* don't copy off the end of the input array */
		for (i = 0; i < xmitsize; i++) {
			out_data[i + 1] = (out_buffer[i] << 1) | wrapbit;
			wrapbit = (out_buffer[i] >> 7) & 0x1;
		}

		if (i < 8)
			out_data[i + 1] = wrapbit;
		else
			out_data[9] = wrapbit;

		/* If the last data bit is a '1', then we need to append a '0' so the top-level module
		 * won't treat the burst as a 'module select' command.
		 */
		stopbit = !!(out_data[9] & 0x01);

	} else {
		startbit = 0;
		/* First byte out has write count in upper nibble */
		out_data[0] = 0x0 | (xmitsize << 4);
		if (xmitsize > 0)
			memcpy(&out_data[1], out_buffer, xmitsize);

		/* If the last data bit is a '1', then we need to append a '0' so the top-level module
		 * won't treat the burst as a 'module select' command.
		 */
		stopbit = !!(out_data[8] & 0x80);
	}

	field.num_bits = 72 + startbit + stopbit;
	field.out_value = out_data;
	field.in_value = in_data;

	jtag_add_dr_scan(jtag_info->tap, 1, &field, TAP_IDLE);

	retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		return retval;

	/* bytes available is in the upper nibble */
	*in_len = (in_data[0] >> 4) & 0xF;
	memcpy(in_buffer, &in_data[1], *in_len);

	int bytes_free = in_data[0] & 0x0F;
	*out_len = (bytes_free < xmitsize) ? bytes_free : xmitsize;

	return ERROR_OK;
}

static struct rl_du rl_dbg_adv = {
	.name                   = "rl_dbg_adv",
	.options                = NO_OPTION,
	.rl_jtag_init           = rl_adv_jtag_init,

	.rl_is_cpu_running      = rl_adv_is_cpu_running,
	.rl_cpu_stall           = rl_adv_cpu_stall,
	.rl_cpu_reset           = rl_adv_cpu_reset,

	.rl_jtag_read_cpu       = rl_adv_jtag_read_cpu,
	.rl_jtag_write_cpu      = rl_adv_jtag_write_cpu,

	.rl_jtag_read_memory    = rl_adv_jtag_read_memory,
	.rl_jtag_write_memory   = rl_adv_jtag_write_memory
};

int rl_dbg_adv_register(void)
{
	list_add_tail(&rl_dbg_adv.list, &rl_du_list);
	return 0;
}
