/*
 * hdparm.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <app_include.h>
#include <scsi/sg.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("hdparm");

#define SG_ATA_16 0x85
#define SG_ATA_PROTO_NON_DATA (3 << 1)
#define SG_ATA_PROTO_PIO_IN (4 << 1)
#define SG_ATA_PROTO_PIO_OUT (5 << 1)

#define SG_CDB2_TLEN_FEAT (1 << 0)
#define SG_CDB2_TLEN_NSECT (2 << 0)
#define SG_CDB2_TLEN_SECTORS (1 << 2)
#define SG_CDB2_TDIR_FROM_DEV (1 << 3)
#define SG_CDB2_CHECK_COND (1 << 5)

#define SG_CHECK_CONDITION 0x02
#define SG_DRIVER_SENSE 0x08

#define ATA_USING_LBA (1 << 6)

#define ATA_OP_SMART_READ_DATA 0xb0
#define ATA_OP_STANDBY 0xe2
#define ATA_OP_IDLE 0xe3
#define ATA_OP_IDENTIFY 0xec
#define ATA_OP_SET_FEATURES 0xef

#define ATA_SET_FEATURES_SUBOP_APM 0x05

#define ATA_SMART_READ_DATA_FEATURE_READ_VALUES 0xD0
#define ATA_SMART_READ_DATA_FEATURE_READ_THRESHOLDS 0xD1
#define ATA_SMART_READ_DATA_FEATURE_STATUS 0xDA

typedef bool (*hdparm_smart_id_get_value_str_func_t)(char *ptr, char *end, uint8_t raw[6]);

struct hdparm_smart_id_decode_t {
	uint8_t id;
	const char name[24];
	hdparm_smart_id_get_value_str_func_t get_value_str_func;
};

static bool hdparm_smart_id_get_value_str_raw48(char *ptr, char *end, uint8_t raw[6]);
static bool hdparm_smart_id_get_value_str_raw16(char *ptr, char *end, uint8_t raw[6]);
static bool hdparm_smart_id_get_value_str_raw24(char *ptr, char *end, uint8_t raw[6]);
static bool hdparm_smart_id_get_value_str_temp_min_max(char *ptr, char *end, uint8_t raw[6]);

static struct hdparm_smart_id_decode_t hdparm_smart_id_decode_table[] =
{
	{1, "Raw_Read_Error_Rate", hdparm_smart_id_get_value_str_raw48},
	{3, "Spin_Up_Time", hdparm_smart_id_get_value_str_raw16},
	{4, "Start_Stop_Count", hdparm_smart_id_get_value_str_raw48},
	{5, "Reallocated_Sector_Ct", hdparm_smart_id_get_value_str_raw16},
	{7, "Seek_Error_Rate", hdparm_smart_id_get_value_str_raw48},
	{9, "Power_On_Hours", hdparm_smart_id_get_value_str_raw24},
	{10, "Spin_Retry_Count", hdparm_smart_id_get_value_str_raw48},
	{11, "Calibration_Retry_Count", hdparm_smart_id_get_value_str_raw48},
	{12, "Power_Cycle_Count", hdparm_smart_id_get_value_str_raw48},
	{184, "End-to-End_Error", hdparm_smart_id_get_value_str_raw48},
	{187, "Reported_Uncorrect", hdparm_smart_id_get_value_str_raw48},
	{188, "Command_Timeout", hdparm_smart_id_get_value_str_raw48},
	{189, "High_Fly_Writes", hdparm_smart_id_get_value_str_raw48},
	{190, "Airflow_Temperature_Cel", hdparm_smart_id_get_value_str_temp_min_max},
	{191, "G-Sense_Error_Rate", hdparm_smart_id_get_value_str_raw48},
	{192, "Power-Off_Retract_Count", hdparm_smart_id_get_value_str_raw48},
	{193, "Load_Cycle_Count", hdparm_smart_id_get_value_str_raw48},
	{194, "Temperature_Celsius", hdparm_smart_id_get_value_str_temp_min_max},
	{196, "Reallocated_Event_Count", hdparm_smart_id_get_value_str_raw16},
	{197, "Current_Pending_Sector", hdparm_smart_id_get_value_str_raw48},
	{198, "Offline_Uncorrectable", hdparm_smart_id_get_value_str_raw48},
	{199, "UDMA_CRC_Error_Count", hdparm_smart_id_get_value_str_raw48},
	{200, "Multi_Zone_Error_Rate", hdparm_smart_id_get_value_str_raw48},
	{206, "Flying_Height", hdparm_smart_id_get_value_str_raw48},
	{240, "Head_Flying_Hours", hdparm_smart_id_get_value_str_raw24},
	{241, "Total_LBAs_Written", hdparm_smart_id_get_value_str_raw48},
	{242, "Total_LBAs_Read", hdparm_smart_id_get_value_str_raw48},
	{254, "Free_Fall_Sensor", hdparm_smart_id_get_value_str_raw48},
	{0, "Unknown", hdparm_smart_id_get_value_str_raw48}
};

static bool hdparm_smart_id_get_value_str_raw48(char *ptr, char *end, uint8_t raw[6])
{
	uint64_t val = mem_int_read_le_u48(raw);
	return sprintf_custom(ptr, end, "%llu", val);
}

static bool hdparm_smart_id_get_value_str_raw16(char *ptr, char *end, uint8_t raw[6])
{
	uint16_t val = mem_int_read_le_u16(raw);
	return sprintf_custom(ptr, end, "%u", val);
}

static bool hdparm_smart_id_get_value_str_raw24(char *ptr, char *end, uint8_t raw[6])
{
	uint32_t val = mem_int_read_le_u24(raw);
	return sprintf_custom(ptr, end, "%u", val);
}

static bool hdparm_smart_id_get_value_str_temp_min_max(char *ptr, char *end, uint8_t raw[6])
{
	uint8_t val = mem_int_read_u8(raw);
	return sprintf_custom(ptr, end, "%u", val);
}

struct hdparm_smart_id_decode_t *hdparm_smart_id_decode_lookup(uint8_t id)
{
	struct hdparm_smart_id_decode_t *decode = hdparm_smart_id_decode_table;
	while (1) {
		if (decode->id == id) {
			break;
		}
		if (decode->id == 0) {
			break;
		}

		decode++;
	}

	return decode;
}

const char *hdparm_smart_id_get_name(struct hdparm_smart_id_decode_t *decode)
{
	return decode->name;
}

bool hdparm_smart_id_get_value_str(struct hdparm_smart_id_decode_t *decode, char *ptr, char *end, uint8_t raw[6])
{
	return decode->get_value_str_func(ptr, end, raw);
}

static bool hdparm_ata_cmd_non_data(const char *dev_name, uint8_t cmd[16])
{
	struct file_t *dev_file = file_open_existing(dev_name);
	if (!dev_file) {
		DEBUG_ERROR("failed to open %s (%d)", dev_name, errno);
		return false;
	}

	struct sg_io_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));

	uint8_t sb[32];
	memset(sb, 0, sizeof(sb));

	hdr.interface_id = 'S';
	hdr.dxfer_direction = SG_DXFER_NONE;
	hdr.cmd_len = 16;
	hdr.mx_sb_len = sizeof(sb);
	hdr.cmdp = cmd;
	hdr.sbp = sb;
	hdr.timeout = 15000;

	if (ioctl(dev_file->fp, SG_IO, &hdr) < 0) {
		DEBUG_ERROR("command sent to %s failed (%d)", dev_name, errno);
		file_close(dev_file);
		return false;
	}

	file_close(dev_file);

	if (hdr.status && (hdr.status != SG_CHECK_CONDITION)) {
		DEBUG_ERROR("%s scsi status error %u", dev_name, hdr.status);
		return false;
	}

	if (hdr.host_status) {
		DEBUG_ERROR("%s host status error %u", dev_name, hdr.host_status);
		return false;
	}

	if (hdr.driver_status && (hdr.driver_status != SG_DRIVER_SENSE)) {
		DEBUG_ERROR("%s driver status error %u", dev_name, hdr.driver_status);
		return false;
	}

	return true;
}

static bool hdparm_ata_cmd_pio_in(const char *dev_name, uint8_t ata_op, uint8_t feature, uint32_t lba, uint8_t output_buffer[512])
{
	memset(output_buffer, 0, 512);

	struct file_t *dev_file = file_open_existing(dev_name);
	if (!dev_file) {
		DEBUG_ERROR("failed to open %s (%d)", dev_name, errno);
		return false;
	}

	struct sg_io_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));

	uint8_t cmd[16];
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = SG_ATA_16;
	cmd[1] = SG_ATA_PROTO_PIO_IN;
	cmd[2] = SG_CDB2_TDIR_FROM_DEV | SG_CDB2_TLEN_SECTORS | SG_CDB2_TLEN_NSECT;
	cmd[4] = feature;
	cmd[6] = 1; /* number of sectors */
	cmd[8] = (uint8_t)(lba >> 0);
	cmd[10] = (uint8_t)(lba >> 8);
	cmd[12] = (uint8_t)(lba >> 16);
	cmd[13] = ATA_USING_LBA | (uint8_t)((lba >> 24) & 0x0F);
	cmd[14] = ata_op;

	uint8_t sb[32];
	memset(sb, 0, sizeof(sb));

	hdr.interface_id = 'S';
	hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	hdr.cmd_len = sizeof(cmd);
	hdr.mx_sb_len = sizeof(sb);
	hdr.dxfer_len = 512;
	hdr.cmdp = cmd;
	hdr.sbp = sb;
	hdr.dxferp = output_buffer;
	hdr.timeout = 15000;

	if (ioctl(dev_file->fp, SG_IO, &hdr) < 0) {
		DEBUG_ERROR("command sent to %s failed (%d)", dev_name, errno);
		file_close(dev_file);
		return false;
	}

	file_close(dev_file);

	if (hdr.status && (hdr.status != SG_CHECK_CONDITION)) {
		DEBUG_ERROR("%s scsi status error %u", dev_name, hdr.status);
		return false;
	}

	if (hdr.host_status) {
		DEBUG_ERROR("%s host status error %u", dev_name, hdr.host_status);
		return false;
	}

	if (hdr.driver_status && (hdr.driver_status != SG_DRIVER_SENSE)) {
		DEBUG_ERROR("%s driver status error %u", dev_name, hdr.driver_status);
		return false;
	}

	return true;
}

static void hdparm_get_identify_str_internal(char *dst, uint8_t *src_ptr, uint8_t *src_end)
{
	char *dst_ptr = dst;

	while (src_ptr < src_end) {
		if (src_ptr[1] > ' ') {
			break;
		}
		if (src_ptr[0] > ' ') {
			*dst_ptr++ = (char)(src_ptr[0]);
			src_ptr += 2;
			break;
		}

		src_ptr += 2;
	}

	while (src_ptr < src_end) {
		*dst_ptr++ = (char)(src_ptr[1]);
		*dst_ptr++ = (char)(src_ptr[0]);
		src_ptr += 2;
	}

	*dst_ptr = 0;
	str_trim_whitespace(dst);
}

bool hdparm_get_identify(const char *dev_name, struct hdparm_identify_t *identify)
{
	uint8_t data[512];
	if (!hdparm_ata_cmd_pio_in(dev_name, ATA_OP_IDENTIFY, 0x00, 0x00000000, data)) {
		DEBUG_ERROR("ATA_OP_IDENTIFY failed for %s", dev_name);
		return false;
	}

	identify->sectors = mem_int_read_le_u64(data + 200);
	hdparm_get_identify_str_internal(identify->model_str, data + 54, data + 94);
	hdparm_get_identify_str_internal(identify->serial_str, data + 20, data + 40);
	return true;
}

bool hdparm_get_smart(const char *dev_name, struct hdparm_smart_t *smart)
{
	uint8_t data[512];
	if (!hdparm_ata_cmd_pio_in(dev_name, ATA_OP_SMART_READ_DATA, ATA_SMART_READ_DATA_FEATURE_READ_VALUES, 0x00C24F00, data)) {
		DEBUG_ERROR("ATA_OP_SMART_READ_DATA failed for %s", dev_name);
		return false;
	}

	struct hdparm_smart_entry_t *entry = smart->entry;
	uint8_t *ptr = data + 2;

	for (uint8_t i = 0; i < 30; i++) {
		uint8_t id = ptr[0];
		if (id == 0x00) {
			ptr += 12;
			continue;
		}

		entry->id = id;
		entry->current = ptr[3];
		entry->worst = ptr[4];
		entry->threshold = 0;
		entry->flags = mem_int_read_le_u16(ptr + 1);

		entry->raw[0] = ptr[5];
		entry->raw[1] = ptr[6];
		entry->raw[2] = ptr[7];
		entry->raw[3] = ptr[8];
		entry->raw[4] = ptr[9];
		entry->raw[5] = ptr[10];

		entry++;
		ptr += 12;
	}

	if (!hdparm_ata_cmd_pio_in(dev_name, ATA_OP_SMART_READ_DATA, ATA_SMART_READ_DATA_FEATURE_READ_THRESHOLDS, 0x00C24F00, data)) {
		DEBUG_ERROR("ATA_OP_SMART_READ_DATA failed for %s", dev_name);
		return false;
	}

	smart->count = entry - smart->entry;
	entry = smart->entry;
	ptr = data + 2;

	for (uint8_t i = 0; i < 30; i++) {
		uint8_t id = ptr[0];
		if (id == 0x00) {
			ptr += 12;
			continue;
		}

		if (id != entry->id) {
			ptr += 12;
			continue;
		}

		entry->threshold = ptr[1];
		entry++;

		ptr += 12;
	}

	smart->pass = true;
	entry = smart->entry;

	for (uint8_t i = 0; i < smart->count; i++) {
		if ((entry->flags & 0x01) == 0) {
			entry++;
			continue;
		}

		if ((entry->current <= entry->threshold) || (entry->worst <= entry->threshold)) {
			smart->pass = false;
			break;
		}

		entry++;
	}

	return true;
}

bool hdparm_set_standby_time(const char *dev_name, uint32_t seconds)
{
	uint32_t value = (seconds + 4) / 5;
	if (value > 240) {
		value = 240;
	}

	uint8_t cmd[16];
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = SG_ATA_16;
	cmd[1] = SG_ATA_PROTO_NON_DATA;
	cmd[2] = SG_CDB2_CHECK_COND;
	cmd[6] = value;
	cmd[13] = ATA_USING_LBA;
	cmd[14] = ATA_OP_IDLE;

	bool ret1 = hdparm_ata_cmd_non_data(dev_name, cmd);
	if (!ret1) {
		DEBUG_WARN("failed to set idle time of %s", dev_name);
	}

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = SG_ATA_16;
	cmd[1] = SG_ATA_PROTO_NON_DATA;
	cmd[2] = SG_CDB2_CHECK_COND;
	cmd[6] = value;
	cmd[13] = ATA_USING_LBA;
	cmd[14] = ATA_OP_STANDBY;

	bool ret2 = hdparm_ata_cmd_non_data(dev_name, cmd);
	if (!ret2) {
		DEBUG_WARN("failed to set standby time of %s", dev_name);
	}

	return ret1 || ret2;
}

bool hdparm_set_advanced_power_management(const char *dev_name, uint8_t level)
{
	uint8_t cmd[16];
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = SG_ATA_16;
	cmd[1] = SG_ATA_PROTO_NON_DATA;
	cmd[2] = SG_CDB2_CHECK_COND;
	cmd[4] = ATA_SET_FEATURES_SUBOP_APM;
	cmd[6] = level;
	cmd[13] = ATA_USING_LBA;
	cmd[14] = ATA_OP_SET_FEATURES;

	if (!hdparm_ata_cmd_non_data(dev_name, cmd)) {
		DEBUG_ERROR("failed to set advanced power management level of %s", dev_name);
		return false;
	}

	return true;
}

