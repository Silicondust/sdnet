/*
 * dmidecode.c
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <app_include.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

 /*
  * Define the filename to be used for assertions.
  */
THIS_FILE("dmidecode");

static uint8_t *dmidecode_skip_strings(uint8_t *ptr, uint8_t *end)
{
	while (1) {
		while (1) {
			if (ptr + 2 > end) {
				return end;
			}

			if (*ptr++ == 0) {
				if (*ptr++ == 0) {
					return ptr;
				}
			}
		}
	}
}

static void dmidecode_get_string(char *out_ptr, char *out_end, uint8_t index, const char *strings_ptr, const char *strings_end)
{
	if (index == 0) {
		utf8_put_null(out_ptr, out_end);
		return;
	}

	index--;

	while (index > 0) {
		while (1) {
			if (strings_ptr >= strings_end) {
				return;
			}

			if (*strings_ptr++ == 0) {
				index--;
				break;
			}
		}
	}

	while (1) {
		uint16_t c = utf8_get_wchar(&strings_ptr, 0);
		if (c == 0) {
			break;
		}

		utf8_put_wchar(&out_ptr, out_end, c);
	}

	utf8_put_null(out_ptr, out_end);
}

static void dmidecode_get_system_information(uint8_t *header_ptr, uint8_t *header_end, const char *strings_ptr, const char *strings_end, struct dmidecode_info_t *info)
{
	memset(info, 0, sizeof(struct dmidecode_info_t));

	if (header_ptr + 0x19 > header_end) {
		return;
	}

	dmidecode_get_string(info->system_information.manufacturer, info->system_information.manufacturer + sizeof(info->system_information.manufacturer), header_ptr[0x04], strings_ptr, strings_end);
	dmidecode_get_string(info->system_information.product_name, info->system_information.product_name + sizeof(info->system_information.product_name), header_ptr[0x05], strings_ptr, strings_end);
	dmidecode_get_string(info->system_information.version, info->system_information.version + sizeof(info->system_information.version), header_ptr[0x06], strings_ptr, strings_end);
	dmidecode_get_string(info->system_information.serial_number, info->system_information.serial_number + sizeof(info->system_information.serial_number), header_ptr[0x07], strings_ptr, strings_end);
	memcpy(&info->system_information.uuid, header_ptr + 0x08, 16);
}

static void dmidecode_get_processor_information(uint8_t *header_ptr, uint8_t *header_end, const char *strings_ptr, const char *strings_end, struct dmidecode_info_t *info)
{
	memset(info, 0, sizeof(struct dmidecode_info_t));

	if (header_ptr + 0x20 > header_end) {
		return;
	}

	dmidecode_get_string(info->processor_information.manufacturer, info->processor_information.manufacturer + sizeof(info->processor_information.manufacturer), header_ptr[0x07], strings_ptr, strings_end);
	dmidecode_get_string(info->processor_information.version, info->processor_information.version + sizeof(info->processor_information.version), header_ptr[0x10], strings_ptr, strings_end);
}

static void dmidecode_get_memory_device(uint8_t *header_ptr, uint8_t *header_end, const char *strings_ptr, const char *strings_end, struct dmidecode_info_t *info)
{
	memset(info, 0, sizeof(struct dmidecode_info_t));

	if (header_ptr + 0x1B > header_end) {
		return;
	}

	uint16_t memory_size = mem_int_read_le_u16(header_ptr + 0x0C);
	if (memory_size == 0) {
		return;
	}

	dmidecode_get_string(info->memory_device.manufacturer, info->memory_device.manufacturer + sizeof(info->memory_device.manufacturer), header_ptr[0x17], strings_ptr, strings_end);
	dmidecode_get_string(info->memory_device.serial_number, info->memory_device.serial_number + sizeof(info->memory_device.serial_number), header_ptr[0x18], strings_ptr, strings_end);
	dmidecode_get_string(info->memory_device.part_number, info->memory_device.part_number + sizeof(info->memory_device.part_number), header_ptr[0x1A], strings_ptr, strings_end);
	info->memory_device.installed = true;
}

bool dmidecode_get_type(struct netbuf *dmi, uint8_t dmi_type, uint8_t index, struct dmidecode_info_t *info)
{
	uint8_t *ptr = netbuf_get_ptr(dmi);
	uint8_t *end = ptr + netbuf_get_remaining(dmi);

	uint8_t length;
	while (1) {
		if (ptr + 4 > end) {
			DEBUG_WARN("not found");
			return false;
		}

		uint8_t type = ptr[0];
		length = ptr[1];

		if (length < 4) {
			DEBUG_WARN("bad length");
			return false;
		}
		if (ptr + length > end) {
			DEBUG_WARN("bad length");
			return false;
		}

		if (type != dmi_type) {
			ptr = dmidecode_skip_strings(ptr + length, end);
			continue;
		}

		if (index == 0) {
			break;
		}

		index--;
		ptr = dmidecode_skip_strings(ptr + length, end);
	}

	uint8_t *header_ptr = ptr;
	uint8_t *header_end = ptr + length;
	const char *strings_ptr = (const char *)header_end;
	const char *strings_end = (const char *)dmidecode_skip_strings(header_end, end);

	switch (dmi_type) {
	case DMIDECODE_DMI_TYPE_SYSTEM_INFORMATION:
		dmidecode_get_system_information(header_ptr, header_end, strings_ptr, strings_end, info);
		return true;

	case DMIDECODE_DMI_TYPE_PROCESSOR_INFORMATION:
		dmidecode_get_processor_information(header_ptr, header_end, strings_ptr, strings_end, info);
		return true;

	case DMIDECODE_DMI_TYPE_MEMORY_DEVICE:
		dmidecode_get_memory_device(header_ptr, header_end, strings_ptr, strings_end, info);
		return true;

	default:
		return false;
	}
}

struct netbuf *dmidecode_load(void)
{
	struct file_t *dmi_file = file_open_read("/sys/firmware/dmi/tables/DMI");
	if (!dmi_file) {
		DEBUG_WARN("failed to open dmi data (%d)", errno);
		return NULL;
	}

	size_t dmi_size = (size_t)file_get_size(dmi_file, 0);
	if (dmi_size == 0) {
		DEBUG_WARN("failed to get size of dmi data (%d)", errno);
		file_close(dmi_file);
		return NULL;
	}

	struct netbuf *dmi = netbuf_alloc_with_fwd_space(dmi_size);
	if (!dmi) {
		DEBUG_WARN("out of memory");
		file_close(dmi_file);
		return NULL;
	}

	if (file_read(dmi_file, netbuf_get_ptr(dmi), dmi_size) != dmi_size) {
		DEBUG_WARN("failed to read dmi data");
		netbuf_free(dmi);
		file_close(dmi_file);
		return NULL;
	}

	file_close(dmi_file);
	return dmi;
}
