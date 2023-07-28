/*
 * dmidecode.h
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DMIDECODE_DMI_TYPE_SYSTEM_INFORMATION 1
#define DMIDECODE_DMI_TYPE_PROCESSOR_INFORMATION 4
#define DMIDECODE_DMI_TYPE_MEMORY_DEVICE 17

struct dmidecode_info_t {
	union {
		struct {
			char manufacturer[64];
			char product_name[64];
			char version[64];
			char serial_number[64];
			struct guid uuid;
		} system_information;
		struct {
			char manufacturer[64];
			char version[64];
		} processor_information;
		struct {
			char manufacturer[64];
			char serial_number[64];
			char part_number[64];
			bool installed;
		} memory_device;
	};
};

extern struct netbuf *dmidecode_load(void);
extern bool dmidecode_get_type(struct netbuf *dmi, uint8_t dmi_type, uint8_t index, struct dmidecode_info_t *info);
