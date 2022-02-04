/*
 * hdparm.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define HDPARM_STANDBY_TIME_DISABLED 0

struct hdparm_identify_t {
	uint64_t sectors;
	char model_str[41];
	char serial_str[21];
};

struct hdparm_smart_id_decode_t;

struct hdparm_smart_entry_t {
	uint8_t id;
	uint8_t current;
	uint8_t worst;
	uint8_t threshold;
	uint16_t flags;
	uint8_t raw[6];
};

struct hdparm_smart_t {
	struct hdparm_smart_entry_t entry[30];
	uint8_t count;
	bool pass;
};

extern struct hdparm_smart_id_decode_t *hdparm_smart_id_decode_lookup(uint8_t id);
extern const char *hdparm_smart_id_get_name(struct hdparm_smart_id_decode_t *decode);
extern bool hdparm_smart_id_get_value_str(struct hdparm_smart_id_decode_t *decode, char *ptr, char *end, uint8_t raw[6]);

extern bool hdparm_get_identify(struct file_t *dev_file, struct hdparm_identify_t *identify);
extern bool hdparm_get_smart(struct file_t *dev_file, struct hdparm_smart_t *smart);
extern int8_t hdparm_get_smart_temperature(struct file_t *dev_file, int8_t value_on_error);
extern bool hdparm_set_standby_time(struct file_t *dev_file, uint32_t seconds);
extern bool hdparm_set_advanced_power_management(struct file_t *dev_file, uint8_t level);
