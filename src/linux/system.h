/*
 * ./src/linux/system.h
 *
 * Copyright © 2007 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define SYSTEM_CRASH_DUMP_MAGIC 0xE5592573

struct system_crash_dump_t {
	uint32_t data[16];
};

extern struct mqueue_t *system_app_queue;
#define system_data_queue system_app_queue

extern void system_init(void);
extern void system_reset(void) __attribute__((noreturn));

extern uint32_t system_detect_file_limit(void);
extern void system_update_file_limit(uint32_t new_limit);

extern void system_drop_root(void);
