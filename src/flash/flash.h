/*
 * ./src/flash/flash.h
 *
 * Copyright © 2012-2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct flash_stats_t {
	uint64_t read_bytes;
	uint64_t read_time;
	uint64_t write_bytes;
	uint64_t write_time;
	uint64_t erase_bytes;
	uint64_t erase_time;
};

extern void flash_init(void);
extern void flash_shutdown(struct system_crash_dump_t *crash_dump);
extern void flash_read(addr_t addr, void *dst, size_t length);
extern void flash_write(addr_t addr, const void *src, size_t length);
extern void flash_erase(addr_t addr, size_t length);
extern void flash_writeprotect_bootsector(size_t size);
extern void flash_writeprotect_clear(void);
extern uint32_t flash_get_id(void);

extern void flash_get_stats(struct flash_stats_t *stats);
extern void flash_print_stats(void);
extern void flash_reset_stats(void);
