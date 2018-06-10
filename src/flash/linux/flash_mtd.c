/*
 * flash_mtd.c
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <os.h>
#include <mtd/mtd-user.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("flash_mtd");

#define FLASH_MTD "/dev/mtd0"
#define FLASH_MAX_READ_SIZE 65536
#define FLASH_MAX_WRITE_SIZE 65536

struct flash_mtd_t {
	struct spinlock lock;
	int fd;

	struct flash_stats_t stats;
};

static struct flash_mtd_t flash_mtd;

static void flash_wait_for_complete(addr_t addr)
{
	off_t offset = lseek(flash_mtd.fd, addr, SEEK_SET);
	if (offset != addr) {
		DEBUG_ERROR("flash_wait seek @%08X failed: %d", addr, errno);
		return;
	}

	uint8_t v; 
	if (read(flash_mtd.fd, &v, 1) != 1) {
		DEBUG_ERROR("flash_wait read @%08X failed: %d", addr, errno);
		return;
	}
}

static void flash_read_internal(addr_t addr, void *dst, size_t length)
{
	DEBUG_ASSERT(addr + length <= FLASH_DEV_SIZE, "flash_read beyond end of flash @%08X", addr);
	uint8_t *dst8 = (uint8_t *)dst;
	addr_t end = addr + length;

	DEBUG_TRACE("flash_read %08X %u", addr, end - addr);
	uint32_t start_time = timer_get_fast_ticks();

	off_t offset = lseek(flash_mtd.fd, addr, SEEK_SET);
	if (offset != addr) {
		DEBUG_ERROR("flash_read seek @%08X failed: %d", addr, errno);
		memset(dst8, 0xFF, end - addr);
		return;
	}

	while (addr < end) {
		addr_t chunk_end = (addr + FLASH_MAX_READ_SIZE) & ~(FLASH_MAX_READ_SIZE - 1);
		if (chunk_end > end) {
			chunk_end = end;
		}

		size_t len = chunk_end - addr;

		if (read(flash_mtd.fd, dst8, len) != len) {
			DEBUG_ERROR("flash_read @%08X failed: %d", addr, errno);
			memset(dst8, 0xFF, end - addr);
			return;
		}

		dst8 += len;
		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_mtd.stats.read_bytes += len;
		flash_mtd.stats.read_time += (uint32_t)(current_time - start_time);
		start_time = current_time;
	}
}

static void flash_write_internal(addr_t addr, const void *src, size_t length)
{
	DEBUG_ASSERT(addr + length <= FLASH_DEV_SIZE, "flash_write beyond end of flash @%08X", addr);
	uint8_t *src8 = (uint8_t *)src;
	addr_t end = addr + length;

	DEBUG_TRACE("flash_write %08X %u", addr, end - addr);
	uint32_t start_time = timer_get_fast_ticks();

	while (addr < end) {
		off_t offset = lseek(flash_mtd.fd, addr, SEEK_SET);
		if (offset != addr) {
			DEBUG_ERROR("flash_write seek @%08X failed: %d", addr, errno);
			return;
		}

		addr_t chunk_end = (addr + FLASH_MAX_WRITE_SIZE) & ~(FLASH_MAX_WRITE_SIZE - 1);
		if (chunk_end > end) {
			chunk_end = end;
		}

		size_t len = chunk_end - addr;

		if (write(flash_mtd.fd, src8, len) != len) {
			DEBUG_ERROR("flash_write @%08X failed: %d", addr, errno);
			return;
		}

		flash_wait_for_complete(addr);

		src8 += len;
		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_mtd.stats.write_bytes += len;
		flash_mtd.stats.write_time += (uint32_t)(current_time - start_time);
		start_time = current_time;
	}
}

static void flash_erase_internal(addr_t addr, size_t length)
{
	addr_t end = addr + length;
	DEBUG_ASSERT(end <= FLASH_DEV_SIZE, "flash_erase beyond end of flash @%08X", addr);

	addr = addr & ~(FLASH_PAGE_SIZE - 1);
	end = (end + FLASH_PAGE_SIZE - 1) & ~(FLASH_PAGE_SIZE - 1);

	DEBUG_TRACE("flash_erase %08X %u", addr, end - addr);
	uint32_t start_time = timer_get_fast_ticks();

	while (addr < end) {
		size_t len = FLASH_PAGE_SIZE;

		struct erase_info_user erase;
		erase.start = addr;
		erase.length = len;
		if (ioctl(flash_mtd.fd, MEMERASE, &erase) < 0) {
			DEBUG_ERROR("flash_erase @%08X failed: %d", addr, errno);
			return;
		}

		flash_wait_for_complete(addr);

		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_mtd.stats.erase_bytes += len;
		flash_mtd.stats.erase_time += (uint32_t)(current_time - start_time);
		start_time = current_time;
	}
}

void flash_read(addr_t addr, void *dst, size_t length)
{
	spinlock_lock(&flash_mtd.lock);
	flash_read_internal(addr, dst, length);
	spinlock_unlock(&flash_mtd.lock);
}

void flash_write(addr_t addr, const void *src, size_t length)
{
	spinlock_lock(&flash_mtd.lock);
	flash_write_internal(addr, src, length);
	spinlock_unlock(&flash_mtd.lock);
}

void flash_erase(addr_t addr, size_t length)
{
	spinlock_lock(&flash_mtd.lock);
	flash_erase_internal(addr, length);
	spinlock_unlock(&flash_mtd.lock);
}

void flash_writeprotect_bootsector(size_t size)
{
	DEBUG_ERROR("flash_writeprotect_bootsector not implemented");
}

void flash_writeprotect_clear(void)
{
	DEBUG_ERROR("flash_writeprotect_clear not implemented");
}

static void flash_print_stats_internal(void)
{
	if ((flash_mtd.stats.read_bytes > 0) && (flash_mtd.stats.read_time > 0)) {
		DEBUG_INFO("read %llu bytes in %llums = %lluB/s", flash_mtd.stats.read_bytes, flash_mtd.stats.read_time / FAST_TICK_RATE_MS, flash_mtd.stats.read_bytes * FAST_TICK_RATE / flash_mtd.stats.read_time);
	}
	if ((flash_mtd.stats.write_bytes > 0) && (flash_mtd.stats.write_time > 0)) {
		DEBUG_INFO("write %llu bytes in %llums = %lluB/s", flash_mtd.stats.write_bytes, flash_mtd.stats.write_time / FAST_TICK_RATE_MS, flash_mtd.stats.write_bytes * FAST_TICK_RATE / flash_mtd.stats.write_time);
	}
	if ((flash_mtd.stats.erase_bytes > 0) && (flash_mtd.stats.erase_time > 0)) {
		DEBUG_INFO("erase %llu bytes in %llums = %lluB/s", flash_mtd.stats.erase_bytes, flash_mtd.stats.erase_time / FAST_TICK_RATE_MS, flash_mtd.stats.erase_bytes * FAST_TICK_RATE / flash_mtd.stats.erase_time);
	}
}

void flash_get_stats(struct flash_stats_t *stats)
{
	spinlock_lock(&flash_mtd.lock);
	memcpy(stats, &flash_mtd.stats, sizeof(struct flash_stats_t));
	spinlock_unlock(&flash_mtd.lock);
}

void flash_print_stats(void)
{
	spinlock_lock(&flash_mtd.lock);
	flash_print_stats_internal();
	spinlock_unlock(&flash_mtd.lock);
}

void flash_reset_stats(void)
{
	spinlock_lock(&flash_mtd.lock);
	memset(&flash_mtd.stats, 0, sizeof(struct flash_stats_t));
	spinlock_unlock(&flash_mtd.lock);
}

/* All threads must be stopped before calling flash_shutdown(). */
void flash_shutdown(struct system_crash_dump_t *crash_dump)
{
	flash_print_stats_internal();
}

void flash_init(void)
{
	flash_mtd.fd = open(FLASH_MTD, O_SYNC | O_RDWR);
	if (flash_mtd.fd < 0) {
		DEBUG_ERROR("flash_init error");
	}
}
