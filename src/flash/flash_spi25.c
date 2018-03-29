/*
 * ./src/flash/flash_spi25.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("flash_spi25");

#define FLASH_MAX_READ_SIZE 1024
/* Write size is set by the flash chip (256 byte pages) */
#define FLASH_MAX_WRITE_SIZE 256
/* Erase size is set by the flash chip (4k sector, 64k block) */
#define FLASH_SMALL_ERASE_SIZE 4096
#define FLASH_LARGE_ERASE_SIZE 65536

#define FLASH_OPCODE_PAGE_PROGRAM 0x02
#define FLASH_OPCODE_WRITE_DISABLE 0x04
#define FLASH_OPCODE_READ_STATUS_REGISTER 0x05
#define FLASH_OPCODE_WRITE_ENABLE 0x06
#define FLASH_OPCODE_FAST_READ 0x0B
#define FLASH_OPCODE_SECTOR_ERASE_4K 0x20
#define FLASH_OPCODE_ENABLE_RESET 0x66
#define FLASH_OPCODE_RESET_DEVICE 0x99
#define FLASH_OPCODE_JEDEC_ID 0x9F
#define FLASH_OPCODE_ENTER_4BYTE_ADDRESS_MODE 0xB7
#define FLASH_OPCODE_BLOCK_ERASE_64K 0xD8

#if (FLASH_DEV_SIZE > 16 * 1024 * 1024)
#error serial nor flash larger than 16MB not supported
#endif

struct flash_spi25_t {
	struct spinlock lock;
	struct spi_master_instance *spi;
	uint32_t flash_id;

	struct flash_stats_t stats;
};

static struct flash_spi25_t flash_spi25;

static inline void flash_set_byte(uint8_t **pptr, uint8_t v)
{
	uint8_t *ptr = *pptr;
	*ptr++ = v;
	*pptr = ptr;
}

static inline void flash_set_address(uint8_t **pptr, addr_t addr)
{
	uint8_t *ptr = *pptr;

	*ptr++ = (uint8_t)(addr >> 16);
	*ptr++ = (uint8_t)(addr >> 8);
	*ptr++ = (uint8_t)(addr >> 0);

	*pptr = ptr;
}

static bool flash_wait_until_complete(uint32_t poll_delay_fast_ticks)
{
	while (1) {
		timer_sleep_fast(poll_delay_fast_ticks);

		uint8_t send[1], recv[1];
		send[0] = FLASH_OPCODE_READ_STATUS_REGISTER;

		if (!spi_master_send_then_recv(flash_spi25.spi, send, 1, recv, 1)) {
			DEBUG_ERROR("flash_wait_until_complete spi error");
			return false;
		}

		if ((recv[0] & 0x01) == 0) { /* busy flag */
			break;
		}
	}

	return true;
}

static void flash_read_internal(addr_t addr, void *dst, size_t length)
{
	DEBUG_ASSERT(addr + length <= FLASH_DEV_SIZE, "flash_read beyond end of flash @%08X", addr);
	uint8_t *dst8 = (uint8_t *)dst;
	addr_t end = addr + length;

	DEBUG_TRACE("flash_read %08X %u", addr, end - addr);
	uint32_t start_time = timer_get_fast_ticks();

	while (addr < end) {
		if ((addr & 0x0003FFFF) == 0) {
			DEBUG_TRACE("flash_read %08X", addr);
		}

		addr_t chunk_end = (addr + FLASH_MAX_READ_SIZE) & ~(FLASH_MAX_READ_SIZE - 1);
		if (chunk_end > end) {
			chunk_end = end;
		}

		size_t len = chunk_end - addr;

		uint8_t send[6];
		uint8_t *ptr = send;
		flash_set_byte(&ptr, FLASH_OPCODE_FAST_READ);
		flash_set_address(&ptr, addr);
		flash_set_byte(&ptr, 0x00); /* dummy */

		if (!spi_master_send_then_recv(flash_spi25.spi, send, ptr - send, dst8, len)) {
			DEBUG_ERROR("flash_read @%08X len %u failed", addr, len);
			memset(dst8, 0xFF, end - addr);
			return;
		}

		dst8 += len;
		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_spi25.stats.read_bytes += len;
		flash_spi25.stats.read_time += (uint32_t)(current_time - start_time);
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
		if ((addr & 0x0003FFFF) == 0) {
			DEBUG_TRACE("flash_write %08X", addr);
		}

		addr_t chunk_end = (addr + FLASH_MAX_WRITE_SIZE) & ~(FLASH_MAX_WRITE_SIZE - 1);
		if (chunk_end > end) {
			chunk_end = end;
		}

		size_t len = chunk_end - addr;

		uint8_t send[5 + FLASH_MAX_WRITE_SIZE];
		send[0] = FLASH_OPCODE_WRITE_ENABLE;

		if (!spi_master_send_only(flash_spi25.spi, send, 1)) {
			DEBUG_ERROR("flash_write @%08X failed", addr);
			return;
		}

		uint8_t *ptr = send;
		flash_set_byte(&ptr, FLASH_OPCODE_PAGE_PROGRAM);
		flash_set_address(&ptr, addr);
		memcpy(ptr, src8, len);
		ptr += len;

		if (!spi_master_send_only(flash_spi25.spi, send, ptr - send)) {
			DEBUG_ERROR("flash_write @%08X failed", addr);
			return;
		}

		if (!flash_wait_until_complete(FAST_TICK_RATE_US * 10)) {
			DEBUG_ERROR("flash_write @%08X failed", addr);
			return;
		}

		src8 += len;
		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_spi25.stats.write_bytes += len;
		flash_spi25.stats.write_time += (uint32_t)(current_time - start_time);
		start_time = current_time;
	}
}

static bool flash_erase_page(addr_t addr, uint8_t opcode)
{
	uint8_t send[5];
	send[0] = FLASH_OPCODE_WRITE_ENABLE;

	if (!spi_master_send_only(flash_spi25.spi, send, 1)) {
		DEBUG_ERROR("flash_erase @%08X failed", addr);
		return false;
	}

	uint8_t *ptr = send;
	flash_set_byte(&ptr, opcode);
	flash_set_address(&ptr, addr);

	if (!spi_master_send_only(flash_spi25.spi, send, ptr - send)) {
		DEBUG_ERROR("flash_erase @%08X failed", addr);
		return false;
	}

	if (!flash_wait_until_complete(FAST_TICK_RATE_MS)) {
		DEBUG_ERROR("flash_erase @%08X failed", addr);
		return false;
	}

	return true;
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
		if ((addr & 0x0003FFFF) == 0) {
			DEBUG_TRACE("flash_erase %08X", addr);
		}

		size_t len;
		if (((addr & (FLASH_LARGE_ERASE_SIZE - 1)) == 0) && (end - addr >= FLASH_LARGE_ERASE_SIZE)) {
			len = FLASH_LARGE_ERASE_SIZE;
			flash_erase_page(addr, FLASH_OPCODE_BLOCK_ERASE_64K);
		} else {
			len = FLASH_SMALL_ERASE_SIZE;
			flash_erase_page(addr, FLASH_OPCODE_SECTOR_ERASE_4K);
		}

		addr += len;

		uint32_t current_time = timer_get_fast_ticks();
		flash_spi25.stats.erase_bytes += len;
		flash_spi25.stats.erase_time += (uint32_t)(current_time - start_time);
		start_time = current_time;
	}
}

void flash_read(addr_t addr, void *dst, size_t length)
{
	spinlock_lock(&flash_spi25.lock);
	flash_read_internal(addr, dst, length);
	spinlock_unlock(&flash_spi25.lock);
}

void flash_write(addr_t addr, const void *src, size_t length)
{
	spinlock_lock(&flash_spi25.lock);
	flash_write_internal(addr, src, length);
	spinlock_unlock(&flash_spi25.lock);
}

void flash_erase(addr_t addr, size_t length)
{
	spinlock_lock(&flash_spi25.lock);
	flash_erase_internal(addr, length);
	spinlock_unlock(&flash_spi25.lock);
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
	if ((flash_spi25.stats.read_bytes > 0) && (flash_spi25.stats.read_time > 0)) {
		DEBUG_INFO("read %llu bytes in %llums = %lluB/s", flash_spi25.stats.read_bytes, flash_spi25.stats.read_time / FAST_TICK_RATE_MS, flash_spi25.stats.read_bytes * FAST_TICK_RATE / flash_spi25.stats.read_time);
	}
	if ((flash_spi25.stats.write_bytes > 0) && (flash_spi25.stats.write_time > 0)) {
		DEBUG_INFO("write %llu bytes in %llums = %lluB/s", flash_spi25.stats.write_bytes, flash_spi25.stats.write_time / FAST_TICK_RATE_MS, flash_spi25.stats.write_bytes * FAST_TICK_RATE / flash_spi25.stats.write_time);
	}
	if ((flash_spi25.stats.erase_bytes > 0) && (flash_spi25.stats.erase_time > 0)) {
		DEBUG_INFO("erase %llu bytes in %llums = %lluB/s", flash_spi25.stats.erase_bytes, flash_spi25.stats.erase_time / FAST_TICK_RATE_MS, flash_spi25.stats.erase_bytes * FAST_TICK_RATE / flash_spi25.stats.erase_time);
	}
}

void flash_get_stats(struct flash_stats_t *stats)
{
	spinlock_lock(&flash_spi25.lock);
	memcpy(stats, &flash_spi25.stats, sizeof(struct flash_stats_t));
	spinlock_unlock(&flash_spi25.lock);
}

void flash_print_stats(void)
{
	spinlock_lock(&flash_spi25.lock);
	flash_print_stats_internal();
	spinlock_unlock(&flash_spi25.lock);
}

void flash_reset_stats(void)
{
	spinlock_lock(&flash_spi25.lock);
	memset(&flash_spi25.stats, 0, sizeof(struct flash_stats_t));
	spinlock_unlock(&flash_spi25.lock);
}

static void flash_software_reset(void)
{
	uint8_t send[1];
	send[0] = FLASH_OPCODE_ENABLE_RESET;
	if (!spi_master_send_only(flash_spi25.spi, send, 1)) {
		DEBUG_ERROR("flash_shutdown spi error");
		return;
	}

	send[0] = FLASH_OPCODE_RESET_DEVICE;
	if (!spi_master_send_only(flash_spi25.spi, send, 1)) {
		DEBUG_ERROR("flash_shutdown spi error");
		return;
	}

	timer_sleep_fast(FAST_TICK_RATE_MS * 50);
}

/* All threads must be stopped before calling flash_shutdown(). */
void flash_shutdown(struct system_crash_dump_t *crash_dump)
{
	flash_print_stats_internal();

	uint8_t send[1];
	send[0] = FLASH_OPCODE_WRITE_DISABLE;
	if (!spi_master_send_only(flash_spi25.spi, send, 1)) {
		DEBUG_ERROR("flash_shutdown spi error");
		return;
	}

	if (!flash_wait_until_complete(FAST_TICK_RATE_US * 10)) {
		DEBUG_ERROR("flash_shutdown spi error");
		return;
	}

#if defined(SYSTEM_CRASH_DUMP_ADDR)
	if (crash_dump) {
		flash_erase_internal(SYSTEM_CRASH_DUMP_ADDR, sizeof(struct system_crash_dump_t));
		flash_write_internal(SYSTEM_CRASH_DUMP_ADDR, crash_dump, sizeof(struct system_crash_dump_t));
	}
#endif

	flash_software_reset();
}

uint32_t flash_get_id(void)
{
	return flash_spi25.flash_id;
}

void flash_init(void)
{
	spinlock_init(&flash_spi25.lock, 0);

	flash_spi25.spi = spi_master_instance_alloc(FLASH_SPI_BUS_INDEX); 
	if (!flash_spi25.spi) {
		return;
	}

	flash_software_reset();

	uint8_t send[1], recv[3];
	send[0] = FLASH_OPCODE_JEDEC_ID;

	if (!spi_master_send_then_recv(flash_spi25.spi, send, 1, recv, 3)) {
		return;
	}

	flash_spi25.flash_id = ((uint32_t)recv[0] << 16) | ((uint32_t)recv[1] << 8) | ((uint32_t)recv[2] << 0);
	DEBUG_INFO("flash id %06x", flash_spi25.flash_id);
}
