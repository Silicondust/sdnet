/*
 * flash_file.c
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("flash_file");

#if !defined(FLASH_PAGE_SIZE)
#define FLASH_PAGE_SIZE 4096
#endif

#if !defined(FLASH_FILE_NAME)
#define FLASH_FILE_NAME "flash.bin"
#endif

static FILE *flash_file_fp = NULL;

static FILE *flash_file_get_fp_if_exists(void)
{
	if (flash_file_fp) {
		return flash_file_fp;
	}

	flash_file_fp = fopen_utf8(FLASH_FILE_NAME, "r+b");
	return flash_file_fp;
}

static FILE *flash_file_get_fp_create(void)
{
	if (flash_file_fp) {
		return flash_file_fp;
	}

	flash_file_fp = fopen_utf8(FLASH_FILE_NAME, "r+b");
	if (flash_file_fp) {
		return flash_file_fp;
	}

	flash_file_fp = fopen_utf8(FLASH_FILE_NAME, "w+b");
	DEBUG_ASSERT(flash_file_fp, "failed to create " FLASH_FILE_NAME " file");
	return flash_file_fp;
}

void flash_read(addr_t addr, void *dst, size_t length)
{
	FILE *fp = flash_file_get_fp_if_exists();
	if (!fp) {
		memset(dst, 0xFF, length);
		return;
	}

	fseek(fp, 0, SEEK_END);

	long file_length = ftell(fp);
	if ((long)addr >= file_length) {
		memset(dst, 0xFF, length);
		return;
	}

	fseek(fp, (long)addr, SEEK_SET);

	size_t actual = fread(dst, 1, length, fp);
	if (actual < length) {
		memset((uint8_t *)dst + actual, 0xFF, length - actual);
	}
}

void flash_write(addr_t addr, const void *src, size_t length)
{
	FILE *fp = flash_file_get_fp_create();
	if (!fp) {
		return;
	}

	fseek(fp, 0, SEEK_END);

	long file_length = ftell(fp);
	if (file_length < 0) {
		return;
	}

	while ((addr_t)file_length < addr) {
		fputc(0xFF, fp);
		file_length++;
	}

	if ((addr_t)file_length > addr) {
		fseek(fp, (long)addr, SEEK_SET);
	}

	fwrite(src, 1, length, fp);
	fflush(fp);
}

void flash_erase(addr_t addr, size_t length)
{
	addr_t end = (addr + length + FLASH_PAGE_SIZE - 1) & ~(FLASH_PAGE_SIZE - 1);
	addr &= ~(FLASH_PAGE_SIZE - 1);

	FILE *fp = flash_file_get_fp_create();
	if (!fp) {
		return;
	}

	fseek(fp, 0, SEEK_END);

	long file_length = ftell(fp);
	if (file_length < 0) {
		return;
	}

	while ((addr_t)file_length < addr) {
		fputc(0xFF, fp);
		file_length++;
	}

	if ((addr_t)file_length > addr) {
		fseek(fp, (long)addr, SEEK_SET);
	}

	while (addr < end) {
		fputc(0xFF, fp);
		addr++;
	}

	fflush(fp);
}

void flash_writeprotect_bootsector(size_t size)
{
	DEBUG_ERROR("flash_writeprotect_bootsector not implemented");
}

void flash_writeprotect_clear(void)
{
	DEBUG_ERROR("flash_writeprotect_clear not implemented");
}

#if (RUNTIME_DEBUG)
void flash_print_stats(void)
{
}

void flash_reset_stats(void)
{
}
#endif

void flash_shutdown(struct system_crash_dump_t *crash_dump)
{
	if (!flash_file_fp) {
		return;
	}

	fclose(flash_file_fp);
	flash_file_fp = NULL;
}

void flash_init(void)
{
}
