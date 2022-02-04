/*
 * gpt.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
THIS_FILE("gpt");

struct gpt_state_t {
	uint64_t total_sectors;
	uint64_t primary_header_location;
	uint64_t primary_array_location;
	uint64_t secondary_header_location;
	uint64_t secondary_array_location;
	uint64_t usable_begin;
	uint64_t usable_end;
	uint64_t partition_begin;
	uint64_t partition_end;
};

static void gpt_mem_write_guid(uint8_t *ptr, struct guid *guid)
{
	mem_int_write_le_u32(ptr + 0, guid->time_low);
	mem_int_write_le_u16(ptr + 4, guid->time_mid);
	mem_int_write_le_u16(ptr + 6, guid->time_hi_and_version);
	mem_int_write_u8(ptr + 8, guid->clock_seq_hi_and_reserved);
	mem_int_write_u8(ptr + 9, guid->clock_seq_low);
	memcpy(ptr + 10, guid->node, 6);
}

static uint32_t gpt_crc32_append(uint32_t crc, uint8_t *ptr, uint8_t *end)
{
	static const uint32_t netbuf_crc32_lookup_low[16] = {
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91
	};

	static const uint32_t netbuf_crc32_lookup_high[16] = {
		0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
		0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
	};

	while (ptr < end) {
		uint8_t x = (uint8_t)crc ^ *ptr++;
		crc >>= 8;
		crc ^= netbuf_crc32_lookup_low[x & 0x0F];
		crc ^= netbuf_crc32_lookup_high[x >> 4];
	}

	return crc;
}

static uint32_t gpt_crc32_complete(uint32_t crc)
{
	return crc ^ 0xFFFFFFFF;
}

static bool gpt_write_protective_mbr(struct file_t *dev_file, struct gpt_state_t *gpt_state)
{
	uint8_t buffer[512];
	memset(buffer, 0, 512);

	/* boot signature */
	mem_int_write_le_u16(buffer + 510, 0xAA55);

	/* partition 1 */
	uint64_t partition_size = gpt_state->total_sectors - 1;
	if (partition_size > 0x00000000FFFFFFFFULL) {
		partition_size = 0x00000000FFFFFFFFULL;
	}

	uint8_t *partition = buffer + 446;
	mem_int_write_u8(partition + 0, 0x00);
	mem_int_write_le_u24(partition + 1, 0x000200);
	mem_int_write_u8(partition + 4, 0xEE);
	mem_int_write_le_u24(partition + 5, 0xFFFFFF);
	mem_int_write_le_u32(partition + 8, 1);
	mem_int_write_le_u32(partition + 12, (uint32_t)partition_size);

	/* write mbr to disk */
	if (!file_seek_set(dev_file, 0)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("write failed (%d)", errno);
		return false;
	}

	return true;
}

static bool gpt_write_partition_header(struct file_t *dev_file, struct gpt_state_t *gpt_state, uint32_t partition_array_crc)
{
	/* primary gpt header */
	uint8_t buffer[512];
	memset(buffer, 0, 512);

	struct guid disk_unique_guid;
	guid_create_random(&disk_unique_guid);

	mem_int_write_le_u64(buffer + 0, 0x5452415020494645ULL);
	mem_int_write_le_u32(buffer + 8, 0x00010000);
	mem_int_write_le_u32(buffer + 12, 92);
	mem_int_write_le_u64(buffer + 24, gpt_state->primary_header_location);
	mem_int_write_le_u64(buffer + 32, gpt_state->secondary_header_location);
	mem_int_write_le_u64(buffer + 40, gpt_state->usable_begin);
	mem_int_write_le_u64(buffer + 48, gpt_state->usable_end - 1);
	gpt_mem_write_guid(buffer + 56, &disk_unique_guid);
	mem_int_write_le_u64(buffer + 72, gpt_state->primary_array_location);
	mem_int_write_le_u32(buffer + 80, 128);
	mem_int_write_le_u32(buffer + 84, 128);
	mem_int_write_le_u32(buffer + 88, partition_array_crc);

	uint32_t crc = 0xFFFFFFFF;
	crc = gpt_crc32_append(crc, buffer, buffer + 92);
	crc = gpt_crc32_complete(crc);
	mem_int_write_le_u32(buffer + 16, crc);

	if (!file_seek_set(dev_file, gpt_state->primary_header_location * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("write failed (%d)", errno);
		return false;
	}

	/* secondary gpt header */
	mem_int_write_le_u32(buffer + 16, 0);
	mem_int_write_le_u64(buffer + 24, gpt_state->secondary_header_location);
	mem_int_write_le_u64(buffer + 32, gpt_state->primary_header_location);
	mem_int_write_le_u64(buffer + 72, gpt_state->secondary_array_location);

	crc = 0xFFFFFFFF;
	crc = gpt_crc32_append(crc, buffer, buffer + 92);
	crc = gpt_crc32_complete(crc);
	mem_int_write_le_u32(buffer + 16, crc);

	if (!file_seek_set(dev_file, gpt_state->secondary_header_location * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("write failed (%d)", errno);
		return false;
	}

	return true;
}

static bool gpt_write_partition_array(struct file_t *dev_file, struct gpt_state_t *gpt_state, uint32_t *partition_array_crc)
{
	uint8_t zero[512];
	memset(zero, 0, 512);

	uint8_t buffer[512];
	memset(buffer, 0, 512);

	/* partition 1 */
	struct guid partition_type_guid;
	guid_read_string(&partition_type_guid, "0FC63DAF-8483-4772-8E79-3D69D8477DE4");

	struct guid partition_unique_guid;
	guid_create_random(&partition_unique_guid);

	uint64_t partition_attribute_flags = 0;

	uint8_t *partition = buffer;
	gpt_mem_write_guid(partition + 0, &partition_type_guid);
	gpt_mem_write_guid(partition + 16, &partition_unique_guid);
	mem_int_write_le_u64(partition + 32, gpt_state->partition_begin);
	mem_int_write_le_u64(partition + 40, gpt_state->partition_end - 1);
	mem_int_write_le_u64(partition + 48, partition_attribute_flags);

	/* Write primary partition array */
	if (!file_seek_set(dev_file, gpt_state->primary_array_location * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("write failed (%d)", errno);
		return false;
	}

	for (int i = 1; i < 32; i++) {
		if (file_write(dev_file, zero, 512) != 512) {
			DEBUG_ERROR("write failed (%d)", errno);
			return false;
		}
	}

	/* Write secondary partition array */
	if (!file_seek_set(dev_file, gpt_state->secondary_array_location * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("write failed (%d)", errno);
		return false;
	}

	for (int i = 1; i < 32; i++) {
		if (file_write(dev_file, zero, 512) != 512) {
			DEBUG_ERROR("write failed (%d)", errno);
			return false;
		}
	}

	/* CRC */
	uint32_t crc = 0xFFFFFFFF;
	crc = gpt_crc32_append(crc, buffer, buffer + 512);

	for (int i = 1; i < 32; i++) {
		crc = gpt_crc32_append(crc, zero, zero + 512);
	}

	*partition_array_crc = gpt_crc32_complete(crc);
	return true;
}

static bool gpt_write_partition_cleanup(struct file_t *dev_file, struct gpt_state_t *gpt_state)
{
	uint8_t zero[512];
	memset(zero, 0, 512);

	/* wipe area between usable start and partition 1, plus the fist 16k of the partition */
	if (!file_seek_set(dev_file, gpt_state->usable_begin * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	for (uint64_t i = gpt_state->usable_begin; i < gpt_state->partition_begin + 32; i++) {
		if (file_write(dev_file, zero, 512) != 512) {
			DEBUG_ERROR("write failed (%d)", errno);
			return false;
		}
	}

	/* wipe area between partition 1 end and usable end, plus the last 16k of the partition */
	if (!file_seek_set(dev_file, (gpt_state->partition_end - 32) * 512)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	for (uint64_t i = gpt_state->partition_end - 32; i < gpt_state->usable_end; i++) {
		if (file_write(dev_file, zero, 512) != 512) {
			DEBUG_ERROR("write failed (%d)", errno);
			return false;
		}
	}

	return true;
}

bool gpt_create_with_one_partition(struct file_t *dev_file)
{
	struct gpt_state_t gpt_state;
	memset(&gpt_state, 0, sizeof(struct gpt_state_t));

	/* Check size of dev */
	if (!file_seek_end(dev_file)) {
		DEBUG_ERROR("seek failed (%d)", errno);
		return false;
	}

	uint64_t dev_size = file_get_pos(dev_file, 0);
	if (dev_size <= 0) {
		DEBUG_ERROR("failed to determine size (%d)", errno);
		return false;
	}

	gpt_state.total_sectors = dev_size / 512;

	gpt_state.primary_header_location = 1;
	gpt_state.primary_array_location = gpt_state.primary_header_location + 1;
	gpt_state.usable_begin = gpt_state.primary_array_location + 32;

	gpt_state.secondary_header_location = gpt_state.total_sectors - 1;
	gpt_state.secondary_array_location = gpt_state.secondary_header_location - 32;
	gpt_state.usable_end = gpt_state.secondary_array_location;

	gpt_state.partition_begin = 2048;
	gpt_state.partition_end = (gpt_state.usable_end / 2048) * 2048;

	/* Write GPT partition array */
	uint32_t partition_array_crc;
	if (!gpt_write_partition_array(dev_file, &gpt_state, &partition_array_crc)) {
		return false;
	}

	/* Write GPT partition header */
	if (!gpt_write_partition_header(dev_file, &gpt_state, partition_array_crc)) {
		return false;
	}

	/* Wipe gaps and old filesystem headers */
	if (!gpt_write_partition_cleanup(dev_file, &gpt_state)) {
		return false;
	}

	/* Write protective MBR */
	if (!gpt_write_protective_mbr(dev_file, &gpt_state)) {
		return false;
	}

	/* Sync to disk */
	if (fsync(dev_file->fp) < 0) {
		DEBUG_ERROR("sync failed (%d)", errno);
		return false;
	}

	/* Trigger linux kernel to reload the partition table */
	if (ioctl(dev_file->fp, BLKRRPART) < 0) {
		DEBUG_ERROR("kernel failed to reload the parition table (%d)", errno);
		return false;
	}

	return true;
}

int gpt_mbr_is_blank(struct file_t *dev_file)
{
	if (!file_seek_set(dev_file, 0ULL)) {
		DEBUG_ERROR("file_seek_set failed");
		return -1;
	}

	uint32_t buffer32[512 / 4];
	if (file_read(dev_file, buffer32, 512) != 512) {
		DEBUG_ERROR("file_read failed (%d)", errno);
		return -1;
	}

	uint32_t *ptr32 = buffer32;
	uint32_t *end32 = buffer32 + (512 / 4);
	while (ptr32 < end32) {
		if (*ptr32++ != 0x00000000) {
			return 0;
		}
	}

	return 1;
}

bool gpt_mbr_wipe(struct file_t *dev_file)
{
	if (!file_seek_set(dev_file, 0ULL)) {
		DEBUG_ERROR("failed to seek to start (%d)", errno);
		return false;
	}

	uint8_t buffer[512];
	memset(buffer, 0, 512);

	if (file_write(dev_file, buffer, 512) != 512) {
		DEBUG_ERROR("failed to write (%d)", errno);
		return false;
	}

	if (fsync(dev_file->fp) < 0) {
		DEBUG_WARN("failed to sync (%d)", errno);
		return false;
	}

	return true;
}
