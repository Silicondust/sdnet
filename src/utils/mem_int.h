/*
 * mem_int.h
 *
 * Copyright © 2011,2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

static inline uint8_t mem_int_read_u8(uint8_t *ptr)
{
	return ptr[0];
}

static inline uint16_t mem_int_read_be_u16(uint8_t *ptr)
{
	return ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1] << 0);
}

static inline uint32_t mem_int_read_be_u32(uint8_t *ptr)
{
	return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | ((uint32_t)ptr[3] << 0);
}

static inline uint64_t mem_int_read_be_u64(uint8_t *ptr)
{
	return ((uint64_t)ptr[0] << 56) | ((uint64_t)ptr[1] << 48) | ((uint64_t)ptr[2] << 40) | ((uint64_t)ptr[3] << 32) |
		   ((uint64_t)ptr[4] << 24) | ((uint64_t)ptr[5] << 16) | ((uint64_t)ptr[6] <<  8) | ((uint64_t)ptr[7] <<  0);
}

static inline uint16_t mem_int_read_le_u16(uint8_t *ptr)
{
	return ((uint16_t)ptr[1] << 8) | ((uint16_t)ptr[0] << 0);
}

static inline uint32_t mem_int_read_le_u32(uint8_t *ptr)
{
	return ((uint32_t)ptr[3] << 24) | ((uint32_t)ptr[2] << 16) | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[0] << 0);
}

static inline uint64_t mem_int_read_le_u64(uint8_t *ptr)
{
	return ((uint64_t)ptr[7] << 56) | ((uint64_t)ptr[6] << 48) | ((uint64_t)ptr[5] << 40) | ((uint64_t)ptr[4] << 32) |
		   ((uint64_t)ptr[3] << 24) | ((uint64_t)ptr[2] << 16) | ((uint64_t)ptr[1] <<  8) | ((uint64_t)ptr[0] <<  0);
}

static inline void mem_int_write_u8(uint8_t *ptr, uint8_t v)
{
	ptr[0] = v;
}

static inline void mem_int_write_be_u16(uint8_t *ptr, uint16_t v)
{
	ptr[0] = (uint8_t)(v >> 8);
	ptr[1] = (uint8_t)(v >> 0);
}

static inline void mem_int_write_be_u32(uint8_t *ptr, uint32_t v)
{
	ptr[0] = (uint8_t)(v >> 24);
	ptr[1] = (uint8_t)(v >> 16);
	ptr[2] = (uint8_t)(v >> 8);
	ptr[3] = (uint8_t)(v >> 0);
}

static inline void mem_int_write_be_u64(uint8_t *ptr, uint64_t v)
{
	ptr[0] = (uint8_t)(v >> 56);
	ptr[1] = (uint8_t)(v >> 48);
	ptr[2] = (uint8_t)(v >> 40);
	ptr[3] = (uint8_t)(v >> 32);
	ptr[4] = (uint8_t)(v >> 24);
	ptr[5] = (uint8_t)(v >> 16);
	ptr[6] = (uint8_t)(v >> 8);
	ptr[7] = (uint8_t)(v >> 0);
}

static inline void mem_int_write_le_u16(uint8_t *ptr, uint16_t v)
{
	ptr[0] = (uint8_t)(v >> 0);
	ptr[1] = (uint8_t)(v >> 8);
}

static inline void mem_int_write_le_u32(uint8_t *ptr, uint32_t v)
{
	ptr[0] = (uint8_t)(v >> 0);
	ptr[1] = (uint8_t)(v >> 8);
	ptr[2] = (uint8_t)(v >> 16);
	ptr[3] = (uint8_t)(v >> 24);
}

static inline void mem_int_write_le_u64(uint8_t *ptr, uint64_t v)
{
	ptr[0] = (uint8_t)(v >> 0);
	ptr[1] = (uint8_t)(v >> 8);
	ptr[2] = (uint8_t)(v >> 16);
	ptr[3] = (uint8_t)(v >> 24);
	ptr[4] = (uint8_t)(v >> 32);
	ptr[5] = (uint8_t)(v >> 40);
	ptr[6] = (uint8_t)(v >> 48);
	ptr[7] = (uint8_t)(v >> 56);
}
