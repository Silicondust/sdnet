/*
 * hash32.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("hash32");

static const uint32_t hash32_lookup_low[16] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91
};

static const uint32_t hash32_lookup_high[16] = {
	0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
	0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
};

uint32_t hash32_append(uint32_t hash, const void *ptr, size_t length)
{
	const uint8_t *ptr8 = (uint8_t *)ptr;

	while (length--) {
		uint8_t x = (uint8_t)hash ^ *ptr8++;
		hash >>= 8;
		hash ^= hash32_lookup_low[x & 0x0F];
		hash ^= hash32_lookup_high[x >> 4];
	}

	return hash;
}

uint32_t hash32_append_str(uint32_t hash, const char *str)
{
	const uint8_t *ptr8 = (uint8_t *)str;

	while (*ptr8) {
		uint8_t x = (uint8_t)hash ^ *ptr8++;
		hash >>= 8;
		hash ^= hash32_lookup_low[x & 0x0F];
		hash ^= hash32_lookup_high[x >> 4];
	}

	return hash;
}

uint32_t hash32_append_nb(uint32_t hash, struct netbuf *nb, size_t length)
{
#if defined(IPOS)
	while (length > 0) {
		uint8_t *block_start, *block_end;
		uint8_t *ptr = netbuf_direct_access(nb, &block_start, &block_end);

		size_t block_length = block_end - block_start;
		if (block_length > length) {
			block_length = length;
		}

		hash = hash32_append(hash, ptr, block_length);
		netbuf_advance_pos(nb, block_length);
		length -= block_length;
	}

	return hash;
#else
	return hash32_append(hash, netbuf_get_ptr(nb), length);
#endif
}
