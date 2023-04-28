/*
 * hash64.c
 *
 * Copyright © 2012-2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("hash64");

static const uint64_t hash64_lookup_low[16] = {
	0x0000000000000000ULL, 0xB32E4CBE03A75F6FULL, 0xF4843657A840A05BULL, 0x47AA7AE9ABE7FF34ULL,
	0x7BD0C384FF8F5E33ULL, 0xC8FE8F3AFC28015CULL, 0x8F54F5D357CFFE68ULL, 0x3C7AB96D5468A107ULL,
	0xF7A18709FF1EBC66ULL, 0x448FCBB7FCB9E309ULL, 0x0325B15E575E1C3DULL, 0xB00BFDE054F94352ULL,
	0x8C71448D0091E255ULL, 0x3F5F08330336BD3AULL, 0x78F572DAA8D1420EULL, 0xCBDB3E64AB761D61ULL
};
static const uint64_t hash64_lookup_high[16] = {
	0x0000000000000000ULL, 0x7D9BA13851336649ULL, 0xFB374270A266CC92ULL, 0x86ACE348F355AADBULL,
	0x64B62BCAEBC387A1ULL, 0x192D8AF2BAF0E1E8ULL, 0x9F8169BA49A54B33ULL, 0xE21AC88218962D7AULL,
	0xC96C5795D7870F42ULL, 0xB4F7F6AD86B4690BULL, 0x325B15E575E1C3D0ULL, 0x4FC0B4DD24D2A599ULL,
	0xADDA7C5F3C4488E3ULL, 0xD041DD676D77EEAAULL, 0x56ED3E2F9E224471ULL, 0x2B769F17CF112238ULL
};

uint64_t hash64_append(uint64_t hash, const void *ptr, size_t length)
{
	const uint8_t *ptr8 = (uint8_t *)ptr;

	while (length--) {
		uint8_t x = (uint8_t)hash ^ *ptr8++;
		hash >>= 8;
		hash ^= hash64_lookup_low[x & 0x0F];
		hash ^= hash64_lookup_high[x >> 4];
	}

	return hash;
}

uint64_t hash64_append_str(uint64_t hash, const char *str)
{
	const uint8_t *ptr8 = (uint8_t *)str;

	while (*ptr8) {
		uint8_t x = (uint8_t)hash ^ *ptr8++;
		hash >>= 8;
		hash ^= hash64_lookup_low[x & 0x0F];
		hash ^= hash64_lookup_high[x >> 4];
	}

	return hash;
}

uint64_t hash64_append_nb(uint64_t hash, struct netbuf *nb, size_t length)
{
#if defined(IPOS)
	while (length > 0) {
		uint8_t *block_start, *block_end;
		uint8_t *ptr = netbuf_direct_access(nb, &block_start, &block_end);

		size_t block_length = block_end - block_start;
		if (block_length > length) {
			block_length = length;
		}

		hash = hash64_append(hash, ptr, block_length);
		netbuf_advance_pos(nb, block_length);
		length -= block_length;
	}

	return hash;
#else
	return hash64_append(hash, netbuf_get_ptr(nb), length);
#endif
}
