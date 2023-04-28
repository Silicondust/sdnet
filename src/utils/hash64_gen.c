/*
 * hash64_gen.c
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void hash32_gen(void)
{
	uint32_t poly = 0xEDB88320U;

	uint32_t hash32_lookup_low[16];
	uint32_t hash32_lookup_high[16];
	memset(hash32_lookup_low, 0, sizeof(hash32_lookup_low));
	memset(hash32_lookup_high, 0, sizeof(hash32_lookup_high));

	for (uint32_t c = 0; c < 16; c++) {
		uint32_t remainder = c;
		for (uint32_t bit = 8; bit > 0; bit--) {
			if (remainder & 0x01) {
				remainder = (remainder >> 1) ^ poly;
			} else {
				remainder = (remainder >> 1);
			}
		}
		hash32_lookup_low[c] = remainder;
	}

	for (uint32_t c = 0; c < 256; c += 16) {
		uint32_t remainder = c;
		for (uint32_t bit = 8; bit > 0; bit--) {
			if (remainder & 0x01) {
				remainder = (remainder >> 1) ^ poly;
			} else {
				remainder = (remainder >> 1);
			}
		}
		hash32_lookup_high[c >> 4] = remainder;
	}

	printf("static const uint32_t hash32_lookup_low[16] = {\n");
	for (int i = 0; i < 16; i++) {
		printf("0x%08XU,", (unsigned int)hash32_lookup_low[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("};\n");

	printf("static const uint32_t hash32_lookup_high[16] = {\n");
	for (int i = 0; i < 16; i++) {
		printf("0x%08XU,", (unsigned int)hash32_lookup_high[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("};\n");
}

static void hash64_gen(void)
{
	uint64_t poly = 0xC96C5795D7870F42ULL;

	uint64_t hash64_lookup_low[16];
	uint64_t hash64_lookup_high[16];
	memset(hash64_lookup_low, 0, sizeof(hash64_lookup_low));
	memset(hash64_lookup_high, 0, sizeof(hash64_lookup_high));

	for (uint64_t c = 0; c < 16; c++) {
		uint64_t remainder = c;
		for (uint64_t bit = 8; bit > 0; bit--) {
			if (remainder & 0x01) {
				remainder = (remainder >> 1) ^ poly;
			} else {
				remainder = (remainder >> 1);
			}
		}
		hash64_lookup_low[c] = remainder;
	}

	for (uint64_t c = 0; c < 256; c += 16) {
		uint64_t remainder = c;
		for (uint64_t bit = 8; bit > 0; bit--) {
			if (remainder & 0x01) {
				remainder = (remainder >> 1) ^ poly;
			} else {
				remainder = (remainder >> 1);
			}
		}
		hash64_lookup_high[c >> 4] = remainder;
	}

	printf("static const uint64_t hash64_lookup_low[16] = {\n");
	for (int i = 0; i < 16; i++) {
		printf("0x%016llXULL,", (unsigned long long)hash64_lookup_low[i]);
		if (i % 4 == 3) {
			printf("\n");
		}
	}
	printf("};\n");

	printf("static const uint64_t hash64_lookup_high[16] = {\n");
	for (int i = 0; i < 16; i++) {
		printf("0x%016llXULL,", (unsigned long long)hash64_lookup_high[i]);
		if (i % 4 == 3) {
			printf("\n");
		}
	}
	printf("};\n");
}

int main(int argc, char *arg[])
{
	hash32_gen();
	hash64_gen();
	return 0;
}
