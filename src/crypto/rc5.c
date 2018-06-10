/*
 * rc5.c
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("rc5");

static inline uint16_t ROTL(uint16_t v, int n)
{
	n &= 15;
	return (v << n) | (v >> (16 - n));
}

static inline uint16_t ROTR(uint16_t v, int n)
{
	n &= 15;
	return (v >> n) | (v << (16 - n));
}

static void rc5_key128_block32_round20_setup(uint16_t S[42], uint8_t key[16])
{
	uint16_t L[8];

	L[7] = 0;
	for (int i = 15; i >= 0; i--) {
		L[i / 2] = (L[i / 2] << 8) + key[i];
	}

	S[0] = 0xB7E1;
	for (int i = 1; i < 42; i++) {
		S[i] = S[i - 1] + 0x9E37;
	}

	uint16_t A = 0;
	uint16_t B = 0;
	int i = 0;
	int j = 0;

	for (int k = 0; k < 126; k++) {
		A = S[i] = ROTL(S[i] + A + B, 3);
		B = L[j] = ROTL(L[j] + A + B, A + B);
		i = (i + 1) % 42;
		j = (j + 1) % 8;
	}
}

void rc5_key128_block32_round20_encrypt(uint8_t ptr[4], uint8_t key[16])
{
	uint16_t S[42];
	rc5_key128_block32_round20_setup(S, key);

	uint16_t A = ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1] << 0);
	uint16_t B = ((uint16_t)ptr[2] << 8) | ((uint16_t)ptr[3] << 0);

	A += S[0];
	B += S[1];

	for (int i = 1; i <= 20; i++) {
		A = ROTL(A ^ B, B) + S[2 * i];
		B = ROTL(B ^ A, A) + S[2 * i + 1];
	}

	ptr[0] = (uint8_t)(A >> 8);
	ptr[1] = (uint8_t)(A >> 0);
	ptr[2] = (uint8_t)(B >> 8);
	ptr[3] = (uint8_t)(B >> 0);
}

void rc5_key128_block32_round20_decrypt(uint8_t ptr[4], uint8_t key[16])
{
	uint16_t S[42];
	rc5_key128_block32_round20_setup(S, key);

	uint16_t A = ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1] << 0);
	uint16_t B = ((uint16_t)ptr[2] << 8) | ((uint16_t)ptr[3] << 0);

	for (int i = 20; i > 0; i--) {
		B = ROTR(B - S[2 * i + 1], A) ^ A;
		A = ROTR(A - S[2 * i], B) ^ B;
	}

	A -= S[0];
	B -= S[1];

	ptr[0] = (uint8_t)(A >> 8);
	ptr[1] = (uint8_t)(A >> 0);
	ptr[2] = (uint8_t)(B >> 8);
	ptr[3] = (uint8_t)(B >> 0);
}
