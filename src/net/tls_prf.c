/*
 * tls_prf.c
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

THIS_FILE("tls_prf");

struct tls_prf_p_hash_sha256_state_t {
	sha256_digest_t an;
};

static void tls_prf_p_hash_sha256_first(struct tls_prf_p_hash_sha256_state_t *state, sha256_digest_t *out, uint8_t *label, size_t label_len, uint8_t *seed, size_t seed_len, uint8_t *secret, size_t secret_len)
{
	uint8_t data[128];
	DEBUG_ASSERT(sizeof(state->an.u8) + label_len + seed_len <= sizeof(data), "overflow");

	uint8_t *ptr = data;
	memcpy(ptr, label, label_len);
	ptr += label_len;
	memcpy(ptr, seed, seed_len);
	ptr += seed_len;

	sha256_hmac_compute_digest(&state->an, data, ptr - data, secret, secret_len);

	ptr = data;
	memcpy(ptr, state->an.u8, sizeof(state->an.u8));
	ptr += sizeof(state->an.u8);
	memcpy(ptr, label, label_len);
	ptr += label_len;
	memcpy(ptr, seed, seed_len);
	ptr += seed_len;

	sha256_hmac_compute_digest(out, data, ptr - data, secret, secret_len);
}

static void tls_prf_p_hash_sha256_next(struct tls_prf_p_hash_sha256_state_t *state, sha256_digest_t *out, uint8_t *label, size_t label_len, uint8_t *seed, size_t seed_len, uint8_t *secret, size_t secret_len)
{
	sha256_hmac_compute_digest(&state->an, state->an.u8, sizeof(state->an), secret, secret_len);

	uint8_t data[128];
	DEBUG_ASSERT(sizeof(state->an.u8) + label_len + seed_len <= sizeof(data), "overflow");

	uint8_t *ptr = data;
	memcpy(ptr, state->an.u8, sizeof(state->an.u8));
	ptr += sizeof(state->an.u8);
	memcpy(ptr, label, label_len);
	ptr += label_len;
	memcpy(ptr, seed, seed_len);
	ptr += seed_len;

	sha256_hmac_compute_digest(out, data, ptr - data, secret, secret_len);
}

void tls_prf(uint8_t *out, uint8_t out_len, const char *label, uint8_t *seed, size_t seed_len, uint8_t *secret, size_t secret_len)
{
	size_t label_len = strlen(label);

	sha256_digest_t sha256_out;
	struct tls_prf_p_hash_sha256_state_t sha256_state;
	tls_prf_p_hash_sha256_first(&sha256_state, &sha256_out, (uint8_t *)label, label_len, seed, seed_len, secret, secret_len);

	uint8_t *end = out + out_len;
	if (out + sizeof(sha256_out.u8) >= end) {
		memcpy(out, sha256_out.u8, end - out);
		return;
	}

	memcpy(out, sha256_out.u8, sizeof(sha256_out.u8));
	out += sizeof(sha256_out.u8);

	while (out + sizeof(sha256_out.u8) < end) {
		tls_prf_p_hash_sha256_next(&sha256_state, &sha256_out, (uint8_t *)label, label_len, seed, seed_len, secret, secret_len);
		memcpy(out, sha256_out.u8, sizeof(sha256_out.u8));
		out += sizeof(sha256_out.u8);
	}

	if (out < end) {
		tls_prf_p_hash_sha256_next(&sha256_state, &sha256_out, (uint8_t *)label, label_len, seed, seed_len, secret, secret_len);
		memcpy(out, sha256_out.u8, end - out);
	}
}

#if defined(DEBUG)
void tls_prf_test(void)
{
	uint8_t secret[16] = { 0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35 };
	uint8_t seed[16] = { 0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c };
	const char *label = "test label";
	uint8_t expected[100] = {
		0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
		0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
		0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
		0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17, 0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
		0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b, 0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
		0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
		0x87, 0x34, 0x7b, 0x66
	};

	uint8_t output[100];
	tls_prf(output, sizeof(output), label, seed, sizeof(seed), secret, sizeof(secret));
	DEBUG_ASSERT(memcmp(output, expected, sizeof(output)) == 0, "tls_prf test failed");
}
#endif
