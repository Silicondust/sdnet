/*
 * ./src/crypto/crypto_test.c
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("crypto_test");

#if defined(DEBUG)

static uint8_t crypto_test_data[128] = {
	0xcb, 0x0d, 0x3e, 0x10, 0x0c, 0x3a, 0xce, 0x0d, 0x25, 0x8c, 0x68, 0x1b, 0x84, 0x63, 0x4a, 0x01,
	0x37, 0x54, 0x4a, 0x03, 0x5d, 0xda, 0x54, 0x9d, 0x18, 0x22, 0x2d, 0x6e, 0x76, 0x5d, 0x2c, 0x13,
	0xfd, 0x05, 0x0e, 0x40, 0x3d, 0x2d, 0xa8, 0x1e, 0x31, 0x51, 0x0c, 0x1f, 0xcf, 0xba, 0x16, 0x87,
	0x91, 0xca, 0xa3, 0x21, 0x4e, 0x3b, 0x88, 0xc4, 0xa1, 0x54, 0x0a, 0xda, 0xa9, 0x82, 0x91, 0xb9,
	0xc6, 0xa6, 0x80, 0x6c, 0x6e, 0x5d, 0x8e, 0x10, 0x6d, 0x5d, 0xed, 0x66, 0x34, 0x0d, 0xcd, 0xdc,
	0xcd, 0x85, 0xeb, 0x74, 0xab, 0xd2, 0xf8, 0x76, 0xa3, 0xba, 0x03, 0x95, 0x15, 0xbb, 0xd5, 0x28,
	0x7e, 0x17, 0x07, 0x67, 0x88, 0xac, 0xd0, 0x68, 0x7d, 0xe5, 0x11, 0x8e, 0x9a, 0xf7, 0x93, 0x17,
	0x12, 0x38, 0xb1, 0xdc, 0x21, 0x9e, 0x4e, 0x6e, 0x68, 0xb9, 0x7b, 0x17, 0xec, 0x01, 0xe1, 0xc0
};

static void crypto_test_sha1(void)
{
	sha1_digest_t hash;
	sha1_compute_digest(&hash, crypto_test_data, 128);
	uint8_t expected[20] = { 0x81, 0x88, 0x2d, 0x49, 0x7d, 0xe1, 0x76, 0xb9, 0x59, 0xcc, 0x2c, 0xe0, 0x0c, 0xdb, 0xa2, 0xfb, 0x36, 0xef, 0xea, 0x10 };
	DEBUG_ASSERT(memcmp(hash.u8, expected, 20) == 0, "sha1_compute_digest test failed");
}

static void crypto_test_aes(void)
{
	aes_128_key_t key = { { 0x31, 0xd1, 0x92, 0x8c, 0xf4, 0xb4, 0x56, 0x22, 0x40, 0x75, 0xd5, 0xe3, 0xe1, 0xff, 0x5f, 0xf6 } };
	aes_128_iv_t iv = { { 0x9f, 0x0f, 0x42, 0xa6, 0xc9, 0xc5, 0x2a, 0x51, 0xe3, 0x29, 0x61, 0x71, 0xaa, 0x13, 0xae, 0x1b } };
	aes_128_iv_t tmp_iv;
	uint8_t data[32];

	memcpy(data, crypto_test_data, 32);
	aes_ecb_128_encrypt_inplace(data, data + 32, &key);
	uint8_t expected_ecb_encrypt[32] = { 0xe8, 0xc1, 0xa3, 0x52, 0x0c, 0x3a, 0x77, 0x34, 0xd1, 0xb3, 0x70, 0xcf, 0xec, 0x10, 0x0d, 0x41, 0xe8, 0x98, 0x9d, 0x92, 0xa8, 0xbd, 0xf3, 0x4f, 0x98, 0x3e, 0x77, 0xda, 0x5c, 0x16, 0xe6, 0x38 };
	DEBUG_ASSERT(memcmp(data, expected_ecb_encrypt, 32) == 0, "aes_ecb_128_encrypt_inplace test failed");

	memcpy(data, crypto_test_data, 32);
	aes_ecb_128_decrypt_inplace(data, data + 32, &key);
	uint8_t expected_ecb_decrypt[32] = { 0xbd, 0x71, 0x5e, 0x74, 0xfc, 0x4f, 0x69, 0xaa, 0xc7, 0xa4, 0x13, 0xaa, 0x59, 0x4b, 0x62, 0x71, 0x9a, 0xb7, 0x57, 0xc1, 0xe5, 0x35, 0xcf, 0xef, 0x62, 0x18, 0xb3, 0x49, 0xda, 0x05, 0x23, 0x30 };
	DEBUG_ASSERT(memcmp(data, expected_ecb_decrypt, 32) == 0, "aes_ecb_128_decrypt_inplace test failed");

	memcpy(tmp_iv.u8, iv.u8, 16);
	memcpy(data, crypto_test_data, 32);
	aes_cbc_128_encrypt_inplace(data, data + 32, &tmp_iv, &key);
	uint8_t expected_cbc_encrypt_iv[16] = { 0x98, 0xF2, 0x29, 0xFA, 0xB9, 0xD9, 0xC7, 0xD7, 0x6C, 0x7D, 0x4D, 0xCC, 0x10, 0xA1, 0x72, 0x8F};
	uint8_t expected_cbc_encrypt_data[32] = { 0xC4, 0x62, 0x3C, 0x82, 0x56, 0x45, 0x58, 0x11, 0xA7, 0x49, 0xA0, 0xD1, 0x1E, 0xCA, 0xCD, 0x9F, 0x98, 0xF2, 0x29, 0xFA, 0xB9, 0xD9, 0xC7, 0xD7, 0x6C, 0x7D, 0x4D, 0xCC, 0x10, 0xA1, 0x72, 0x8F };
	DEBUG_ASSERT(memcmp(tmp_iv.u8, expected_cbc_encrypt_iv, 16) == 0, "aes_cbc_128_encrypt_inplace test failed");
	DEBUG_ASSERT(memcmp(data, expected_cbc_encrypt_data, 32) == 0, "aes_cbc_128_encrypt_inplace test failed");

	memcpy(tmp_iv.u8, iv.u8, 16);
	memcpy(data, crypto_test_data, 32);
	aes_cbc_128_decrypt_inplace(data, data + 32, &tmp_iv, &key);
	uint8_t expected_cbc_decrypt_iv[16] = { 0x37, 0x54, 0x4A, 0x03, 0x5D, 0xDA, 0x54, 0x9D, 0x18, 0x22, 0x2D, 0x6E, 0x76, 0x5D, 0x2C, 0x13 };
	uint8_t expected_cbc_decrypt_data[32] = { 0x22, 0x7E, 0x1C, 0xD2, 0x35, 0x8A, 0x43, 0xFB, 0x24, 0x8D, 0x72, 0xDB, 0xF3, 0x58, 0xCC, 0x6A, 0x51, 0xBA, 0x69, 0xD1, 0xE9, 0x0F, 0x01, 0xE2, 0x47, 0x94, 0xDB, 0x52, 0x5E, 0x66, 0x69, 0x31 };
	DEBUG_ASSERT(memcmp(tmp_iv.u8, expected_cbc_decrypt_iv, 16) == 0, "aes_cbc_128_decrypt_inplace test failed");
	DEBUG_ASSERT(memcmp(data, expected_cbc_decrypt_data, 32) == 0, "aes_cbc_128_decrypt_inplace test failed");
}

void crypto_test(void)
{
	crypto_test_sha1();
	crypto_test_aes();

	DEBUG_INFO("crypt test passed");
}

#endif
