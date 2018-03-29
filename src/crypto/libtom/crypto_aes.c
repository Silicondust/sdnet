/*
 * ./src/crypto/libtom/crypto_aes.c
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

THIS_FILE("crypto_aes");

void aes_ecb_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key)
{
	DEBUG_ASSERT(((end - ptr) % 16) == 0, "bad length %u", end - ptr);

	symmetric_key skey;
	rijndael_setup(key->u8, 16, 0, &skey);

	while (ptr < end) {
		rijndael_ecb_encrypt(ptr, ptr, &skey);
		ptr += 16;
	}
}

void aes_ecb_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key)
{
	DEBUG_ASSERT(((end - ptr) % 16) == 0, "bad length %u", end - ptr);

	symmetric_key skey;
	rijndael_setup(key->u8, 16, 0, &skey);

	while (ptr < end) {
		rijndael_ecb_decrypt(ptr, ptr, &skey);
		ptr += 16;
	}
}

void aes_cbc_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key)
{
	DEBUG_ASSERT(((end - ptr) % 16) == 0, "bad length %u", end - ptr);

	symmetric_key skey;
	rijndael_setup(key->u8, 16, 0, &skey);

	uint8_t *iv_ptr = iv->u8;

	while (ptr < end) {
		ptr[0] ^= iv_ptr[0];
		ptr[1] ^= iv_ptr[1];
		ptr[2] ^= iv_ptr[2];
		ptr[3] ^= iv_ptr[3];
		ptr[4] ^= iv_ptr[4];
		ptr[5] ^= iv_ptr[5];
		ptr[6] ^= iv_ptr[6];
		ptr[7] ^= iv_ptr[7];
		ptr[8] ^= iv_ptr[8];
		ptr[9] ^= iv_ptr[9];
		ptr[10] ^= iv_ptr[10];
		ptr[11] ^= iv_ptr[11];
		ptr[12] ^= iv_ptr[12];
		ptr[13] ^= iv_ptr[13];
		ptr[14] ^= iv_ptr[14];
		ptr[15] ^= iv_ptr[15];

		rijndael_ecb_encrypt(ptr, ptr, &skey);
		iv_ptr = ptr;
		ptr += 16;
	}

	iv->u8[0] = iv_ptr[0];
	iv->u8[1] = iv_ptr[1];
	iv->u8[2] = iv_ptr[2];
	iv->u8[3] = iv_ptr[3];
	iv->u8[4] = iv_ptr[4];
	iv->u8[5] = iv_ptr[5];
	iv->u8[6] = iv_ptr[6];
	iv->u8[7] = iv_ptr[7];
	iv->u8[8] = iv_ptr[8];
	iv->u8[9] = iv_ptr[9];
	iv->u8[10] = iv_ptr[10];
	iv->u8[11] = iv_ptr[11];
	iv->u8[12] = iv_ptr[12];
	iv->u8[13] = iv_ptr[13];
	iv->u8[14] = iv_ptr[14];
	iv->u8[15] = iv_ptr[15];
}

void aes_cbc_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key)
{
	DEBUG_ASSERT(((end - ptr) % 16) == 0, "bad length %u", end - ptr);

	symmetric_key skey;
	rijndael_setup(key->u8, 16, 0, &skey);

	uint8_t *nexta_iv = iv->u8;
	uint8_t nextb_iv[16];

	while (ptr < end) {
		nextb_iv[0] = ptr[0];
		nextb_iv[1] = ptr[1];
		nextb_iv[2] = ptr[2];
		nextb_iv[3] = ptr[3];
		nextb_iv[4] = ptr[4];
		nextb_iv[5] = ptr[5];
		nextb_iv[6] = ptr[6];
		nextb_iv[7] = ptr[7];
		nextb_iv[8] = ptr[8];
		nextb_iv[9] = ptr[9];
		nextb_iv[10] = ptr[10];
		nextb_iv[11] = ptr[11];
		nextb_iv[12] = ptr[12];
		nextb_iv[13] = ptr[13];
		nextb_iv[14] = ptr[14];
		nextb_iv[15] = ptr[15];

		rijndael_ecb_decrypt(ptr, ptr, &skey);

		ptr[0] ^= nexta_iv[0];
		ptr[1] ^= nexta_iv[1];
		ptr[2] ^= nexta_iv[2];
		ptr[3] ^= nexta_iv[3];
		ptr[4] ^= nexta_iv[4];
		ptr[5] ^= nexta_iv[5];
		ptr[6] ^= nexta_iv[6];
		ptr[7] ^= nexta_iv[7];
		ptr[8] ^= nexta_iv[8];
		ptr[9] ^= nexta_iv[9];
		ptr[10] ^= nexta_iv[10];
		ptr[11] ^= nexta_iv[11];
		ptr[12] ^= nexta_iv[12];
		ptr[13] ^= nexta_iv[13];
		ptr[14] ^= nexta_iv[14];
		ptr[15] ^= nexta_iv[15];

		ptr += 16;

		if (ptr >= end) {
			iv->u8[0] = nextb_iv[0];
			iv->u8[1] = nextb_iv[1];
			iv->u8[2] = nextb_iv[2];
			iv->u8[3] = nextb_iv[3];
			iv->u8[4] = nextb_iv[4];
			iv->u8[5] = nextb_iv[5];
			iv->u8[6] = nextb_iv[6];
			iv->u8[7] = nextb_iv[7];
			iv->u8[8] = nextb_iv[8];
			iv->u8[9] = nextb_iv[9];
			iv->u8[10] = nextb_iv[10];
			iv->u8[11] = nextb_iv[11];
			iv->u8[12] = nextb_iv[12];
			iv->u8[13] = nextb_iv[13];
			iv->u8[14] = nextb_iv[14];
			iv->u8[15] = nextb_iv[15];
			return;
		}

		nexta_iv[0] = ptr[0];
		nexta_iv[1] = ptr[1];
		nexta_iv[2] = ptr[2];
		nexta_iv[3] = ptr[3];
		nexta_iv[4] = ptr[4];
		nexta_iv[5] = ptr[5];
		nexta_iv[6] = ptr[6];
		nexta_iv[7] = ptr[7];
		nexta_iv[8] = ptr[8];
		nexta_iv[9] = ptr[9];
		nexta_iv[10] = ptr[10];
		nexta_iv[11] = ptr[11];
		nexta_iv[12] = ptr[12];
		nexta_iv[13] = ptr[13];
		nexta_iv[14] = ptr[14];
		nexta_iv[15] = ptr[15];

		rijndael_ecb_decrypt(ptr, ptr, &skey);

		ptr[0] ^= nextb_iv[0];
		ptr[1] ^= nextb_iv[1];
		ptr[2] ^= nextb_iv[2];
		ptr[3] ^= nextb_iv[3];
		ptr[4] ^= nextb_iv[4];
		ptr[5] ^= nextb_iv[5];
		ptr[6] ^= nextb_iv[6];
		ptr[7] ^= nextb_iv[7];
		ptr[8] ^= nextb_iv[8];
		ptr[9] ^= nextb_iv[9];
		ptr[10] ^= nextb_iv[10];
		ptr[11] ^= nextb_iv[11];
		ptr[12] ^= nextb_iv[12];
		ptr[13] ^= nextb_iv[13];
		ptr[14] ^= nextb_iv[14];
		ptr[15] ^= nextb_iv[15];

		ptr += 16;
	}
}
