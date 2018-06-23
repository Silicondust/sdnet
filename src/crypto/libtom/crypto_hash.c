/*
 * crypto_hash.c
 *
 * Copyright © 2012-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("crypto_hash");

void md5_compute_digest(md5_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	md5_init(&md);
	md5_process(&md, data, length);
	md5_done(&md, hash->u8);
}

void md5_compute_digest_netbuf(md5_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	md5_compute_digest(hash, data, length);
}

void md5_hmac_compute_digest(md5_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len)
{
	uint32_t key_block[64 / 4];
	memset(key_block, 0, sizeof(key_block));
	if (key_len <= sizeof(key_block)) {
		memcpy(key_block, key, key_len);
	} else {
		md5_compute_digest(hash, key, key_len);
		memcpy(key_block, hash->u8, sizeof(hash->u8));
	}

	uint32_t key_xor[64 / 4];
	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x36363636;
	}

	hash_state md;
	md5_init(&md);
	md5_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	md5_process(&md, input, input_len);
	md5_done(&md, hash->u8);

	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x5C5C5C5C;
	}

	md5_init(&md);
	md5_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	md5_process(&md, hash->u8, sizeof(hash->u8));
	md5_done(&md, hash->u8);
}

void md5_hmac_compute_digest_netbuf(md5_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len)
{
	uint8_t *data = netbuf_get_ptr(nb);
	md5_hmac_compute_digest(hash, data, input_len, key, key_len);
}

bool md5_compare_digest(md5_digest_t *digest1, md5_digest_t *digest2)
{
	return (digest1->u32be[0] == digest2->u32be[0]) && (digest1->u32be[1] == digest2->u32be[1]) && (digest1->u32be[2] == digest2->u32be[2]) && (digest1->u32be[3] == digest2->u32be[3]);
}

void sha1_compute_digest(sha1_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	sha1_init(&md);
	sha1_process(&md, data, length);
	sha1_done(&md, hash->u8);
}

void sha1_compute_digest_netbuf(sha1_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha1_compute_digest(hash, data, length);
}

void sha1_hmac_compute_digest(sha1_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len)
{
	uint32_t key_block[64 / 4];
	memset(key_block, 0, sizeof(key_block));
	if (key_len <= sizeof(key_block)) {
		memcpy(key_block, key, key_len);
	} else {
		sha1_compute_digest(hash, key, key_len);
		memcpy(key_block, hash->u8, sizeof(hash->u8));
	}

	uint32_t key_xor[64 / 4];
	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x36363636;
	}

	hash_state md;
	sha1_init(&md);
	sha1_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha1_process(&md, input, input_len);
	sha1_done(&md, hash->u8);

	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x5C5C5C5C;
	}

	sha1_init(&md);
	sha1_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha1_process(&md, hash->u8, sizeof(hash->u8));
	sha1_done(&md, hash->u8);
}

void sha1_hmac_compute_digest_netbuf(sha1_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha1_hmac_compute_digest(hash, data, input_len, key, key_len);
}

bool sha1_compare_digest(sha1_digest_t *digest1, sha1_digest_t *digest2)
{
	return (digest1->u32be[0] == digest2->u32be[0]) && (digest1->u32be[1] == digest2->u32be[1]) && (digest1->u32be[2] == digest2->u32be[2]) && (digest1->u32be[3] == digest2->u32be[3]) && (digest1->u32be[4] == digest2->u32be[4]);
}

void sha256_compute_digest(sha256_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	sha256_init(&md);
	sha256_process(&md, data, length);
	sha256_done(&md, hash->u8);
}

void sha256_compute_digest_netbuf(sha256_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha256_compute_digest(hash, data, length);
}

void sha256_hmac_compute_digest(sha256_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len)
{
	uint32_t key_block[64 / 4];
	memset(key_block, 0, sizeof(key_block));
	if (key_len <= sizeof(key_block)) {
		memcpy(key_block, key, key_len);
	} else {
		sha256_compute_digest(hash, key, key_len);
		memcpy(key_block, hash->u8, sizeof(hash->u8));
	}

	uint32_t key_xor[64 / 4];
	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x36363636;
	}

	hash_state md;
	sha256_init(&md);
	sha256_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha256_process(&md, input, input_len);
	sha256_done(&md, hash->u8);

	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x5C5C5C5C;
	}

	sha256_init(&md);
	sha256_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha256_process(&md, hash->u8, sizeof(hash->u8));
	sha256_done(&md, hash->u8);
}

void sha256_hmac_compute_digest_netbuf(sha256_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha256_hmac_compute_digest(hash, data, input_len, key, key_len);
}

bool sha256_compare_digest(sha256_digest_t *digest1, sha256_digest_t *digest2)
{
	for (int i = 0; i < 8; i++) {
		if (digest1->u32be[i] != digest2->u32be[i]) {
			return false;
		}
	}

	return true;
}

void sha384_compute_digest(sha384_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	sha384_init(&md);
	sha384_process(&md, data, length);
	sha384_done(&md, hash->u8);
}

void sha384_compute_digest_netbuf(sha384_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha384_compute_digest(hash, data, length);
}

void sha384_hmac_compute_digest(sha384_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len)
{
	uint32_t key_block[64 / 4];
	memset(key_block, 0, sizeof(key_block));
	if (key_len <= sizeof(key_block)) {
		memcpy(key_block, key, key_len);
	} else {
		sha384_compute_digest(hash, key, key_len);
		memcpy(key_block, hash->u8, sizeof(hash->u8));
	}

	uint32_t key_xor[64 / 4];
	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x36363636;
	}

	hash_state md;
	sha384_init(&md);
	sha384_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha384_process(&md, input, input_len);
	sha384_done(&md, hash->u8);

	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x5C5C5C5C;
	}

	sha384_init(&md);
	sha384_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha384_process(&md, hash->u8, sizeof(hash->u8));
	sha384_done(&md, hash->u8);
}

void sha384_hmac_compute_digest_netbuf(sha384_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha384_hmac_compute_digest(hash, data, input_len, key, key_len);
}

bool sha384_compare_digest(sha384_digest_t *digest1, sha384_digest_t *digest2)
{
	for (int i = 0; i < 12; i++) {
		if (digest1->u32be[i] != digest2->u32be[i]) {
			return false;
		}
	}

	return true;
}

void sha512_compute_digest(sha512_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	sha512_init(&md);
	sha512_process(&md, data, length);
	sha512_done(&md, hash->u8);
}

void sha512_compute_digest_netbuf(sha512_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha512_compute_digest(hash, data, length);
}

void sha512_hmac_compute_digest(sha512_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len)
{
	uint32_t key_block[64 / 4];
	memset(key_block, 0, sizeof(key_block));
	if (key_len <= sizeof(key_block)) {
		memcpy(key_block, key, key_len);
	} else {
		sha512_compute_digest(hash, key, key_len);
		memcpy(key_block, hash->u8, sizeof(hash->u8));
	}

	uint32_t key_xor[64 / 4];
	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x36363636;
	}

	hash_state md;
	sha512_init(&md);
	sha512_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha512_process(&md, input, input_len);
	sha512_done(&md, hash->u8);

	for (size_t i = 0; i < 64 / 4; i++) {
		key_xor[i] = key_block[i] ^ 0x5C5C5C5C;
	}

	sha512_init(&md);
	sha512_process(&md, (uint8_t *)key_xor, sizeof(key_xor));
	sha512_process(&md, hash->u8, sizeof(hash->u8));
	sha512_done(&md, hash->u8);
}

void sha512_hmac_compute_digest_netbuf(sha512_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha512_hmac_compute_digest(hash, data, input_len, key, key_len);
}

bool sha512_compare_digest(sha512_digest_t *digest1, sha512_digest_t *digest2)
{
	for (int i = 0; i < 16; i++) {
		if (digest1->u32be[i] != digest2->u32be[i]) {
			return false;
		}
	}

	return true;
}
