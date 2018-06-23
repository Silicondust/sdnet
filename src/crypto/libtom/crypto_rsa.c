/*
 * crypto_rsa.c
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

THIS_FILE("crypto_rsa");

struct rsa_key_t {
	rsa_key key;
	int which;
};

struct rsa_key_t *rsa_key_import_private(uint8_t *in, size_t in_len)
{
	struct rsa_key_t *key = (struct rsa_key_t *)heap_alloc_and_zero(sizeof(struct rsa_key_t), PKG_OS, MEM_TYPE_OS_RSA_KEY);
	if (!key) {
		return NULL;
	}

	if (rsa_import(in, (unsigned long)in_len, &key->key) != CRYPT_OK) {
		heap_free(key);
		return NULL;
	}

	key->which = PK_PRIVATE;
	return key;
}

struct rsa_key_t *rsa_key_import_public(uint8_t *in, size_t in_len)
{
	struct rsa_key_t *key = (struct rsa_key_t *)heap_alloc_and_zero(sizeof(struct rsa_key_t), PKG_OS, MEM_TYPE_OS_RSA_KEY);
	if (!key) {
		return NULL;
	}

	if (rsa_import(in, (unsigned long)in_len, &key->key) != CRYPT_OK) {
		heap_free(key);
		return NULL;
	}

	key->which = PK_PUBLIC;
	return key;
}

void rsa_key_free(struct rsa_key_t *key)
{
	rsa_free(&key->key);
	heap_free(key);
}

uint32_t rsa_key_get_size_bits(struct rsa_key_t *key)
{
	return (uint32_t)rsa_get_size(&key->key) * 8;
}

uint32_t rsa_key_get_size_bytes(struct rsa_key_t *key)
{
	return (uint32_t)rsa_get_size(&key->key);
}

bool rsa_exptmod_auto(uint8_t *input, uint8_t *output, size_t len, struct rsa_key_t *key)
{
	unsigned long output_len = (unsigned long)len;
	int ret = rsa_exptmod(input, (unsigned long)len, output, &output_len, key->which, &key->key);
	if (ret != CRYPT_OK) {
		return false;
	}

	if (output_len < len) {
		size_t shift = len - output_len;
		memmove(output + shift, output, output_len);
		memset(output, 0, shift);
	}

	return true;
}
