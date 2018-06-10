/*
 * crypto_sha1.c
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

THIS_FILE("crypto_sha1");

void md5_compute_digest(md5_digest_t *hash, uint8_t *data, size_t length)
{
	hash_state md;
	md5_init(&md);
	md5_process(&md, data, length);
	md5_done(&md, hash->u8);
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
	DEBUG_ASSERT(0, "not implemented");
	memset(hash, 0, sizeof(sha1_digest_t));
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
