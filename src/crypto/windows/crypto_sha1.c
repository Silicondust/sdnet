/*
 * ./src/crypto/windows/crypto_sha1.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
	struct thread_public_context_t *context = thread_get_public_context();

	HCRYPTHASH hHash;
	if (!CryptCreateHash(context->crypt_handle, CALG_MD5, 0, 0, &hHash)) {
		fprintf(stderr, "CPCreateHash failed\n");
		exit(1);
	}

	if (!CryptHashData(hHash, (BYTE *)data, (DWORD)length, 0)) {
		fprintf(stderr, "CPSignHash failed\n");
		exit(1);
	}

	DWORD hash_length = 16;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE *)hash->u8, &hash_length, 0)) {
		fprintf(stderr, "CryptGetHashParam failed\n");
		exit(1);
	}

	CryptDestroyHash(hHash);
}

void sha1_compute_digest(sha1_digest_t *hash, uint8_t *data, size_t length)
{
	struct thread_public_context_t *context = thread_get_public_context();

	HCRYPTHASH hHash;
	if (!CryptCreateHash(context->crypt_handle, CALG_SHA1, 0, 0, &hHash)) {
		fprintf(stderr, "CPCreateHash failed\n");
		exit(1);
	}

	if (!CryptHashData(hHash, (BYTE *)data, (DWORD)length, 0)) {
		fprintf(stderr, "CPSignHash failed\n");
		exit(1);
	}

	DWORD hash_length = 20;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE *)hash->u8, &hash_length, 0)) {
		fprintf(stderr, "CryptGetHashParam failed\n");
		exit(1);
	}

	CryptDestroyHash(hHash);
}

void sha1_compute_digest_netbuf(sha1_digest_t *hash, struct netbuf *nb, size_t length)
{
	uint8_t *data = netbuf_get_ptr(nb);
	sha1_compute_digest(hash, data, length);
}

bool sha1_compare_digest(sha1_digest_t *digest1, sha1_digest_t *digest2)
{
	return (digest1->u32be[0] == digest2->u32be[0]) && (digest1->u32be[1] == digest2->u32be[1]) && (digest1->u32be[2] == digest2->u32be[2]) && (digest1->u32be[3] == digest2->u32be[3]) && (digest1->u32be[4] == digest2->u32be[4]);
}
