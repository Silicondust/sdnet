/*
 * crypto_aes.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

struct aes_128_key_blob_t {
	BLOBHEADER hdr;
	DWORD dwKeySize;
	BYTE rgbKeyData[16];
};

void aes_ecb_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key)
{
	struct thread_public_context_t *context = thread_get_public_context();

	struct aes_128_key_blob_t key_blob;
	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_AES_128;
	key_blob.dwKeySize = 16;
	memcpy(key_blob.rgbKeyData, key->u8, 16);

	HCRYPTKEY crypt_key_handle;
	if (!CryptImportKey(context->crypt_handle, (BYTE *)&key_blob, sizeof(struct aes_128_key_blob_t), 0, 0, &crypt_key_handle)) {
		fprintf(stderr, "CryptImportKey failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD crypt_mode = CRYPT_MODE_ECB;
	if (!CryptSetKeyParam(crypt_key_handle, KP_MODE, (BYTE*)&crypt_mode, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD length = (DWORD)(end - ptr);
	if (!CryptEncrypt(crypt_key_handle, 0, false, 0, ptr, &length, length)) {
		fprintf(stderr, "CryptEncrypt failed (%08X)\n", GetLastError());
		exit(1);
	}

	CryptDestroyKey(crypt_key_handle);
}

void aes_ecb_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key)
{
	struct thread_public_context_t *context = thread_get_public_context();

	struct aes_128_key_blob_t key_blob;
	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_AES_128;
	key_blob.dwKeySize = 16;
	memcpy(key_blob.rgbKeyData, key->u8, 16);

	HCRYPTKEY crypt_key_handle;
	if (!CryptImportKey(context->crypt_handle, (BYTE *)&key_blob, sizeof(struct aes_128_key_blob_t), 0, 0, &crypt_key_handle)) {
		fprintf(stderr, "CryptImportKey failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD crypt_mode = CRYPT_MODE_ECB;
	if (!CryptSetKeyParam(crypt_key_handle, KP_MODE, (BYTE*)&crypt_mode, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD length = (DWORD)(end - ptr);
	if (!CryptDecrypt(crypt_key_handle, 0, false, 0, ptr, &length)) {
		fprintf(stderr, "CryptEncrypt failed (%08X)\n", GetLastError());
		exit(1);
	}

	CryptDestroyKey(crypt_key_handle);
}

void aes_cbc_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key)
{
	struct thread_public_context_t *context = thread_get_public_context();

	struct aes_128_key_blob_t key_blob;
	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_AES_128;
	key_blob.dwKeySize = 16;
	memcpy(key_blob.rgbKeyData, key->u8, 16);

	HCRYPTKEY crypt_key_handle;
	if (!CryptImportKey(context->crypt_handle, (BYTE *)&key_blob, sizeof(struct aes_128_key_blob_t), 0, 0, &crypt_key_handle)) {
		fprintf(stderr, "CryptImportKey failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD crypt_mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(crypt_key_handle, KP_MODE, (BYTE *)&crypt_mode, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	if (!CryptSetKeyParam(crypt_key_handle, KP_IV, iv->u8, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD length = (DWORD)(end - ptr);
	if (!CryptEncrypt(crypt_key_handle, 0, false, 0, ptr, &length, length)) {
		fprintf(stderr, "CryptEncrypt failed (%08X)\n", GetLastError());
		exit(1);
	}

	memcpy(iv, end - 16, 16);
	CryptDestroyKey(crypt_key_handle);
}

void aes_cbc_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key)
{
	struct thread_public_context_t *context = thread_get_public_context();

	struct aes_128_key_blob_t key_blob;
	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_AES_128;
	key_blob.dwKeySize = 16;
	memcpy(key_blob.rgbKeyData, key->u8, 16);

	HCRYPTKEY crypt_key_handle;
	if (!CryptImportKey(context->crypt_handle, (BYTE *)&key_blob, sizeof(struct aes_128_key_blob_t), 0, 0, &crypt_key_handle)) {
		fprintf(stderr, "CryptImportKey failed (%08X)\n", GetLastError());
		exit(1);
	}

	DWORD crypt_mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(crypt_key_handle, KP_MODE, (BYTE *)&crypt_mode, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	if (!CryptSetKeyParam(crypt_key_handle, KP_IV, iv->u8, 0)) {
		fprintf(stderr, "CryptSetKeyParam failed (%08X)\n", GetLastError());
		exit(1);
	}

	memcpy(iv, end - 16, 16);

	DWORD length = (DWORD)(end - ptr);
	if (!CryptDecrypt(crypt_key_handle, 0, false, 0, ptr, &length)) {
		fprintf(stderr, "CryptEncrypt failed (%08X)\n", GetLastError());
		exit(1);
	}

	CryptDestroyKey(crypt_key_handle);
}
