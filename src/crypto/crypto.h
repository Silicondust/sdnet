/*
 * ./src/crypto/crypto.h
 *
 * Copyright © 2013-2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void crypto_test(void);

#if !defined(DEBUG)
extern inline void crypto_test(void) {}
#endif

/*
 * MD5.
 */
typedef union {
	uint8_t u8[16];
	uint32_t u32be[4];
} md5_digest_t;

extern void md5_compute_digest(md5_digest_t *hash, uint8_t *data, size_t length);

/*
 * SHA1.
 */
typedef union {
	uint8_t u8[20];
	uint32_t u32be[5];
} sha1_digest_t;

extern void sha1_compute_digest(sha1_digest_t *hash, uint8_t *data, size_t length);
extern void sha1_compute_digest_netbuf(sha1_digest_t *hash, struct netbuf *nb, size_t input_len);
extern void sha1_hmac_compute_digest(sha1_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len);
extern void sha1_hmac_compute_digest_netbuf(sha1_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len);
extern bool sha1_compare_digest(sha1_digest_t *digest1, sha1_digest_t *digest2);

/*
 * AES.
 */
typedef union {
	uint8_t u8[16];
	uint32_t u32be[4];
} aes_128_key_t;

typedef union {
	uint8_t u8[16];
	uint32_t u32be[4];
} aes_128_iv_t;

extern void aes_ecb_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key);
extern void aes_ecb_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_key_t *key);
extern void aes_cbc_128_encrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key);
extern void aes_cbc_128_decrypt_inplace(uint8_t *ptr, uint8_t *end, aes_128_iv_t *iv, aes_128_key_t *key);

/*
 * DES3.
 */
typedef union {
	uint8_t u8[24];
	uint32_t u32be[6];
} des3_key_t;

extern void des3_ede_ecb_decrypt_inplace(uint8_t *ptr, uint8_t *end, des3_key_t *key);

/*
 * RC5
 */
extern void rc5_key128_block32_round20_encrypt(uint8_t ptr[4], uint8_t key[16]);
extern void rc5_key128_block32_round20_decrypt(uint8_t ptr[4], uint8_t key[16]);

/*
 * PKCS1
 */
extern void pkcs1_v15_pad(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
extern bool pkcs1_v15_unpad(uint8_t *in, size_t in_len, uint8_t *out, size_t *pout_len);
extern void pkcs1_v15_pad_sha1(sha1_digest_t *digest, uint8_t *out, size_t out_len);
extern bool pkcs1_v15_unpad_compare_sha1(sha1_digest_t *digest, uint8_t *in, size_t in_len);

/*
 * RSA.
 */
struct rsa_key_t;

extern struct rsa_key_t *rsa_key_import_private(uint8_t *in, size_t in_len);
extern struct rsa_key_t *rsa_key_import_public(uint8_t *in, size_t in_len);
extern void rsa_key_free(struct rsa_key_t *key);

extern bool rsa_exptmod_auto(uint8_t *input, uint8_t *output, size_t len, struct rsa_key_t *key);

static inline bool rsa_exptmod_1024(uint8_t input[128], uint8_t output[128], struct rsa_key_t *key)
{
	return rsa_exptmod_auto(input, output, 128, key);
}

static inline bool rsa_exptmod_2048(uint8_t input[256], uint8_t output[256], struct rsa_key_t *key)
{
	return rsa_exptmod_auto(input, output, 256, key);
}
