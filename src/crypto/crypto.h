/*
 * crypto.h
 *
 * Copyright © 2013-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void crypto_init(void);
extern void crypto_test(void);

#if !defined(DEBUG)
extern inline void crypto_test(void) {}
#endif

/*
 * AES.
 */
struct aes_instance_t;

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

extern struct aes_instance_t *aes_instance_alloc(void);
extern void aes_instance_free(struct aes_instance_t *aes);
extern void aes_instance_ecb_128_set_key(struct aes_instance_t *aes, aes_128_key_t *key);
extern void aes_instance_ecb_128_encrypt_inplace(struct aes_instance_t *aes, uint8_t *ptr, uint8_t *end);
extern void aes_instance_ecb_128_decrypt_inplace(struct aes_instance_t *aes, uint8_t *ptr, uint8_t *end);
extern void aes_instance_cbc_128_set_iv_key(struct aes_instance_t *aes, aes_128_iv_t *iv, aes_128_key_t *key);
extern void aes_instance_cbc_128_get_iv(struct aes_instance_t *aes, aes_128_iv_t *iv);
extern void aes_instance_cbc_128_encrypt_inplace(struct aes_instance_t *aes, uint8_t *ptr, uint8_t *end);
extern void aes_instance_cbc_128_decrypt_inplace(struct aes_instance_t *aes, uint8_t *ptr, uint8_t *end);

/*
 * DES3.
 */
struct des3_instance_t;

typedef union {
	uint8_t u8[24];
	uint32_t u32be[6];
} des3_key_t;

extern struct des3_instance_t *des3_instance_alloc(void);
extern void des3_instance_free(struct des3_instance_t *des3);
extern void des3_instance_set_key(struct des3_instance_t *des3, des3_key_t *key);
extern void des3_instance_ecb_decrypt_inplace(struct des3_instance_t *des3, uint8_t *ptr, uint8_t *end);

/*
 * RC5
 */
extern void rc5_key128_block32_round20_encrypt(uint8_t ptr[4], uint8_t key[16]);
extern void rc5_key128_block32_round20_decrypt(uint8_t ptr[4], uint8_t key[16]);

/*
 * RSA.
 */
struct rsa_key_t;

extern struct rsa_key_t *rsa_key_import_private(uint8_t *in, size_t in_len);
extern struct rsa_key_t *rsa_key_import_public(uint8_t *in, size_t in_len);
extern void rsa_key_free(struct rsa_key_t *key);

extern uint32_t rsa_key_get_size_bits(struct rsa_key_t *key);
extern uint32_t rsa_key_get_size_bytes(struct rsa_key_t *key);
extern bool rsa_exptmod_auto(uint8_t *input, uint8_t *output, size_t len, struct rsa_key_t *key);

static inline bool rsa_exptmod_1024(uint8_t input[128], uint8_t output[128], struct rsa_key_t *key)
{
	return rsa_exptmod_auto(input, output, 128, key);
}

static inline bool rsa_exptmod_2048(uint8_t input[256], uint8_t output[256], struct rsa_key_t *key)
{
	return rsa_exptmod_auto(input, output, 256, key);
}

static inline bool rsa_exptmod_4096(uint8_t input[512], uint8_t output[512], struct rsa_key_t *key)
{
	return rsa_exptmod_auto(input, output, 512, key);
}

/*
 * Internal
 */
extern void aes_init(void);
