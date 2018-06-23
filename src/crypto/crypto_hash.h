/*
 * crypto_hash.h
 *
 * Copyright © 2013-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * MD5.
 */
typedef union {
	uint8_t u8[16];
	uint32_t u32be[4];
} md5_digest_t;

extern void md5_compute_digest(md5_digest_t *hash, uint8_t *data, size_t length);
extern void md5_compute_digest_netbuf(md5_digest_t *hash, struct netbuf *nb, size_t input_len);
extern void md5_hmac_compute_digest(md5_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len);
extern void md5_hmac_compute_digest_netbuf(md5_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len);
extern bool md5_compare_digest(md5_digest_t *digest1, md5_digest_t *digest2);

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
 * SHA256.
 */
typedef union {
	uint8_t u8[32];
	uint32_t u32be[8];
} sha256_digest_t;

extern void sha256_compute_digest(sha256_digest_t *hash, uint8_t *data, size_t length);
extern void sha256_compute_digest_netbuf(sha256_digest_t *hash, struct netbuf *nb, size_t input_len);
extern void sha256_hmac_compute_digest(sha256_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len);
extern void sha256_hmac_compute_digest_netbuf(sha256_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len);
extern bool sha256_compare_digest(sha256_digest_t *digest1, sha256_digest_t *digest2);

/*
 * SHA384.
 */
typedef union {
	uint8_t u8[48];
	uint32_t u32be[12];
} sha384_digest_t;

extern void sha384_compute_digest(sha384_digest_t *hash, uint8_t *data, size_t length);
extern void sha384_compute_digest_netbuf(sha384_digest_t *hash, struct netbuf *nb, size_t input_len);
extern void sha384_hmac_compute_digest(sha384_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len);
extern void sha384_hmac_compute_digest_netbuf(sha384_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len);
extern bool sha384_compare_digest(sha384_digest_t *digest1, sha384_digest_t *digest2);

/*
 * SHA512.
 */
typedef union {
	uint8_t u8[64];
	uint32_t u32be[16];
} sha512_digest_t;

extern void sha512_compute_digest(sha512_digest_t *hash, uint8_t *data, size_t length);
extern void sha512_compute_digest_netbuf(sha512_digest_t *hash, struct netbuf *nb, size_t input_len);
extern void sha512_hmac_compute_digest(sha512_digest_t *hash, uint8_t *input, size_t input_len, uint8_t *key, size_t key_len);
extern void sha512_hmac_compute_digest_netbuf(sha512_digest_t *hash, struct netbuf *nb, size_t input_len, uint8_t *key, size_t key_len);
extern bool sha512_compare_digest(sha512_digest_t *digest1, sha512_digest_t *digest2);
