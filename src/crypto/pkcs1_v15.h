/*
 * pkcs1_v15.h
 *
 * Copyright © 2013-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void pkcs1_v15_type1_pad(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
extern void pkcs1_v15_type2_pad(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
extern bool pkcs1_v15_unpad(uint8_t *in, size_t in_len, uint8_t *out, size_t *pout_len);
extern void pkcs1_v15_pad_sha1(sha1_digest_t *digest, uint8_t *out, size_t out_len);
extern void pkcs1_v15_pad_sha256(sha256_digest_t *digest, uint8_t *out, size_t out_len);
extern void pkcs1_v15_pad_sha384(sha384_digest_t *digest, uint8_t *out, size_t out_len);
extern void pkcs1_v15_pad_sha512(sha512_digest_t *digest, uint8_t *out, size_t out_len);
extern bool pkcs1_v15_unpad_compare_sha1(sha1_digest_t *digest, uint8_t *in, size_t in_len);
extern bool pkcs1_v15_unpad_compare_sha256(sha256_digest_t *digest, uint8_t *in, size_t in_len);
extern bool pkcs1_v15_unpad_compare_sha384(sha384_digest_t *digest, uint8_t *in, size_t in_len);
extern bool pkcs1_v15_unpad_compare_sha512(sha512_digest_t *digest, uint8_t *in, size_t in_len);
