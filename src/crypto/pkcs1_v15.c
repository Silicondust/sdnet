/*
 * pkcs1_v15.c
 *
 * Copyright © 2010-2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("pkcs1_v15");

static const uint8_t pkcs1_v15_digest_info_sha1[15] =
{
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static const uint8_t pkcs1_v15_digest_info_sha256[19] =
{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static const uint8_t pkcs1_v15_digest_info_sha384[19] =
{
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

static const uint8_t pkcs1_v15_digest_info_sha512[19] =
{
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/* 0x00, 0x01, 0xFF-fill, 0x00, in-bytes */
void pkcs1_v15_type1_pad(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
	*out++ = 0x00;
	*out++ = 0x01;

	size_t fill_len = out_len - in_len - 3;
	memset(out, 0xFF, fill_len);
	out += fill_len;

	*out++ = 0x00;

	memcpy(out, in, in_len);
}

/* 0x00, 0x01, random-non-zero-fill, 0x00, in-bytes */
void pkcs1_v15_type2_pad(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
	*out++ = 0x00;
	*out++ = 0x02;

	size_t fill_len = out_len - in_len - 3;
	uint8_t *fill_end = out + fill_len;

	uint32_t random = random_get32();
	while (out < fill_end) {
		uint8_t v = random & 0xFF;
		if (v == 0) {
			if (random != 0) {
				random >>= 8;
				continue;
			}

			random = random_get32();
			continue;
		}

		*out++ = v;
		random >>= 8;
	}

	*out++ = 0x00;

	memcpy(out, in, in_len);
}

bool pkcs1_v15_unpad(uint8_t *in, size_t in_len, uint8_t *out, size_t *pout_len)
{
	uint8_t *in_end = in + in_len;

	if (*in == 0x00) {
		in++;
	}

	uint8_t type = *in++;
	if ((type != 0x01) && (type != 0x02)) {
		DEBUG_ERROR("pkcs1_v15_unpad: invalid start marker");
		return false;
	}

	while (1) {
		if (in >= in_end) {
			DEBUG_ERROR("pkcs1_v15_unpad: no end marker found");
			return false;
		}
		if (*in++ == 0x00) {
			break;
		}
	}

	if (in >= in_end) {
		DEBUG_ERROR("pkcs1_v15_unpad: no payload found");
		return false;
	}

	memmove(out, in, in_end - in);

	*pout_len = in_end - in;
	return true;
}

static void pkcs1_v15_pad_digest(const uint8_t *digest_info, size_t digest_info_len, uint8_t *digest, size_t digest_len, uint8_t *out, size_t out_len)
{
	*out++ = 0x00;
	*out++ = 0x01;

	size_t fill_len = out_len - digest_info_len - digest_len - 3;
	memset(out, 0xFF, fill_len);
	out += fill_len;

	*out++ = 0x00;

	memcpy(out, digest_info, digest_info_len);
	out += digest_info_len;

	memcpy(out, digest, digest_len);
}

static bool pkcs1_v15_unpad_compare_digest(const uint8_t *digest_info, size_t digest_info_len, uint8_t *digest, size_t digest_len, uint8_t *in, size_t in_len)
{
	uint8_t *in_end = in + in_len;

	if (*in == 0x00) {
		in++;
	}

	uint8_t type = *in++;
	if ((type != 0x01) && (type != 0x02)) {
		DEBUG_ERROR("pkcs1_v15_unpad_compare_digest: invalid start marker");
		return false;
	}

	while (1) {
		if (in >= in_end) {
			DEBUG_ERROR("pkcs1_v15_unpad_compare_digest: no end marker found");
			return false;
		}
		if (*in++ == 0x00) {
			break;
		}
	}

	if (in + digest_info_len + digest_len != in_end) {
		DEBUG_ERROR("pkcs1_v15_unpad_compare_digest: digest length check failed");
		return false;
	}

	if (memcmp(in, digest_info, digest_info_len) != 0) {
		DEBUG_ERROR("pkcs1_v15_unpad_compare_digest: digest info check failed");
		return false;
	}

	in += digest_info_len;

	if (memcmp(in, digest, digest_len) != 0) {
		DEBUG_ERROR("pkcs1_v15_unpad_compare_digest: digest compare check failed");
		return false;
	}

	return true;
}

void pkcs1_v15_pad_sha1(sha1_digest_t *digest, uint8_t *out, size_t out_len)
{
	pkcs1_v15_pad_digest(pkcs1_v15_digest_info_sha1, sizeof(pkcs1_v15_digest_info_sha1), digest->u8, sizeof(digest->u8), out, out_len);
}

bool pkcs1_v15_unpad_compare_sha1(sha1_digest_t *digest, uint8_t *in, size_t in_len)
{
	return pkcs1_v15_unpad_compare_digest(pkcs1_v15_digest_info_sha1, sizeof(pkcs1_v15_digest_info_sha1), digest->u8, sizeof(digest->u8), in, in_len);
}

void pkcs1_v15_pad_sha256(sha256_digest_t *digest, uint8_t *out, size_t out_len)
{
	pkcs1_v15_pad_digest(pkcs1_v15_digest_info_sha256, sizeof(pkcs1_v15_digest_info_sha256), digest->u8, sizeof(digest->u8), out, out_len);
}

bool pkcs1_v15_unpad_compare_sha256(sha256_digest_t *digest, uint8_t *in, size_t in_len)
{
	return pkcs1_v15_unpad_compare_digest(pkcs1_v15_digest_info_sha256, sizeof(pkcs1_v15_digest_info_sha256), digest->u8, sizeof(digest->u8), in, in_len);
}

void pkcs1_v15_pad_sha384(sha384_digest_t *digest, uint8_t *out, size_t out_len)
{
	pkcs1_v15_pad_digest(pkcs1_v15_digest_info_sha384, sizeof(pkcs1_v15_digest_info_sha384), digest->u8, sizeof(digest->u8), out, out_len);
}

bool pkcs1_v15_unpad_compare_sha384(sha384_digest_t *digest, uint8_t *in, size_t in_len)
{
	return pkcs1_v15_unpad_compare_digest(pkcs1_v15_digest_info_sha384, sizeof(pkcs1_v15_digest_info_sha384), digest->u8, sizeof(digest->u8), in, in_len);
}

void pkcs1_v15_pad_sha512(sha512_digest_t *digest, uint8_t *out, size_t out_len)
{
	pkcs1_v15_pad_digest(pkcs1_v15_digest_info_sha512, sizeof(pkcs1_v15_digest_info_sha512), digest->u8, sizeof(digest->u8), out, out_len);
}

bool pkcs1_v15_unpad_compare_sha512(sha512_digest_t *digest, uint8_t *in, size_t in_len)
{
	return pkcs1_v15_unpad_compare_digest(pkcs1_v15_digest_info_sha512, sizeof(pkcs1_v15_digest_info_sha512), digest->u8, sizeof(digest->u8), in, in_len);
}
