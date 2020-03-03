/*
 * base64_encode.c
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

THIS_FILE("base64_encode");

char base64_encode_table[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
char base64url_encode_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t base64_encode_length(size_t raw_size)
{
	return (raw_size + 2) / 3 * 4;
}

void base64_encode_mem_to_str(uint8_t *raw, size_t raw_size, char *output, char *encode_table)
{
	uint8_t *end = raw + raw_size;

	while (raw + 3 <= end) {
		uint32_t raw24;
		raw24  = (uint32_t)(*raw++) << 16;
		raw24 |= (uint32_t)(*raw++) << 8;
		raw24 |= (uint32_t)(*raw++) << 0;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 6) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 0) & 0x3F];
	}

	size_t remaining = end - raw;
	if (remaining == 2) {
		uint32_t raw24;
		raw24  = (uint32_t)(*raw++) << 16;
		raw24 |= (uint32_t)(*raw++) << 8;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 6) & 0x3F];
		if (encode_table[64]) {
			*output++ = (uint8_t)encode_table[64];
		}
		*output = 0;
		return;
	}

	if (remaining == 1) {
		uint32_t raw24;
		raw24 = (uint32_t)(*raw++) << 16;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		if (encode_table[64]) {
			*output++ = (uint8_t)encode_table[64];
			*output++ = (uint8_t)encode_table[64];
		}
		*output = 0;
		return;
	}

	*output = 0;
}

void base64_encode_netbuf_to_str(struct netbuf *raw_nb, size_t raw_size, char *output, char *encode_table)
{
	addr_t end = netbuf_get_pos(raw_nb) + raw_size;

	while (netbuf_get_pos(raw_nb) + 3 <= end) {
		uint32_t raw24;
		raw24 = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 8;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 0;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 6) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 0) & 0x3F];
	}

	size_t remaining = end - netbuf_get_pos(raw_nb);
	if (remaining == 2) {
		uint32_t raw24;
		raw24 = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 8;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 6) & 0x3F];
		if (encode_table[64]) {
			*output++ = (uint8_t)encode_table[64];
		}
		*output = 0;
		return;
	}

	if (remaining == 1) {
		uint32_t raw24;
		raw24 = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;

		*output++ = (uint8_t)encode_table[(raw24 >> 18) & 0x3F];
		*output++ = (uint8_t)encode_table[(raw24 >> 12) & 0x3F];
		if (encode_table[64]) {
			*output++ = (uint8_t)encode_table[64];
			*output++ = (uint8_t)encode_table[64];
		}
		*output = 0;
		return;
	}

	*output = 0;
}

bool base64_encode_mem_to_netbuf(uint8_t *raw, size_t raw_size, struct netbuf *output_nb, char *encode_table)
{
	size_t encoded_length = base64_encode_length(raw_size);
	if (!netbuf_fwd_make_space(output_nb, encoded_length)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	uint8_t *end = raw + raw_size;

	while (raw + 3 <= end) {
		uint32_t raw24;
		raw24  = (uint32_t)(*raw++) << 16;
		raw24 |= (uint32_t)(*raw++) << 8;
		raw24 |= (uint32_t)(*raw++) << 0;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 6) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 0) & 0x3F]);
	}

	size_t remaining = end - raw;
	if (remaining == 2) {
		uint32_t raw24;
		raw24  = (uint32_t)(*raw++) << 16;
		raw24 |= (uint32_t)(*raw++) << 8;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 6) & 0x3F]);
		if (encode_table[64]) {
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
		}

		return true;
	}

	if (remaining == 1) {
		uint32_t raw24;
		raw24 = (uint32_t)(*raw++) << 16;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		if (encode_table[64]) {
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
		}

		return true;
	}

	return true;
}

bool base64_encode_netbuf_to_netbuf2(struct netbuf *raw_nb, size_t raw_size, struct netbuf *output_nb, char *encode_table)
{
	size_t encoded_length = base64_encode_length(raw_size);
	if (!netbuf_fwd_make_space(output_nb, encoded_length)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	addr_t end = netbuf_get_pos(raw_nb) + raw_size;

	while (netbuf_get_pos(raw_nb) + 3 <= end) {
		uint32_t raw24;
		raw24  = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 8;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 0;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 6) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 0) & 0x3F]);
	}

	size_t remaining = end - netbuf_get_pos(raw_nb);
	if (remaining == 2) {
		uint32_t raw24;
		raw24  = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;
		raw24 |= (uint32_t)netbuf_fwd_read_u8(raw_nb) << 8;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 6) & 0x3F]);
		if (encode_table[64]) {
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
		}

		return true;
	}

	if (remaining == 1) {
		uint32_t raw24;
		raw24  = (uint32_t)netbuf_fwd_read_u8(raw_nb) << 16;

		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 18) & 0x3F]);
		netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[(raw24 >> 12) & 0x3F]);
		if (encode_table[64]) {
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
			netbuf_fwd_write_u8(output_nb, (uint8_t)encode_table[64]);
		}

		return true;
	}

	return true;
}
