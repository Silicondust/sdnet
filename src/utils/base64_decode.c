/*
 * base64_decode.c
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

THIS_FILE("base64_decode");

#define BASE64_DECODE_CHAR_BAD 77
#define BASE64_DECODE_CHAR_SKIP 85
#define BASE64_DECODE_CHAR_EQUALS 90
#define BASE64_DECODE_CHAR_END 99

/* table decodes both base64 and base64url */
static uint8_t base64_decode_table[256] =
{
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 85, 77, 77, 85, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 62, 77, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 90, 77, 77,
	77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
	77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
};

size_t base64_decode_max_length(size_t encoded_size)
{
	return encoded_size / 4 * 3;
}

size_t base64_decode_str_max_length(const char *encoded_data)
{
	return strlen(encoded_data) / 4 * 3;
}

size_t base64_decode_netbuf_max_length(struct netbuf *nb)
{
	return netbuf_get_remaining(nb) / 4 * 3;
}

static uint8_t base64_decode_str_get_next_symbol_val(const char **pencoded_data)
{
	while (1) {
		char lookup = *(*pencoded_data)++;
		if (lookup == 0) {
			(*pencoded_data)--;
			return BASE64_DECODE_CHAR_END;
		}

		uint8_t val = base64_decode_table[(uint8_t)lookup];
		if (val == BASE64_DECODE_CHAR_SKIP) {
			continue;
		}

		return val;
	}
}

size_t base64_decode_str_to_mem(const char *encoded_data, uint8_t *buffer, size_t buffer_size)
{
	uint8_t *ptr = buffer;
	uint8_t *end = buffer + buffer_size;

	while (1) {
		uint8_t v[4];
		v[0] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[1] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[2] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[3] = base64_decode_str_get_next_symbol_val(&encoded_data);

		uint8_t test = v[0] | v[1] | v[2] | v[3];
		if (test >= 64) {
			if (v[0] == BASE64_DECODE_CHAR_END) {
				return (ptr - buffer);
			}

			if ((v[0] >= 64) || (v[1] >= 64) || (v[3] != BASE64_DECODE_CHAR_EQUALS)) {
				return 0;
			}

			if (v[2] < 64) {
				if (base64_decode_str_get_next_symbol_val(&encoded_data) != BASE64_DECODE_CHAR_END) {
					return 0;
				}

				if (ptr + 2 > end) {
					ptr += 2;
					return (ptr - buffer);
				}

				uint32_t val24;
				val24  = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;
				val24 |= (uint32_t)v[2] << 6;

				*ptr++ = (uint8_t)(val24 >> 16);
				*ptr++ = (uint8_t)(val24 >> 8);
				return (ptr - buffer);
			}

			if (v[2] == BASE64_DECODE_CHAR_EQUALS) {
				if (base64_decode_str_get_next_symbol_val(&encoded_data) != BASE64_DECODE_CHAR_END) {
					return 0;
				}

				if (ptr + 1 > end) {
					ptr += 1;
					return (ptr - buffer);
				}

				uint32_t val24;
				val24  = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;

				*ptr++ = (uint8_t)(val24 >> 16);
				return (ptr - buffer);
			}

			return 0;
		}

		if (ptr + 3 > end) {
			ptr += 3;
			continue;
		}

		uint32_t val24;
		val24  = (uint32_t)v[0] << 18;
		val24 |= (uint32_t)v[1] << 12;
		val24 |= (uint32_t)v[2] << 6;
		val24 |= (uint32_t)v[3] << 0;

		*ptr++ = (uint8_t)(val24 >> 16);
		*ptr++ = (uint8_t)(val24 >> 8);
		*ptr++ = (uint8_t)(val24 >> 0);
	}
}

bool base64_decode_str_to_netbuf(const char *encoded_data, struct netbuf *output_nb)
{
	size_t encoded_size = strlen(encoded_data);
	size_t decoded_length = base64_decode_max_length(encoded_size);
	if (!netbuf_fwd_make_space(output_nb, decoded_length)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	while (1) {
		uint8_t v[4];
		v[0] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[1] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[2] = base64_decode_str_get_next_symbol_val(&encoded_data);
		v[3] = base64_decode_str_get_next_symbol_val(&encoded_data);

		uint8_t test = v[0] | v[1] | v[2] | v[3];
		if (test >= 64) {
			if (v[0] == BASE64_DECODE_CHAR_END) {
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			if ((v[0] >= 64) || (v[1] >= 64) || (v[3] != BASE64_DECODE_CHAR_EQUALS)) {
				return false;
			}

			if (v[2] < 64) {
				if (base64_decode_str_get_next_symbol_val(&encoded_data) != BASE64_DECODE_CHAR_END) {
					return false;
				}

				uint32_t val24;
				val24 = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;
				val24 |= (uint32_t)v[2] << 6;

				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 8));
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			if (v[2] == BASE64_DECODE_CHAR_EQUALS) {
				if (base64_decode_str_get_next_symbol_val(&encoded_data) != BASE64_DECODE_CHAR_END) {
					return false;
				}

				uint32_t val24;
				val24 = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;

				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			return false;
		}

		uint32_t val24;
		val24 = (uint32_t)v[0] << 18;
		val24 |= (uint32_t)v[1] << 12;
		val24 |= (uint32_t)v[2] << 6;
		val24 |= (uint32_t)v[3] << 0;

		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 8));
		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 0));
	}
}

static uint8_t base64_decode_netbuf_get_next_symbol_val(struct netbuf *nb)
{
	while (netbuf_fwd_check_space(nb, 1)) {
		uint8_t lookup = netbuf_fwd_read_u8(nb);
		uint8_t val = base64_decode_table[lookup];
		if (val == BASE64_DECODE_CHAR_SKIP) {
			continue;
		}

		return val;
	}

	return BASE64_DECODE_CHAR_END;
}

size_t base64_decode_netbuf_to_mem(struct netbuf *nb, uint8_t *buffer, size_t buffer_size)
{
	uint8_t *ptr = buffer;
	uint8_t *end = buffer + buffer_size;

	while (1) {
		uint8_t v[4];
		v[0] = base64_decode_netbuf_get_next_symbol_val(nb);
		v[1] = base64_decode_netbuf_get_next_symbol_val(nb);
		v[2] = base64_decode_netbuf_get_next_symbol_val(nb);
		v[3] = base64_decode_netbuf_get_next_symbol_val(nb);

		uint8_t test = v[0] | v[1] | v[2] | v[3];
		if (test >= 64) {
			if (v[0] == BASE64_DECODE_CHAR_END) {
				return (ptr - buffer);
			}

			if ((v[0] >= 64) || (v[1] >= 64) || (v[3] != BASE64_DECODE_CHAR_EQUALS)) {
				return 0;
			}

			if (v[2] < 64) {
				if (base64_decode_netbuf_get_next_symbol_val(nb) != BASE64_DECODE_CHAR_END) {
					return 0;
				}

				if (ptr + 2 > end) {
					ptr += 2;
					return (ptr - buffer);
				}

				uint32_t val24;
				val24  = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;
				val24 |= (uint32_t)v[2] << 6;

				*ptr++ = (uint8_t)(val24 >> 16);
				*ptr++ = (uint8_t)(val24 >> 8);
				return (ptr - buffer);
			}

			if (v[2] == BASE64_DECODE_CHAR_EQUALS) {
				if (base64_decode_netbuf_get_next_symbol_val(nb) != BASE64_DECODE_CHAR_END) {
					return 0;
				}

				if (ptr + 1 > end) {
					ptr += 1;
					return (ptr - buffer);
				}

				uint32_t val24;
				val24  = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;

				*ptr++ = (uint8_t)(val24 >> 16);
				return (ptr - buffer);
			}

			return 0;
		}

		if (ptr + 3 > end) {
			ptr += 3;
			continue;
		}

		uint32_t val24;
		val24  = (uint32_t)v[0] << 18;
		val24 |= (uint32_t)v[1] << 12;
		val24 |= (uint32_t)v[2] << 6;
		val24 |= (uint32_t)v[3] << 0;

		*ptr++ = (uint8_t)(val24 >> 16);
		*ptr++ = (uint8_t)(val24 >> 8);
		*ptr++ = (uint8_t)(val24 >> 0);
	}
}

bool base64_decode_netbuf_to_netbuf2(struct netbuf *encoded_nb, struct netbuf *output_nb)
{
	size_t encoded_size = netbuf_get_remaining(encoded_nb);
	size_t decoded_length = base64_decode_max_length(encoded_size);
	if (!netbuf_fwd_make_space(output_nb, decoded_length)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	while (1) {
		uint8_t v[4];
		v[0] = base64_decode_netbuf_get_next_symbol_val(encoded_nb);
		v[1] = base64_decode_netbuf_get_next_symbol_val(encoded_nb);
		v[2] = base64_decode_netbuf_get_next_symbol_val(encoded_nb);
		v[3] = base64_decode_netbuf_get_next_symbol_val(encoded_nb);

		uint8_t test = v[0] | v[1] | v[2] | v[3];
		if (test >= 64) {
			if (v[0] == BASE64_DECODE_CHAR_END) {
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			if ((v[0] >= 64) || (v[1] >= 64) || (v[3] != BASE64_DECODE_CHAR_EQUALS)) {
				return false;
			}

			if (v[2] < 64) {
				if (base64_decode_netbuf_get_next_symbol_val(encoded_nb) != BASE64_DECODE_CHAR_END) {
					return false;
				}

				uint32_t val24;
				val24 = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;
				val24 |= (uint32_t)v[2] << 6;

				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 8));
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			if (v[2] == BASE64_DECODE_CHAR_EQUALS) {
				if (base64_decode_netbuf_get_next_symbol_val(encoded_nb) != BASE64_DECODE_CHAR_END) {
					return false;
				}

				uint32_t val24;
				val24 = (uint32_t)v[0] << 18;
				val24 |= (uint32_t)v[1] << 12;

				netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
				netbuf_set_end_to_pos(output_nb);
				return true;
			}

			return false;
		}

		uint32_t val24;
		val24 = (uint32_t)v[0] << 18;
		val24 |= (uint32_t)v[1] << 12;
		val24 |= (uint32_t)v[2] << 6;
		val24 |= (uint32_t)v[3] << 0;

		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 16));
		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 8));
		netbuf_fwd_write_u8(output_nb, (uint8_t)(val24 >> 0));
	}
}
