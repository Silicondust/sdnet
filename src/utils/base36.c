/*
 * base36.c
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("base36");

bool base36_encode_upper_from_uint64(uint64_t v, char *str, char *end)
{
	char buffer[16];
	char *out = buffer + sizeof(buffer) - 1;
	*out = 0;

	while (1) {
		int index = v % 36;
		v /= 36;

		out--;
		*out = (index >= 10) ? 'A' - 10 + index : '0' + index;

		if (v == 0) {
			break;
		}
	}

	return sprintf_custom(str, end, "%s", out);
}

bool base36_encode_lower_from_uint64(uint64_t v, char *str, char *end)
{
	char buffer[16];
	char *out = buffer + sizeof(buffer) - 1;
	*out = 0;

	while (1) {
		int index = v % 36;
		v /= 36;

		out--;
		*out = (index >= 10) ? 'a' - 10 + index : '0' + index;

		if (v == 0) {
			break;
		}
	}

	return sprintf_custom(str, end, "%s", out);
}

uint64_t base36_decode_to_uint64(const char *str, uint64_t value_on_error)
{
	char c = *str++;
	if (c == 0) {
		return value_on_error;
	}

	uint64_t result = 0;
	while (1) {
		if ((c >= '0') && (c <= '9')) {
			c = c - '0';
		} else if ((c >= 'A') && (c <= 'Z')) {
			c = c - 'A' + 10;
		} else if ((c >= 'a') && (c <= 'z')) {
			c = c - 'a' + 10;
		} else {
			return value_on_error;
		}

		result += (uint64_t)(uint8_t)c;

		c = *str++;
		if (c == 0) {
			return result;
		}

		result *= 36;
	}
}
