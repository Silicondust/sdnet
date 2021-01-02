/*
 * char_str.c
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

THIS_FILE("char_str");

void str_utf16_to_utf8(char *out, char *end, uint16_t *in)
{
	while (1) {
		uint16_t c = *in++;
		if (c == 0) {
			utf8_put_null(out, end);
			return;
		}

		utf8_put_wchar(&out, end, c);
	}
}

void str_utf8_to_utf16(uint16_t *out, uint16_t *end, const char *in)
{
	end--;

	while (out < end) {
		uint16_t c = utf8_get_wchar((char **)&in, 0);
		if (c == 0) {
			break;
		}

		*out++ = c;
	}

	*out = 0;
}

void str_big5_to_utf8(char *out, char *end, char *in)
{
	while (1) {
		uint16_t c = big5_get_wchar(&in, 0);
		if (c == 0) {
			utf8_put_null(out, end);
			return;
		}

		utf8_put_wchar(&out, end, c);
	}
}

bool str_nb_to_str(char *out, char *end, struct netbuf *nb)
{
	bool success = true;
	size_t len = netbuf_get_remaining(nb);

	if (out + len >= end) {
		len = end - out - 1;
		success = false;
	}

	if (LIKELY(len > 0)) {
		netbuf_fwd_read(nb, out, len);
	}

	out[len] = 0;
	return success;
}

void str_to_upper(char *str)
{
	char *ptr = str;

	while (1) {
		char c = *ptr;
		if (c == 0) {
			return;
		}

		if ((c >= 'a') && (c <= 'z')) {
			*ptr = c - 'a' + 'A';
		}

		ptr++;
	}
}

char *str_trim_whitespace(char *str)
{
	while (1) {
		uint8_t c = (uint8_t)*str;
		if (c == 0) {
			return str;
		}
		if (c > ' ') {
			break;
		}
		str++;
	}

	char *ptr = str;
	char *end = str;
	while (1) {
		uint8_t c = (uint8_t)*ptr;
		if (c == 0) {
			*end = 0;
			return str;
		}
		if (c > ' ') {
			end = ptr + 1;
		}
		ptr++;
	}
}

int strprefixcmp(const char *str, const char *prefix)
{
	while (1) {
		char b = *prefix++;
		if (b == 0) {
			return 0;
		}

		char a = *str++;
		int ret = a - b;
		if (ret != 0) {
			return ret;
		}
	}
}

int strprefixcasecmp(const char *str, const char *prefix)
{
	while (1) {
		char b = *prefix++;
		if (b == 0) {
			return 0;
		}

		char a = *str++;
		int ret = a - b;
		if (ret != 0) {
			ret = tolower(a) - tolower(b);
			if (ret != 0) {
				return ret;
			}
		}
	}
}
