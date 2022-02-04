/*
 * char_utf8.c
 *
 * Copyright © 2008 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("char_utf8");

uint16_t utf8_get_wchar(const char **pptr, uint16_t error_char)
{
	const char *ptr = *pptr;

	uint8_t c = (uint8_t)*ptr++;
	if (c == 0) {
		return 0;
	}

	if ((c & 0x80) == 0x00) {
		*pptr = ptr;
		return (uint16_t)c;
	}

	if ((c & 0xE0) == 0xC0) {
		uint16_t result = (uint16_t)(c & 0x1F) << 6;

		c = (uint8_t)*ptr;
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			*pptr = ptr;
			return error_char;
		}

		ptr++;
		result |= (uint16_t)(c & 0x3F) << 0;

		*pptr = ptr;
		return result;
	}

	if ((c & 0xF0) == 0xE0) {
		uint16_t result = (uint16_t)(c & 0x0F) << 12;

		c = (uint8_t)*ptr;
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			*pptr = ptr;
			return error_char;
		}

		ptr++;
		result |= (uint16_t)(c & 0x3F) << 6;

		c = (uint8_t)*ptr;
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			*pptr = ptr;
			return error_char;
		}

		ptr++;
		result |= (uint16_t)(c & 0x3F) << 0;

		*pptr = ptr;
		return result;
	}

	DEBUG_WARN("utf8 string corrupt");
	*pptr = ptr;
	return error_char;
}

void utf8_truncate_str_on_error(char *str)
{
	char *ptr = str;
	while (1) {
		char *tmp = ptr;
		if (utf8_get_wchar((const char **)&tmp, 0) == 0) {
			*ptr = 0;
			break;
		}

		ptr = tmp;
	}
}

void utf8_put_wchar(char **pptr, char *end, uint16_t c)
{
	char *ptr = *pptr;

	if (LIKELY(c <= 0x007F)) {
		if (UNLIKELY(ptr + 2 > end)) { /* Allow room for a terminating null to be written at a later date. */
			goto overflow;
		}

		*ptr++ = (uint8_t)c;
		*pptr = ptr;
		return;
	}

	if (LIKELY(c <= 0x07FF)) {
		if (UNLIKELY(ptr + 3 > end)) { /* Allow room for a terminating null to be written at a later date. */
			goto overflow;
		}

		*ptr++ = 0xC0 | (c >> 6);
		*ptr++ = 0x80 | (c & 0x003F);
		*pptr = ptr;
		return;
	}

	if (UNLIKELY(ptr + 4 > end)) { /* Allow room for a terminating null to be written at a later date. */
		goto overflow;
	}

	*ptr++ = 0xE0 | (c >> 12);
	*ptr++ = 0x80 | ((c >> 6) & 0x003F);
	*ptr++ = 0x80 | ((c >> 0) & 0x003F);
	*pptr = ptr;
	return;

overflow:
	while (1) {
		if (LIKELY(ptr >= end)) {
			break;
		}
		*ptr++ = 0;
	}

	*pptr = end;
}

void utf8_put_null(char *ptr, char *end)
{
	if (ptr >= end) {
		return;
	}

	*ptr = 0;
}
