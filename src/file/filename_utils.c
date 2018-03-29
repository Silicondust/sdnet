/*
 * ./src/file/filename_utils.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("file_utils_common");

bool filename_is_cross_platform_valid_leading_char(uint16_t c)
{
	if (c <= 32) {
		return false;
	}

	switch (c) {
	case '\\':
	case '/':
	case ':':
	case '*':
	case '?':
	case '\"':
	case '<':
	case '>':
	case '|':
	case '.':
		return false;

	default:
		return true;
	}
}

bool filename_is_cross_platform_valid_trailing_char(uint16_t c)
{
	if (c <= 32) {
		return false;
	}

	switch (c) {
	case '\\':
	case '/':
	case ':':
	case '*':
	case '?':
	case '\"':
	case '<':
	case '>':
	case '|':
	case '.':
		return false;

	default:
		return true;
	}
}

bool filename_is_cross_platform_valid_middle_char(uint16_t c)
{
	if (c < 32) {
		return false;
	}

	switch (c) {
	case '\\':
	case '/':
	case ':':
	case '*':
	case '?':
	case '\"':
	case '<':
	case '>':
	case '|':
		return false;

	default:
		return true;
	}
}

void filename_inplace_fix_filename_str_without_path(char *str)
{
	char *rptr = str;
	char *wptr = str;
	char *wend = str + strlen(str) + 1;
	char *trailing = wptr;

	while (1) {
		uint16_t c = utf8_get_wchar(&rptr, 0);
		if (c == 0) {
			utf8_put_null(trailing, wend);
			return;
		}

		if (!filename_is_cross_platform_valid_leading_char(c)) {
			continue;
		}

		utf8_put_wchar(&wptr, wend, c);

		if (!filename_is_cross_platform_valid_trailing_char(c)) {
			break;
		}

		trailing = wptr;
		break;
	}

	while (1) {
		uint16_t c = utf8_get_wchar(&rptr, 0);
		if (c == 0) {
			utf8_put_null(trailing, wend);
			return;
		}

		if (!filename_is_cross_platform_valid_middle_char(c)) {
			continue;
		}

		utf8_put_wchar(&wptr, wend, c);

		if (!filename_is_cross_platform_valid_trailing_char(c)) {
			continue;
		}

		trailing = wptr;
	}
}

char *filename_strdup_without_path(const char *str, uint8_t pkg, uint8_t type)
{
	const char *ptr = strrchr(str, FILENAME_DIR_SEPARATOR_CHAR);
	if (ptr) {
		ptr++;
	} else {
		ptr = str;
	}

	return heap_strdup(ptr, pkg, type);
}

char *filename_strdup_append_slash(const char *str, uint8_t pkg, uint8_t type)
{
	size_t length = strlen(str);
	if (length == 0) {
		return NULL;
	}

	if (str[length - 1] == FILENAME_DIR_SEPARATOR_CHAR) {
		length--;
	}

	char *result = (char *)heap_alloc(length + 2, pkg, type);
	memcpy(result, str, length);
	result[length] = FILENAME_DIR_SEPARATOR_CHAR;
	result[length + 1] = 0;
	return result;
}
