/*
 * strcasestr.c
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("strcasestr");

char *strcasestr(const char *haystack, const char *needle)
{
	size_t len = strlen(needle);
	const char *ptr = haystack;

	while (*ptr) {
		if (strncasecmp(ptr, needle, len) == 0) {
			return (char *)ptr;
		}

		ptr++;
	}

	return NULL;
}
