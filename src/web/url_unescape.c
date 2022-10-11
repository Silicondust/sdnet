/*
 * url_unescape.c
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("url_unescape");

const char *url_unescape(char *out, char *end, const char *in)
{
	char last_c = 0;

	while (1) {
		if (out >= end) {
			return NULL;
		}

		char c = *in++;

		if ((c == 0) || (c == '?')) {
			*out = 0;
			return in - 1;
		}

		if ((c == '/') && (last_c == '/')) {
			continue;
		}

		last_c = c;

		if (c == '%') {
			char str[4];

			str[0] = *in++;
			if (str[0] == 0) {
				return NULL;
			}

			str[1] = *in++;
			if (str[1] == 0) {
				return NULL;
			}

			str[2] = 0;

			char *end;
			unsigned long val = strtoul(str, &end, 16);
			if (*end != 0) {
				return NULL;
			}
			if (val == 0) {
				return NULL;
			}

			*out++ = (char)(uint8_t)val;
			continue;
		}

		*out++ = c;
	}
}
