/*
 * random.c
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("random");

void random_getbytes(uint8_t *out, size_t length)
{
	uint8_t *end = out + length;

	while (out + 4 <= end) {
		uint32_t v = arc4random();
		*out++ = (uint8_t)v; v >>= 8;
		*out++ = (uint8_t)v; v >>= 8;
		*out++ = (uint8_t)v; v >>= 8;
		*out++ = (uint8_t)v;
	}

	if (out >= end) {
		return;
	}

	uint32_t v = arc4random();
	while (out < end) {
		*out++ = (uint8_t)v; v >>= 8;
	}
}
