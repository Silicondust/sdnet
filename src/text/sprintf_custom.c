/*
 * sprintf_custom.c
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

THIS_FILE("sprintf_custom");

struct vsprintf_custom_args_t {
	char *ptr;
	char *end;
};

static bool vsprintf_custom_write(void *arg, const char *str, size_t len)
{
	struct vsprintf_custom_args_t *args = (struct vsprintf_custom_args_t *)arg;

	if (args->ptr + len >= args->end) {
		len = args->end - args->ptr - 1;
		if (len == 0) {
			return false;
		}

		memcpy(args->ptr, str, len);
		args->ptr += len;
		return false;
	}

	memcpy(args->ptr, str, len);
	args->ptr += len;
	return true;
}

bool vsprintf_custom(char *buffer, char *end, const char *fmt, va_list ap)
{
	DEBUG_ASSERT(buffer < end, "bad buffer/end parameter");

	struct vsprintf_custom_args_t args;
	args.ptr = buffer;
	args.end = end;

	bool result = doprint_custom(vsprintf_custom_write, &args, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);

	*args.ptr = 0;
	return result;
}

bool sprintf_custom(char *buffer, char *end, const char *fmt, ...)
{
	DEBUG_ASSERT(buffer < end, "bad buffer/end parameter");

	struct vsprintf_custom_args_t args;
	args.ptr = buffer;
	args.end = end;

	va_list ap;
	va_start(ap, fmt);
	bool result = doprint_custom(vsprintf_custom_write, &args, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);
	va_end(ap);

	*args.ptr = 0;
	return result;
}

bool vsprintf_custom_url(char *buffer, char *end, const char *fmt, va_list ap)
{
	DEBUG_ASSERT(buffer < end, "bad buffer/end parameter");

	struct vsprintf_custom_args_t args;
	args.ptr = buffer;
	args.end = end;

	bool result = doprint_custom(vsprintf_custom_write, &args, DOPRINT_CUSTOM_MODE_URL, fmt, ap);

	*args.ptr = 0;
	return result;
}

bool sprintf_custom_url(char *buffer, char *end, const char *fmt, ...)
{
	DEBUG_ASSERT(buffer < end, "bad buffer/end parameter");

	struct vsprintf_custom_args_t args;
	args.ptr = buffer;
	args.end = end;

	va_list ap;
	va_start(ap, fmt);
	bool result = doprint_custom(vsprintf_custom_write, &args, DOPRINT_CUSTOM_MODE_URL, fmt, ap);
	va_end(ap);

	*args.ptr = 0;
	return result;
}

bool sprintf_hex_array(char *buffer, char *end, void *data, size_t data_length)
{
	uint8_t *data_ptr = (uint8_t *)data;
	uint8_t *data_end = data_ptr + data_length;

	*buffer = 0;

	while (data_ptr < data_end) {
		if (buffer + 2 >= end) {
			return false;
		}

		sprintf(buffer, "%02x", *data_ptr++);
		buffer += 2;
	}

	return true;
}
