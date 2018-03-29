/*
 * ./src/linux/android/debug.c
 *
 * Copyright © 2007,2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <android/log.h>

static const char debug_name[] = "hdhomerun_record";
static char debug_line[256];

void debug_assert(const char *this_file, int line, const char *fmt, ...)
{
	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ********** ASSERT FAILED **********", this_file, line);
	__android_log_print(ANDROID_LOG_ERROR, debug_name, "%s", debug_line);

	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ", this_file, line);
	char *pos = strchr(debug_line, 0);

	va_list ap;
	va_start(ap, fmt);
	vsprintf_custom(pos, debug_line + sizeof(debug_line), fmt, ap);
	va_end(ap);

	__android_log_print(ANDROID_LOG_ERROR, debug_name, "%s", debug_line);

	exit(1);
}

void debug_printf(const char *this_file, int line, const char *fmt, ...)
{
	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ", this_file, line);
	char *pos = strchr(debug_line, 0);

	va_list ap;
	va_start(ap, fmt);
	vsprintf_custom(pos, debug_line + sizeof(debug_line), fmt, ap);
	va_end(ap);

	__android_log_print(ANDROID_LOG_INFO, debug_name, "%s", debug_line);
}

void debug_print_hex_array(const char *this_file, int line, const void *buffer, size_t size)
{
	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ", this_file, line);
	char *pos = strchr(debug_line, 0);

	uint8_t *ptr = (uint8_t *)buffer;
	uint8_t *end = (uint8_t *)buffer + size;

	while (ptr < end) {
		sprintf_custom(pos, debug_line + sizeof(debug_line), "%02X", (unsigned int)(unsigned char)*ptr++);
		pos = strchr(pos, 0);
	}

	__android_log_print(ANDROID_LOG_INFO, debug_name, "%s", debug_line);
}

void debug_print_netbuf(const char *this_file, int line, struct netbuf *nb)
{
	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ", this_file, line);
	char *pos = strchr(debug_line, 0);

	uint8_t *ptr = (uint8_t *)netbuf_get_pos(nb);
	uint8_t *end = (uint8_t *)netbuf_get_end(nb);

	while (ptr < end) {
		sprintf_custom(pos, debug_line + sizeof(debug_line), "%02X", (unsigned int)(unsigned char)*ptr++);
		pos = strchr(pos, 0);
	}

	__android_log_print(ANDROID_LOG_INFO, debug_name, "%s", debug_line);
}

void debug_print_netbuf_text(const char *this_file, int line, struct netbuf *nb, size_t len)
{
	sprintf_custom(debug_line, debug_line + sizeof(debug_line), "%s [%d]: ", this_file, line);
	char *pos = strchr(debug_line, 0);

	if (len == 0) {
		len = netbuf_get_remaining(nb);
	}

	uint8_t *ptr = (uint8_t *)netbuf_get_pos(nb);
	uint8_t *end = ptr + len;

	while (ptr < end) {
		sprintf_custom(pos, debug_line + sizeof(debug_line), "%c", (char)*ptr++);
		pos = strchr(pos, 0);
	}

	__android_log_print(ANDROID_LOG_INFO, debug_name, "%s", debug_line);
}
