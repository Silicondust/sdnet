/*
 * debug.c
 *
 * Copyright © 2007,2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

static bool debug_vprintf_write(void *arg, const char *str, size_t len)
{
	fwrite(str, 1, len, stdout);
	return true;
}

void debug_assert(const char *this_file, int line, const char *fmt, ...)
{
	printf("%s [%d]: ********** ASSERT FAILED **********\n", this_file, line);
	printf("%s [%d]: ", this_file, line);

	va_list ap;
	va_start(ap, fmt);
	doprint_custom(debug_vprintf_write, NULL, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);
	va_end(ap);

	printf("\n");

	while(1);
	exit(1);
}

void debug_vprintf(const char *this_file, int line, const char *fmt, va_list ap)
{
	printf("%s [%d]: ", this_file, line);

	doprint_custom(debug_vprintf_write, NULL, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);

	printf("\n");
}

void debug_printf(const char *this_file, int line, const char *fmt, ...)
{
	printf("%s [%d]: ", this_file, line);

	va_list ap;
	va_start(ap, fmt);
	doprint_custom(debug_vprintf_write, NULL, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);
	va_end(ap);

	printf("\n");
}

void debug_print_hex_array(const char *this_file, int line, const void *buffer, size_t size)
{
	printf("%s [%d]: ", this_file, line);

	uint8_t *ptr = (uint8_t *)buffer;
	uint8_t *end = (uint8_t *)buffer + size;

	while (ptr < end) {
		uint8_t *local_end = min(end, ptr + 64);
		while (ptr < local_end) {
			printf("%02X", (unsigned int)(unsigned char)*ptr++);
		}

		printf("\n");
	}
}

void debug_print_hex_buffer(const char *this_file, int line, const void *buffer, size_t size, size_t width)
{
	uint8_t *charptr = (uint8_t *)buffer;
	uint8_t *lineptr;
	uint8_t *end = (uint8_t *)buffer + size;

	printf("%s [%d]: Address  ", this_file, line);
	for (int i = 0; i < width ; i++) {
		printf(" B%d",i);
	}
	printf("\n%s [%d]:", this_file, line);
	for (int i = 0; i < width ; i++) {
		printf("---");
	}

	while(charptr < end) {
		printf("\n%s [%d]:", this_file, line);
		lineptr = charptr;
		uint8_t *local_end = min(end, charptr + width);
		printf(" %p:", lineptr);
		while (charptr < local_end) {
			printf(" %02x", (unsigned int)(unsigned char)*charptr++);
		}
		printf(" | ");
		charptr = lineptr;
		while (charptr < local_end) {
			if ((*charptr < 32) || (*charptr > 127)) {
				printf(".");
				charptr++;
				continue;
			}
			printf("%c", (char)*charptr++);
		}
	}
	printf("\n");
}

void debug_print_netbuf(const char *this_file, int line, struct netbuf *nb)
{
	printf("%s [%d]: ", this_file, line);

	uint8_t *ptr = (uint8_t *)netbuf_get_pos(nb);
	uint8_t *end = (uint8_t *)netbuf_get_end(nb);

	while (ptr < end) {
		printf("%02X", (unsigned int)(unsigned char)*ptr++);
	}

	printf("\n");
}

void debug_print_netbuf_text(const char *this_file, int line, struct netbuf *nb, size_t len)
{
	printf("%s [%d]: ", this_file, line);

	if (len == 0) {
		len = netbuf_get_remaining(nb);
	}

	uint8_t *ptr = (uint8_t *)netbuf_get_pos(nb);
	uint8_t *end = ptr + len;

	while (ptr < end) {
		printf("%c", (char)*ptr++);
	}

	printf("\n");
}
