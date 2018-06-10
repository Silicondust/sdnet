/*
 * debug.h
 *
 * Copyright © 2007,2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define THIS_FILE(x) static char __this_file[] __attribute__((unused)) = x;

#define DEBUG_ASSERT(cond, fmt, ...) \
{ \
	if (RUNTIME_DEBUG && !(cond)) { \
		debug_assert(__this_file, __LINE__, fmt, ##__VA_ARGS__); \
	} \
}

#define DEBUG_INTERNAL(fmt, ...) \
{ \
	if (RUNTIME_DEBUG) { \
		debug_printf(__this_file, __LINE__, fmt, ##__VA_ARGS__); \
	} \
}

#define DEBUG_PRINT_HEX_ARRAY(buffer, size) \
{ \
	if (RUNTIME_DEBUG) { \
		debug_print_hex_array(__this_file, __LINE__, buffer, size); \
	} \
}

#define DEBUG_PRINT_NETBUF(nb) \
{ \
	if (RUNTIME_DEBUG) { \
		debug_print_netbuf(__this_file, __LINE__, nb); \
	} \
}

#define DEBUG_PRINT_NETBUF_TEXT(nb, len) \
{ \
	if (RUNTIME_DEBUG) { \
		debug_print_netbuf_text(__this_file, __LINE__, nb, len); \
	} \
}

#define DEBUG_ERROR(fmt, ...) DEBUG_INTERNAL(fmt, ##__VA_ARGS__)
#define DEBUG_WARN(fmt, ...) DEBUG_INTERNAL(fmt, ##__VA_ARGS__)
#define DEBUG_INFO2(fmt, ...) DEBUG_INTERNAL(fmt, ##__VA_ARGS__)
#define DEBUG_TRACE(fmt, ...)

#if !defined(DEBUG_INFO)
#define DEBUG_INFO(fmt, ...) DEBUG_INTERNAL(fmt, ##__VA_ARGS__)
#endif

extern void debug_assert(const char *this_file, int line, const char *fmt, ...) __attribute__((noreturn));
extern void debug_printf(const char *this_file, int line, const char *fmt, ...);
extern void debug_vprintf(const char *this_file, int line, const char *fmt, va_list ap);
extern void debug_print_hex_array(const char *this_file, int line, const void *buffer, size_t size);
extern void debug_print_netbuf(const char *this_file, int line, struct netbuf *nb);
extern void debug_print_netbuf_text(const char *this_file, int line, struct netbuf *nb, size_t len);
