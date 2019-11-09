/*
 * doprint_custom.c
 *
 * Copyright © 2012-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("doprint_custom");

#define ELEMENT_TYPE_PERCENT 0
#define ELEMENT_TYPE_INT 1
#define	ELEMENT_TYPE_LONG_LONG 3
#define ELEMENT_TYPE_DOUBLE 5
#define ELEMENT_TYPE_MAC_ADDR 6
#define	ELEMENT_TYPE_IPV4_ADDR 7
#define ELEMENT_TYPE_STRING 8

static uint8_t doprint_custom_get_element_str(const char **pfmt, char element_str[])
{
	const char *fmt = *pfmt;
	char *eptr = element_str;
	*eptr++ = '%';

	unsigned int lcount = 0;

	while (1) {
		char fmtc = *fmt++;
		*eptr++ = fmtc;

		if ((fmtc >= '0') && (fmtc <= '9')) {
			continue;
		}

		switch (fmtc) {
		case '.':
		case 'h':
			break;

		case 'l':
			lcount++;
			break;

		case 'd':
		case 'o':
		case 'u':
		case 'x':
		case 'X':
			*eptr = 0;
			*pfmt = fmt;
			if (lcount >= 2) {
				return ELEMENT_TYPE_LONG_LONG;
			}
			if (lcount == 1) {
				return (sizeof(long) > sizeof(int)) ? ELEMENT_TYPE_LONG_LONG : ELEMENT_TYPE_INT;
			}
			return ELEMENT_TYPE_INT;

		case 'p':
			*eptr = 0;
			*pfmt = fmt;
			return (sizeof(addr_t) > sizeof(int)) ? ELEMENT_TYPE_LONG_LONG : ELEMENT_TYPE_INT;

		case 'f':
			*eptr = 0;
			*pfmt = fmt;
			return ELEMENT_TYPE_DOUBLE;

		case 'm':
			*eptr = 0;
			*pfmt = fmt;
			return ELEMENT_TYPE_MAC_ADDR;

		case 'v':
			*eptr = 0;
			*pfmt = fmt;
			return ELEMENT_TYPE_IPV4_ADDR;

		case 's':
			*eptr = 0;
			*pfmt = fmt;
			return ELEMENT_TYPE_STRING;

		case '%':
			if (fmt == *pfmt + 1) {
				*pfmt = fmt;
				return ELEMENT_TYPE_PERCENT;
			}

			DEBUG_ERROR("malformed fmt str");
			return ELEMENT_TYPE_PERCENT;

		default:
			DEBUG_ERROR("malformed fmt str");
			return ELEMENT_TYPE_PERCENT;
		}
	}
}

static bool doprint_custom_sprintf(doprint_custom_write_func_t write_func, void *write_arg, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	char str[64];
	int len = vsnprintf(str, sizeof(str), fmt, ap);
	DEBUG_ASSERT((size_t)len < sizeof(str), "doprint_custom_sprintf overflow");

	va_end(ap);

	return write_func(write_arg, str, len);
}

static bool doprint_custom_str(doprint_custom_write_func_t write_func, void *write_arg, const char *str)
{
	size_t len = strlen(str);
	if (len == 0) {
		return true;
	}

	return write_func(write_arg, str, len);
}

static const char *doprint_custom_str_json_escaped_lookup(char c)
{
	/* Foward slashes are not escaped (escaping foward slashes is optional and only required to solve a specific corner case when embedding JSON inside HTML). */
	switch (c) {
	case '"':
		return "\\\"";
	case '\\':
		return "\\\\";
	case '\t':
		return "\\t";
	case '\r':
		return "\\r";
	case '\n':
		return "\\n";
	default:
		DEBUG_ASSERT((unsigned char)c >= 32, "invalid character 0x%02x in string", (unsigned char)c);
		return NULL;
	}
}

static bool doprint_custom_str_json_escaped(doprint_custom_write_func_t write_func, void *write_arg, const char *str)
{
	const char *ptr = str;
	while (1) {
		char c = *ptr;
		if (c == 0) {
			if (ptr == str) {
				return true;
			}

			return write_func(write_arg, str, ptr - str);
		}

		const char *escape = doprint_custom_str_json_escaped_lookup(c);
		if (escape) {
			if (ptr > str) {
				if (!write_func(write_arg, str, ptr - str)) {
					return false;
				}
			}

			if (!write_func(write_arg, escape, strlen(escape))) {
				return false;
			}

			ptr++;
			str = ptr;
			continue;
		}

		ptr++;
	}
}

static bool doprint_custom_str_url_escaped_lookup(char c)
{
	if ((c >= 'a') && (c <= 'z')) {
		return false;
	}
	if ((c >= 'A') && (c <= 'Z')) {
		return false;
	}
	if ((c >= '0') && (c <= '9')) {
		return false;
	}
	if (strchr("-_.~", c)) {
		return false;
	}
	return true;
}

static bool doprint_custom_str_url_escaped(doprint_custom_write_func_t write_func, void *write_arg, const char *str)
{
	const char *ptr = str;
	while (1) {
		char c = *ptr;
		if (c == 0) {
			if (ptr == str) {
				return true;
			}

			return write_func(write_arg, str, ptr - str);
		}

		bool escape = doprint_custom_str_url_escaped_lookup(c);
		if (escape) {
			if (ptr > str) {
				if (!write_func(write_arg, str, ptr - str)) {
					return false;
				}
			}

			if (!doprint_custom_sprintf(write_func, write_arg, "%%%02X", (unsigned int)(unsigned char)c)) {
				return false;
			}

			ptr++;
			str = ptr;
			continue;
		}

		ptr++;
	}
}

static const char *doprint_custom_str_xml_escaped_lookup(char c)
{
	switch (c) {
	case '"':
		return "&quot;";
	case '\'':
		return "&apos;";
	case '&':
		return "&amp;";
	case '<':
		return "&lt;";
	case '>':
		return "&gt;";
	default:
		return NULL;
	}
}

static bool doprint_custom_str_xml_escaped(doprint_custom_write_func_t write_func, void *write_arg, const char *str)
{
	const char *ptr = str;
	while (1) {
		char c = *ptr;
		if (c == 0) {
			if (ptr == str) {
				return true;
			}
			return write_func(write_arg, str, ptr - str);
		}

		const char *escape = doprint_custom_str_xml_escaped_lookup(c);
		if (escape) {
			if (ptr > str) {
				if (!write_func(write_arg, str, ptr - str)) {
					return false;
				}
			}

			if (!write_func(write_arg, escape, strlen(escape))) {
				return false;
			}

			ptr++;
			str = ptr;
			continue;
		}

		ptr++;
	}
}

bool doprint_custom(doprint_custom_write_func_t write_func, void *write_arg, uint8_t mode, const char *fmt, va_list ap)
{
	while (1) {
		const char *marker = strchr(fmt, '%');
		if (!marker) {
			size_t len = strlen(fmt);
			if (len == 0) {
				return true;
			}

			return write_func(write_arg, fmt, len);
		}

		if (marker != fmt) {
			size_t len = marker - fmt;
			if (!write_func(write_arg, fmt, len)) {
				return false;
			}

			fmt += len;
		}

		fmt++;
		char element_str[16];
		uint8_t element_type = doprint_custom_get_element_str(&fmt, element_str);

		if (element_type == ELEMENT_TYPE_PERCENT) {
			if (!write_func(write_arg, "%", 1)) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_INT) {
			unsigned int val = va_arg(ap, unsigned int);
			if (!doprint_custom_sprintf(write_func, write_arg, element_str, val)) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_LONG_LONG) {
			unsigned long long val = va_arg(ap, unsigned long long);
			if (!doprint_custom_sprintf(write_func, write_arg, element_str, val)) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_DOUBLE) {
			double val = va_arg(ap, double);
			if (!doprint_custom_sprintf(write_func, write_arg, element_str, val)) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_MAC_ADDR) {
			uint8_t *mac = va_arg(ap, uint8_t *);
			if (!doprint_custom_sprintf(write_func, write_arg, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_IPV4_ADDR) {
			ipv4_addr_t val = va_arg(ap, ipv4_addr_t);
			if (!doprint_custom_sprintf(write_func, write_arg, "%u.%u.%u.%u", (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, (val >> 0) & 0xFF)) {
				return false;
			}

			continue;
		}

		if (element_type == ELEMENT_TYPE_STRING) {
			const char *str = va_arg(ap, char *);
			if (!str) {
				str = "(null)";
			}

			switch (mode) {
			case DOPRINT_CUSTOM_MODE_JSON:
				if (!doprint_custom_str_json_escaped(write_func, write_arg, str)) {
					return false;
				}
				break;

			case DOPRINT_CUSTOM_MODE_URL:
				if (!doprint_custom_str_url_escaped(write_func, write_arg, str)) {
					return false;
				}
				break;

			case DOPRINT_CUSTOM_MODE_XML:
				if (!doprint_custom_str_xml_escaped(write_func, write_arg, str)) {
					return false;
				}
				break;

			default:
				if (!doprint_custom_str(write_func, write_arg, str)) {
					return false;
				}
				break;
			}

			continue;
		}

		DEBUG_ASSERT(0, "invalid element %s", element_str);
		return false;
	}
}
