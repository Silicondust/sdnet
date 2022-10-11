/*
 * sscanf_custom.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("sscanf_custom");

static bool vsscanf_custom_parse_hex_char(char c, uint32_t *pval)
{
	if ((c >= '0') && (c <= '9')) {
		*pval = c - '0';
		return true;
	}
	if ((c >= 'A') && (c <= 'F')) {
		*pval = c - 'A' + 10;
		return true;
	}
	if ((c >= 'a') && (c <= 'f')) {
		*pval = c - 'a' + 10;
		return true;
	}

	return false;
}

static bool vsscanf_custom_parse_dec_char(char c, uint32_t *pval)
{
	if ((c >= '0') && (c <= '9')) {
		*pval = c - '0';
		return true;
	}

	return false;
}

static bool vsscanf_custom_parse_u32_hex(const char **pstr, uint32_t *pval)
{
	const char *str = *pstr;

	uint32_t val;
	if (!vsscanf_custom_parse_hex_char(*str, &val)) {
		return false;
	}
	*pval = val;
	str++;

	while (1) {
		if (!vsscanf_custom_parse_hex_char(*str, &val)) {
			*pstr = str;
			return true;
		}
		*pval = (*pval << 4) | val;
		str++;
	}
}

static bool vsscanf_custom_parse_u32(const char **pstr, uint32_t *pval)
{
	const char *str = *pstr;

	/* First char must be 0-9 */
	uint32_t val;
	if (!vsscanf_custom_parse_dec_char(*str, &val)) {
		return false;
	}
	*pval = val;
	str++;

	/* Check for hex. */
	if ((val == 0) && (*str == 'x')) {
		*pstr = str + 1;
		return vsscanf_custom_parse_u32_hex(pstr, pval);
	}

	/* Remainder of decimal digits. */
	while (1) {
		if (!vsscanf_custom_parse_dec_char(*str, &val)) {
			*pstr = str;
			return true;
		}

		*pval = (*pval * 10) + val;
		str++;
	}
}

static bool vsscanf_custom_parse_ipv4_addr(const char **pstr, ipv4_addr_t *pipaddr)
{
	const char *str = *pstr;
	*pipaddr = 0;

	int shift = 24;
	while (1) {
		uint32_t val;
		if (!vsscanf_custom_parse_u32(&str, &val)) {
			return false;
		}

		if (val > 255) {
			return false;
		}

		*pipaddr |= val << shift;

		if (shift == 0) {
			*pstr = str;
			return true;
		}

		if (*str++ != '.') {
			return false;
		}

		shift -= 8;
	}
}

static bool vsscanf_custom_parse_ip_addr(const char **pstr, ip_addr_t *ipaddr)
{
#if defined(IPV6_SUPPORT)
	const char *str = *pstr;
	bool framed_ipv6 = (*str++ == '[');

	if (!framed_ipv6) {
		str--;

		while (1) {
			char c = *str++;
			if (c == 0) {
				return false;
			}

			if ((c >= '0') && (c <= '9')) {
				continue;
			}

			if ((c >= 'A') && (c <= 'F')) {
				break;
			}
			if ((c >= 'a') && (c <= 'f')) {
				break;
			}
			if (c == ':') {
				break;
			}

			if (c == '.') {
				ipv4_addr_t ipv4;
				if (!vsscanf_custom_parse_ipv4_addr(pstr, &ipv4)) {
					return false;
				}

				ip_addr_set_ipv4(ipaddr, ipv4);
				return true;
			}

			return false;
		}

		str = *pstr;
	}

	uint16_t words[8];
	int word_index = 0;
	int double_colon_index = -1;

	if ((str[0] == ':') && (str[1] == ':')) {
		double_colon_index = word_index;
		str += 2;

		char c = *str++;

		if ((c == 0) && !framed_ipv6) {
			*pstr = str - 1;
			ip_addr_set_zero(ipaddr);
			return true;
		}
		if ((c == ']') && framed_ipv6) {
			*pstr = str;
			ip_addr_set_zero(ipaddr);
			return true;
		}

		str--;
	}

	while (1) {
		uint32_t val;
		if (!vsscanf_custom_parse_u32_hex(&str, &val)) {
			return false;
		}

		if (val > 0xFFFF) {
			return false;
		}

		words[word_index++] = val;

		char c = *str++;

		if ((c == 0) && !framed_ipv6 && ((word_index == 8) || (double_colon_index >= 0))) {
			*pstr = str - 1;
			break;
		}
		if ((c == ']') && framed_ipv6 && ((word_index == 8) || (double_colon_index >= 0))) {
			*pstr = str;
			break;
		}

		if (word_index >= 8) {
			return false;
		}
		if (c != ':') {
			return false;
		}

		c = *str++;

		if (c == ':') {
			if (double_colon_index >= 0) {
				return false;
			}

			double_colon_index = word_index;

			c = *str++;

			if ((c == 0) && !framed_ipv6) {
				*pstr = str - 1;
				break;
			}
			if ((c == ']') && framed_ipv6) {
				*pstr = str;
				break;
			}
		}

		str--;
	}

	if (double_colon_index >= 0) {
		int dest_index = 7;
		word_index--;

		while (word_index >= double_colon_index) {
			words[dest_index--] = words[word_index--];
		}
		while (dest_index >= double_colon_index) {
			words[dest_index--] = 0;
		}
	}

	ipaddr->high = (uint64_t)words[0] << 48;
	ipaddr->high |= (uint64_t)words[1] << 32;
	ipaddr->high |= (uint64_t)words[2] << 16;
	ipaddr->high |= (uint64_t)words[3] << 0;
	ipaddr->low = (uint64_t)words[4] << 48;
	ipaddr->low |= (uint64_t)words[5] << 32;
	ipaddr->low |= (uint64_t)words[6] << 16;
	ipaddr->low |= (uint64_t)words[7] << 0;
	return true;
#else
	return vsscanf_custom_parse_ipv4_addr(pstr, &ipaddr->ipv4);
#endif
}

static bool vsscanf_custom_parse_str(const char **pstr, char *pout, size_t size, char terminating)
{
	const char *str = *pstr;

	if (terminating == 0) {
		terminating = ' ';
	}

	bool escape = false;
	while (1) {
		if (*str == 0) {
			if (terminating != ' ') {
				return false;
			}
			*pout = 0;
			*pstr = str;
			return true;
		}

		if (escape) {
			escape = false;
		} else {
			if (*str == terminating) {
				*pout = 0;
				*pstr = str;
				return true;
			}
			if (*str == '\\') {
				escape = true;
				str++;
				continue;
			}
		}

		if (size <= 1) {
			str++;
			continue;
		}

		*pout++ = *str++;
		size--;
	}
}

bool vsscanf_custom_with_advance(const char **pstr, const char *fmt, va_list ap)
{
	const char *str = *pstr;

	while (1) {
		char fmtc = *fmt++;
		if (fmtc == 0) {
			*pstr = str;
			return true;
		}

		if (fmtc != '%') {
			if (*str++ != fmtc) {
				return false;
			}
			continue;
		}

		fmtc = *fmt++;
		if (fmtc == 0) {
			DEBUG_ERROR("fmt string ends in %");
			return false;
		}

		if (fmtc == 'u') {
			uint32_t *pval = va_arg(ap, uint32_t *);
			if (!vsscanf_custom_parse_u32(&str, pval)) {
				return false;
			}
			continue;
		}

		if (fmtc == 'x') {
			uint32_t *pval = va_arg(ap, uint32_t *);
			if (!vsscanf_custom_parse_u32_hex(&str, pval)) {
				return false;
			}
			continue;
		}

		if (fmtc == 'v') {
			ipv4_addr_t *pval = va_arg(ap, ipv4_addr_t *);
			if (!vsscanf_custom_parse_ipv4_addr(&str, pval)) {
				return false;
			}
			continue;
		}

		if (fmtc == 'V') {
			ip_addr_t *pval = va_arg(ap, ip_addr_t *);
			if (!vsscanf_custom_parse_ip_addr(&str, pval)) {
				return false;
			}
			continue;
		}

		if (fmtc == 's') {
			char terminating = *fmt;
			char *pout = va_arg(ap, char *);
			size_t size = va_arg(ap, size_t);
			if (!vsscanf_custom_parse_str(&str, pout, size, terminating)) {
				return false;
			}
			continue;
		}

		DEBUG_ERROR("unknown fmt %%%c", fmtc);
		return false;
	}
}

bool sscanf_custom_with_advance(const char **pstr, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool result = vsscanf_custom_with_advance(pstr, fmt, ap);
	va_end(ap);
	return result;
}

bool vsscanf_custom(const char *str, const char *fmt, va_list ap)
{
	return vsscanf_custom_with_advance(&str, fmt, ap);
}

bool sscanf_custom(const char *str, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool result = vsscanf_custom_with_advance(&str, fmt, ap);
	va_end(ap);
	return result;
}
