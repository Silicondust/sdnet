/*
 * netbuf_sscanf.c
 *
 * Copyright © 2008-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("netbuf_sscanf");

static bool netbuf_vsscanf_parse_hex_char(struct netbuf *nb, uint32_t *pval)
{
	if (!netbuf_fwd_check_space(nb, 1)) {
		return false;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
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

	netbuf_retreat_pos(nb, 1);
	return false;
}

static bool netbuf_vsscanf_parse_dec_char(struct netbuf *nb, uint32_t *pval)
{
	if (!netbuf_fwd_check_space(nb, 1)) {
		return false;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	if ((c >= '0') && (c <= '9')) {
		*pval = c - '0';
		return true;
	}

	netbuf_retreat_pos(nb, 1);
	return false;
}

static bool netbuf_vsscanf_parse_u32_hex(struct netbuf *nb, uint32_t *pval)
{
	uint32_t val;
	if (!netbuf_vsscanf_parse_hex_char(nb, &val)) {
		return false;
	}
	*pval = val;

	while (1) {
		if (!netbuf_vsscanf_parse_hex_char(nb, &val)) {
			return true;
		}
		*pval = (*pval << 4) | val;
	}
}

static bool netbuf_vsscanf_parse_u32(struct netbuf *nb, uint32_t *pval)
{
	/* First char must be 0-9 */
	uint32_t val;
	if (!netbuf_vsscanf_parse_dec_char(nb, &val)) {
		return false;
	}
	*pval = val;

	/* Check for hex. */
	if (val == 0) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			return true;
		}
		char c = (char)netbuf_fwd_read_u8(nb);
		if (c == 'x') {
			return netbuf_vsscanf_parse_u32_hex(nb, pval);
		}
		netbuf_retreat_pos(nb, 1);
	}

	/* Remainder of decimal digits. */
	while (1) {
		if (!netbuf_vsscanf_parse_dec_char(nb, &val)) {
			return true;
		}

		*pval = (*pval * 10) + val;
	}
}

static bool netbuf_vsscanf_parse_ipv4_addr(struct netbuf *nb, ipv4_addr_t *pipaddr)
{
	*pipaddr = 0;

	int shift = 24;
	while (1) {
		uint32_t val;
		if (!netbuf_vsscanf_parse_u32(nb, &val)) {
			return false;
		}
		if (val > 255) {
			return false;
		}
		*pipaddr |= val << shift;

		if (shift == 0) {
			return true;
		}

		if (!netbuf_fwd_check_space(nb, 1)) {
			return false;
		}
		uint8_t c = netbuf_fwd_read_u8(nb);
		if (c != '.') {
			return false;
		}

		shift -= 8;
	}
}

static bool netbuf_vsscanf_parse_ip_addr(struct netbuf *nb, ip_addr_t *ipaddr)
{
#if defined(IPV6_SUPPORT)
	if (!netbuf_fwd_check_space(nb, 1)) {
		return false;
	}

	char c = (char)netbuf_fwd_read_u8(nb);
	bool framed_ipv6 = (c == '[');

	if (!framed_ipv6) {
		netbuf_retreat_pos(nb, 1);
		addr_t bookmark = netbuf_get_pos(nb);

		while (1) {
			if (!netbuf_fwd_check_space(nb, 1)) {
				return false;
			}

			char c = (char)netbuf_fwd_read_u8(nb);

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
				netbuf_set_pos(nb, bookmark);

				ipv4_addr_t ipv4;
				if (!netbuf_vsscanf_parse_ipv4_addr(nb, &ipv4)) {
					return false;
				}

				ip_addr_set_ipv4(ipaddr, ipv4);
				return true;
			}

			return false;
		}

		netbuf_set_pos(nb, bookmark);
	}

	uint16_t words[8];
	int word_index = 0;
	int double_colon_index = -1;

	if (netbuf_fwd_check_space(nb, 2)) {
		char c1 = (char)netbuf_fwd_read_u8(nb);
		char c2 = (char)netbuf_fwd_read_u8(nb);
		if ((c1 == ':') && (c2 == ':')) {
			double_colon_index = word_index;

			if (!netbuf_fwd_check_space(nb, 1)) {
				if (!framed_ipv6) {
					ip_addr_set_zero(ipaddr);
					return true;
				}
				return false;
			}

			char c = (char)netbuf_fwd_read_u8(nb);

			if ((c == ']') && framed_ipv6) {
				ip_addr_set_zero(ipaddr);
				return true;
			}

			netbuf_retreat_pos(nb, 1);
		} else {
			netbuf_retreat_pos(nb, 2);
		}
	}

	while (1) {
		uint32_t val;
		if (!netbuf_vsscanf_parse_u32_hex(nb, &val)) {
			return false;
		}

		if (val > 0xFFFF) {
			return false;
		}

		words[word_index++] = val;

		if (!netbuf_fwd_check_space(nb, 1)) {
			if (!framed_ipv6 && ((word_index == 8) || (double_colon_index >= 0))) {
				break;
			}
			return false;
		}

		char c = (char)netbuf_fwd_read_u8(nb);

		if ((c == ']') && framed_ipv6 && ((word_index == 8) || (double_colon_index >= 0))) {
			break;
		}

		if (word_index >= 8) {
			return false;
		}
		if (c != ':') {
			return false;
		}

		if (!netbuf_fwd_check_space(nb, 1)) {
			return false;
		}

		c = (char)netbuf_fwd_read_u8(nb);

		if (c == ':') {
			if (double_colon_index >= 0) {
				return false;
			}

			double_colon_index = word_index;

			if (!netbuf_fwd_check_space(nb, 1)) {
				if (!framed_ipv6) {
					break;
				}
				return false;
			}

			char c = (char)netbuf_fwd_read_u8(nb);

			if ((c == ']') && framed_ipv6) {
				break;
			}
		}

		netbuf_retreat_pos(nb, 1);
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
	return netbuf_vsscanf_parse_ipv4_addr(nb, &ipaddr->ipv4);
#endif
}

static bool netbuf_vsscanf_parse_str(struct netbuf *nb, char *pstr, size_t size, char terminating)
{
	if (terminating == 0) {
		terminating = ' ';
	}

	bool escape = false;
	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			*pstr = 0;
			return (terminating == ' ');
		}

		char c = (char)netbuf_fwd_read_u8(nb);
		if (c == 0) {
			*pstr = 0;
			return (terminating == ' ');
		}

		if (escape) {
			escape = false;
		} else {
			if (c == terminating) {
				netbuf_retreat_pos(nb, 1);
				*pstr = 0;
				return true;
			}
			if (c == '\\') {
				escape = true;
				continue;
			}
		}

		if (size <= 1) {
			continue;
		}

		*pstr++ = c;
		size--;
	}
}

bool netbuf_vsscanf(struct netbuf *nb, const char *fmt, va_list ap)
{
	addr_t bookmark = netbuf_get_pos(nb);

	while (1) {
		char fmtc = *fmt++;
		if (fmtc == 0) {
			return true;
		}

		if (fmtc != '%') {
			if (!netbuf_fwd_check_space(nb, 1)) {
				goto error;
			}
			char nbc = (char)netbuf_fwd_read_u8(nb);
			if (nbc != fmtc) {
				goto error;
			}
			continue;
		}

		fmtc = *fmt++;
		if (fmtc == 0) {
			DEBUG_ERROR("fmt string ends in %");
			goto error;
		}

		if (fmtc == 'u') {
			uint32_t *pval = va_arg(ap, uint32_t *);
			if (!netbuf_vsscanf_parse_u32(nb, pval)) {
				goto error;
			}
			continue;
		}

		if (fmtc == 'v') {
			ipv4_addr_t *pval = va_arg(ap, ipv4_addr_t *);
			if (!netbuf_vsscanf_parse_ipv4_addr(nb, pval)) {
				goto error;
			}
			continue;
		}

		if (fmtc == 'V') {
			ip_addr_t *pval = va_arg(ap, ip_addr_t *);
			if (!netbuf_vsscanf_parse_ip_addr(nb, pval)) {
				goto error;
			}
			continue;
		}

		if (fmtc == 's') {
			char terminating = *fmt;
			char *pstr = va_arg(ap, char *);
			size_t size = va_arg(ap, size_t);
			if (!netbuf_vsscanf_parse_str(nb, pstr, size, terminating)) {
				goto error;
			}
			continue;
		}

		DEBUG_ERROR("unknown fmt %%%c", fmtc);
		goto error;
	}

error:
	netbuf_set_pos(nb, bookmark);
	return false;
}

bool netbuf_sscanf(struct netbuf *nb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool ret = netbuf_vsscanf(nb, fmt, ap);
	va_end(ap);
	return ret;
}

time64_t netbuf_sscanf_http_date(struct netbuf *nb)
{
	uint32_t day, year, hour, minute, second;
	char day_of_week_str[8], month_str[4];

	/* Mon, 09 Dec 2013 23:24:04 GMT */
	if (!netbuf_sscanf(nb, "%s %u %s %u %u:%u:%u", day_of_week_str, sizeof(day_of_week_str), &day, month_str, sizeof(month_str), &year, &hour, &minute, &second)) {
		DEBUG_WARN("invalid date format");
		return 0;
	}

	uint32_t month;
	const char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	for (month = 0; month < 12; month++) {
		if (strcasecmp(months[month], month_str) == 0) {
			break;
		}
	}
	if (month >= 12) {
		DEBUG_WARN("invalid month %s", month_str);
		return 0;
	}

	struct tm tm_struct;
	memset(&tm_struct, 0, sizeof(tm_struct));
	tm_struct.tm_sec = second;
	tm_struct.tm_min = minute;
	tm_struct.tm_hour = hour;
	tm_struct.tm_mday = day;
	tm_struct.tm_mon = month;
	tm_struct.tm_year = year - 1900;

	return unix_tm_to_time(&tm_struct);
}

bool netbuf_sscanf_next_option(struct netbuf *nb)
{
	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			return false;
		}

		char nbc = (char)netbuf_fwd_read_u8(nb);
		if (nbc == ' ') {
			break;
		}
	}

	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			return false;
		}

		char nbc = (char)netbuf_fwd_read_u8(nb);
		if (nbc != ' ') {
			break;
		}
	}

	netbuf_retreat_pos(nb, 1);
	return true;
}
