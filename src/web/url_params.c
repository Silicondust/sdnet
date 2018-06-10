/*
 * url_params.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("url_params");

static void url_params_get_value_result(struct netbuf *params_nb, char *value, size_t value_buffer_size)
{
	while (1) {
		if (value_buffer_size < 2) {
			*value = 0;
			return;
		}

		if (!netbuf_fwd_check_space(params_nb, 1)) {
			*value = 0;
			return;
		}

		char c = (char)netbuf_fwd_read_u8(params_nb);
		if (c == '&') {
			*value = 0;
			return;
		}

		if ((c == '%') && netbuf_fwd_check_space(params_nb, 2)) {
			char str[3];
			str[0] = (char)netbuf_fwd_read_u8(params_nb);
			str[1] = (char)netbuf_fwd_read_u8(params_nb);
			str[2] = 0;
			
			char *end;
			unsigned long val = strtoul(str, &end, 16);

			if (*end == 0) {
				c = (char)(unsigned char)val;
			} else {
				netbuf_retreat_pos(params_nb, 2);
			}
		}

		*value++ = c;
		value_buffer_size--;
	}
}

bool url_params_get_value(struct netbuf *params_nb, const char *name, char *value, size_t value_buffer_size)
{
	size_t name_len = strlen(name);
	netbuf_set_pos_to_start(params_nb);

	while (1) {
		if (netbuf_fwd_strncmp(params_nb, name, name_len) == 0) {
			netbuf_advance_pos(params_nb, name_len);

			if (netbuf_get_remaining(params_nb) == 0) {
				if (value_buffer_size > 0) {
					*value = 0;
				}
				return true;
			}

			char c = (char)netbuf_fwd_read_u8(params_nb);

			if (c == '&') {
				if (value_buffer_size > 0) {
					*value = 0;
				}
				return true;
			}

			if (c == '=') {
				if (value_buffer_size > 0) {
					url_params_get_value_result(params_nb, value, value_buffer_size);
				}
				return true;
			}
		}

		addr_t next = netbuf_fwd_strchr(params_nb, '&');
		if (!next) {
			return false;
		}

		netbuf_set_pos(params_nb, next + 1);
	}
}

bool url_params_get_value_u32(struct netbuf *params_nb, const char *name, uint32_t *pvalue, int base)
{
	char str[32];
	if (!url_params_get_value(params_nb, name, str, sizeof(str))) {
		return false;
	}

	char *end;
	uint32_t value = (uint32_t)strtoul(str, &end, base);
	if (*end) {
		return false;
	}

	*pvalue = value;
	return true;
}

bool url_params_get_value_u64(struct netbuf *params_nb, const char *name, uint64_t *pvalue, int base)
{
	char str[32];
	if (!url_params_get_value(params_nb, name, str, sizeof(str))) {
		return false;
	}

	char *end;
	uint64_t value = (uint64_t)strtoull(str, &end, base);
	if (*end) {
		return false;
	}

	*pvalue = value;
	return true;
}
