/*
 * ./src/web/json_parser.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("json_parser");

static json_parser_error_t json_parser_parse_estop(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_start(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_or_open(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_or_open_or_close(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_str(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_colon(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value_str(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value_unquoted(struct json_parser_t *xpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_close_or_comma(struct json_parser_t *xpi, struct netbuf *nb);

struct json_parser_t *json_parser_ref(struct json_parser_t *xpi)
{
	xpi->refs++;
	return xpi;
}

ref_t json_parser_deref(struct json_parser_t *xpi)
{
	xpi->refs--;
	if (xpi->refs != 0) {
		return xpi->refs;
	}

	if (xpi->partial_nb) {
		netbuf_free(xpi->partial_nb);
	}

	netbuf_free(xpi->output_nb);
	heap_free(xpi);
	return 0;
}

static void json_parser_output_clear(struct json_parser_t *xpi)
{
	netbuf_reset(xpi->output_nb);
}

static bool json_parser_output_char(struct json_parser_t *xpi, uint16_t c)
{
	if (netbuf_get_extent(xpi->output_nb) >= NETBUF_MAX_LENGTH) {
		DEBUG_ERROR("overlength");
		return false;
	}

	if (c <= 0x007F) {
		if (!netbuf_fwd_make_space(xpi->output_nb, 1)) {
			return false;
		}

		netbuf_fwd_write_u8(xpi->output_nb, (uint8_t)c);
		return true;
	}

	if (c <= 0x07FF) {
		if (!netbuf_fwd_make_space(xpi->output_nb, 2)) {
			return false;
		}

		netbuf_fwd_write_u8(xpi->output_nb, 0xC0 | (c >> 6));
		netbuf_fwd_write_u8(xpi->output_nb, 0x80 | ((c >> 0) & 0x003F));
		return true;
	}

	if (!netbuf_fwd_make_space(xpi->output_nb, 3)) {
		return false;
	}

	netbuf_fwd_write_u8(xpi->output_nb, 0xE0 | (c >> 12));
	netbuf_fwd_write_u8(xpi->output_nb, 0x80 | ((c >> 6) & 0x003F));
	netbuf_fwd_write_u8(xpi->output_nb, 0x80 | ((c >> 0) & 0x003F));
	return true;
}

static uint16_t json_parser_read_char_result(uint16_t c)
{
	if ((c >= 0x0020) && (c <= 0xD7FF)) {
		return c;
	}

	if ((c >= 0xE000) && (c <= 0xFFFD)) {
		return c;
	}

	if ((c == 0x0009) || (c == 0x000A) || (c == 0x000D)) {
		return c;
	}

	return (uint16_t)JSON_PARSER_ESTOP;
}

static uint16_t json_parser_read_char(struct json_parser_t *xpi, struct netbuf *nb)
{
	/*
	 * UTF-8
	 */
	if (!netbuf_fwd_check_space(nb, 1)) {
		return (uint16_t)JSON_PARSER_EMOREDATA;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	if ((c & 0x80) == 0x00) {
		return json_parser_read_char_result(c);
	}

	if ((c & 0xE0) == 0xC0) {
		uint16_t result = (uint16_t)(c & 0x1F) << 6;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 1);
			return (uint16_t)JSON_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)JSON_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 0;
		return json_parser_read_char_result(result);
	}

	if ((c & 0xF0) == 0xE0) {
		uint16_t result = (uint16_t)(c & 0x0F) << 12;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 1);
			return (uint16_t)JSON_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)JSON_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 6;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 2);
			return (uint16_t)JSON_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)JSON_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 0;
		return json_parser_read_char_result(result);
	}

	DEBUG_WARN("utf8 string corrupt");
	return (uint16_t)JSON_PARSER_ESTOP;
}

static uint16_t json_parser_read_escaped_char(struct json_parser_t *xpi, struct netbuf *nb)
{
	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case 't':
		return '\t';
	case 'r':
		return '\r';
	case 'n':
		return '\n';
	default:
		return c;
	}
}

static bool json_parser_is_valid_unquoted_char(uint16_t c)
{
	if ((c >= '0') && (c <= '9')) {
		return true;
	}

	if ((c >= 'A') && (c <= 'Z')) {
		return true;
	}
	if ((c >= 'a') && (c <= 'z')) {
		return true;
	}

	if (c == '-') {
		return true;
	}
	if (c == '.') {
		return true;
	}

	return false;
}

static bool json_parser_is_whitespace(uint16_t c)
{
	return (c == ' ') || (c == '\t') || (c == '\r') || (c == '\n');
}

static void json_parser_skip_whitespace(struct json_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t bookmark = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(xpi, nb);
		if (!json_parser_is_whitespace(c)) {
			netbuf_set_pos(nb, bookmark);
			return;
		}
	}
}

static json_parser_error_t json_parser_callback_internal_error(struct json_parser_t *xpi)
{
	DEBUG_WARN("%p json_parser_callback_internal_error: state %p", xpi, xpi->parse_func);
	json_parser_error_t ret = xpi->callback(xpi->callback_arg, JSON_PARSER_EVENT_INTERNAL_ERROR, NULL);
	DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);

	if (xpi->parse_func == json_parser_parse_start) { /* json_parser_reset called */
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(xpi);
	xpi->parse_func = json_parser_parse_estop;
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_callback_parse_error(struct json_parser_t *xpi)
{
	DEBUG_WARN("%p json_parser_callback_parse_error: state %p", xpi, xpi->parse_func);
	json_parser_error_t ret = xpi->callback(xpi->callback_arg, JSON_PARSER_EVENT_PARSE_ERROR, NULL);
	DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);

	if (xpi->parse_func == json_parser_parse_start) {
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(xpi);
	xpi->parse_func = json_parser_parse_estop;
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_callback_null_nb(struct json_parser_t *xpi, json_parser_event_t json_event, json_parser_parse_func_t next_parse_func)
{
	json_parser_error_t ret = xpi->callback(xpi->callback_arg, json_event, NULL);

	if (xpi->parse_func == json_parser_parse_start) { /* json_parser_reset called */
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(xpi);

	if (ret != JSON_PARSER_OK) {
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		xpi->parse_func = json_parser_parse_estop;
		return JSON_PARSER_ESTOP;
	}

	xpi->parse_func = next_parse_func;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_callback_with_nb(struct json_parser_t *xpi, json_parser_event_t json_event, json_parser_parse_func_t next_parse_func)
{
	/* Ensure netbuf always has memory allocated. */
	if (!netbuf_fwd_make_space(xpi->output_nb, 0)) {
		DEBUG_ERROR("out of memory");
		return json_parser_callback_internal_error(xpi);
	}

	netbuf_set_pos_to_start(xpi->output_nb);
	json_parser_error_t ret = xpi->callback(xpi->callback_arg, json_event, xpi->output_nb);

	if (xpi->parse_func == json_parser_parse_start) { /* json_parser_reset called */
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(xpi);

	if (ret != JSON_PARSER_OK) {
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		xpi->parse_func = json_parser_parse_estop;
		return JSON_PARSER_ESTOP;
	}

	xpi->parse_func = next_parse_func;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_emoredata(struct netbuf *nb, addr_t start_bookmark)
{
	netbuf_set_start(nb, start_bookmark);
	return JSON_PARSER_EMOREDATA;
}

static json_parser_error_t json_parser_parse_estop(struct json_parser_t *xpi, struct netbuf *nb)
{
	DEBUG_WARN("%p recv called after estop", xpi);
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_parse_start(struct json_parser_t *xpi, struct netbuf *nb)
{
	xpi->parse_func = json_parser_parse_value;
	return json_parser_parse_value(xpi, nb);
}

static json_parser_error_t json_parser_parse_name_or_open(struct json_parser_t *xpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(xpi);

	case '{':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_OBJECT_START, json_parser_parse_name_or_open_or_close);

	case '[':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ARRAY_START, json_parser_parse_name_or_open_or_close);

	case '\"':
		xpi->parse_func = json_parser_parse_name_str;
		return json_parser_parse_name_str(xpi, nb);

	default:
		return json_parser_callback_parse_error(xpi);
	}
}

static json_parser_error_t json_parser_parse_name_or_open_or_close(struct json_parser_t *xpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(xpi);

	case '{':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_OBJECT_START, json_parser_parse_name_or_open_or_close);

	case '}':
		return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

	case '[':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ARRAY_START, json_parser_parse_name_or_open_or_close);

	case ']':
		return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

	case '\"':
		xpi->parse_func = json_parser_parse_name_str;
		return json_parser_parse_name_str(xpi, nb);

	default:
		return json_parser_callback_parse_error(xpi);
	}
}

static json_parser_error_t json_parser_parse_name_str(struct json_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(xpi, nb);
		switch (c) {
		case JSON_PARSER_EMOREDATA:
			return json_parser_emoredata(nb, emoredata_start);

		case JSON_PARSER_ESTOP:
			return json_parser_callback_parse_error(xpi);

		case '\"':
			xpi->parse_func = json_parser_parse_colon;
			return json_parser_parse_colon(xpi, nb);

		case '\\':
			c = json_parser_read_escaped_char(xpi, nb);
			if (c == JSON_PARSER_EMOREDATA) {
				return json_parser_emoredata(nb, emoredata_start);
			}
			if (c == JSON_PARSER_ESTOP) {
				return json_parser_callback_parse_error(xpi);
			}
			break;

		default:
			break;
		}

		if (!json_parser_output_char(xpi, c)) {
			return json_parser_callback_internal_error(xpi);
		}
	}
}

static json_parser_error_t json_parser_parse_colon(struct json_parser_t *xpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(xpi);

	case ':':
		xpi->parse_func = json_parser_parse_value;
		return json_parser_parse_value(xpi, nb);

	default:
		return json_parser_callback_parse_error(xpi);
	}

}

static json_parser_error_t json_parser_parse_value(struct json_parser_t *xpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	json_parser_error_t ret;
	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(xpi);

	case '{':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_OBJECT_START, json_parser_parse_name_or_open_or_close);

	case '[':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ARRAY_START, json_parser_parse_name_or_open_or_close);

	case '\"':
		return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ELEMENT_NAME, json_parser_parse_value_str);

	default:
		if (!json_parser_is_valid_unquoted_char(c)) {
			return json_parser_callback_parse_error(xpi);
		}

		ret = json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ELEMENT_NAME, json_parser_parse_value_unquoted);
		if (ret != JSON_PARSER_OK) {
			return ret;
		}

		if (!json_parser_output_char(xpi, c)) {
			return json_parser_callback_internal_error(xpi);
		}

		return JSON_PARSER_OK;
	}
}

static json_parser_error_t json_parser_parse_value_str(struct json_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(xpi, nb);
		switch (c) {
		case JSON_PARSER_EMOREDATA:
			return json_parser_emoredata(nb, emoredata_start);

		case JSON_PARSER_ESTOP:
			c = '?'; /* Treat invalid characters inside a quoted string value as non-fatal error. */
			break;

		case '\"':
			return json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ELEMENT_VALUE_STR, json_parser_parse_close_or_comma);

		case '\\':
			c = json_parser_read_escaped_char(xpi, nb);
			if (c == JSON_PARSER_EMOREDATA) {
				return json_parser_emoredata(nb, emoredata_start);
			}
			if (c == JSON_PARSER_ESTOP) {
				c = '?'; /* Treat invalid characters inside a quoted string value as non-fatal error. */
			}
			break;

		default:
			break;
		}

		if (!json_parser_output_char(xpi, c)) {
			return json_parser_callback_internal_error(xpi);
		}
	}
}

static json_parser_error_t json_parser_parse_value_unquoted(struct json_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(xpi, nb);
		if (c == JSON_PARSER_EMOREDATA) {
			return json_parser_emoredata(nb, emoredata_start);
		}
		if (c == JSON_PARSER_ESTOP) {
			return json_parser_callback_parse_error(xpi);
		}

		if (!json_parser_is_valid_unquoted_char(c)) {
			json_parser_error_t ret = json_parser_callback_with_nb(xpi, JSON_PARSER_EVENT_ELEMENT_VALUE_UNQUOTED, json_parser_parse_close_or_comma);
			if (ret != JSON_PARSER_OK) {
				return ret;
			}

			switch (c) {
			case '}':
				return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

			case ']':
				return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

			case ',':
				xpi->parse_func = json_parser_parse_name_or_open;
				return JSON_PARSER_OK;

			default:
				if (!json_parser_is_whitespace(c)) {
					return json_parser_callback_parse_error(xpi);
				}

				xpi->parse_func = json_parser_parse_close_or_comma;
				return JSON_PARSER_OK;
			}
		}

		if (!json_parser_output_char(xpi, c)) {
			return json_parser_callback_internal_error(xpi);
		}
	}
}

static json_parser_error_t json_parser_parse_close_or_comma(struct json_parser_t *xpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(xpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(xpi);

	case '}':
		return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

	case ']':
		return json_parser_callback_null_nb(xpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

	case ',':
		xpi->parse_func = json_parser_parse_name_or_open;
		return json_parser_parse_name_or_open(xpi, nb);

	default:
		return json_parser_callback_parse_error(xpi);
	}
}

void json_parser_recv_netbuf(struct json_parser_t *xpi, struct netbuf *nb)
{
	/* Is this part of a partially received request or response? */
	if (xpi->partial_nb) {
		netbuf_set_pos_to_start(xpi->partial_nb);
		size_t prev_size = netbuf_get_remaining(xpi->partial_nb);

		if (prev_size + netbuf_get_remaining(nb) > NETBUF_MAX_LENGTH) {
			DEBUG_ERROR("%p too long", xpi);
			json_parser_ref(xpi);
			json_parser_callback_parse_error(xpi);
			json_parser_deref(xpi);
			return;
		}

		if (!netbuf_rev_make_space(nb, prev_size)) {
			DEBUG_ERROR("out of memory");
			json_parser_ref(xpi);
			json_parser_callback_internal_error(xpi);
			json_parser_deref(xpi);
			return;
		}

		netbuf_rev_copy(nb, xpi->partial_nb, prev_size);

		netbuf_free(xpi->partial_nb);
		xpi->partial_nb = NULL;
	}

	json_parser_error_t ret;
	while (1) {
		DEBUG_TRACE("%p state = %p length = %u", xpi, xpi->parse_func, netbuf_get_remaining(nb));

		json_parser_ref(xpi);
		ret = xpi->parse_func(xpi, nb);
		if (json_parser_deref(xpi) <= 0) {
			return;
		}

		if (ret != JSON_PARSER_OK) {
			break;
		}

		if (netbuf_get_remaining(nb) == 0) {
			break;
		}
	}

	if (ret == JSON_PARSER_EMOREDATA) {
		if (netbuf_get_extent(nb) == 0) {
			return;
		}

		xpi->partial_nb = netbuf_alloc_and_steal(nb);
		if (!xpi->partial_nb) {
			DEBUG_ERROR("out of memory");
			json_parser_ref(xpi);
			json_parser_callback_internal_error(xpi);
			json_parser_deref(xpi);
			return;
		}
	}
}

void json_parser_recv_str(struct json_parser_t *xpi, const char *str, size_t length)
{
	if (length == 0) {
		length = strlen(str);
	}

	struct netbuf *nb = netbuf_alloc_with_rev_space(length);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		json_parser_callback_internal_error(xpi);
		return;
	}

	netbuf_rev_write(nb, str, length);
	json_parser_recv_netbuf(xpi, nb);
	netbuf_free(nb);
}

void json_parser_reset(struct json_parser_t *xpi)
{
	if (xpi->partial_nb) {
		netbuf_free(xpi->partial_nb);
		xpi->partial_nb = NULL;
	}

	json_parser_output_clear(xpi);
	xpi->parse_func = json_parser_parse_start;
}

struct json_parser_t *json_parser_alloc(json_parser_callback_t callback, void *callback_arg)
{
	struct json_parser_t *xpi = (struct json_parser_t *)heap_alloc_and_zero(sizeof(struct json_parser_t), PKG_OS, MEM_TYPE_OS_JSON_PARSER);
	if (!xpi) {
		return NULL;
	}

	xpi->output_nb = netbuf_alloc();
	if (!xpi->output_nb) {
		DEBUG_ERROR("out of memory");
		heap_free(xpi);
		return NULL;
	}

	xpi->refs = 1;
	xpi->callback = callback;
	xpi->callback_arg = callback_arg;
	json_parser_reset(xpi);

	return xpi;
}
