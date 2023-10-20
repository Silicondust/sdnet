/*
 * json_parser.c
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

static json_parser_error_t json_parser_parse_estop(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_start(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_or_value(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_or_value_str(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_name_or_value_str_decider(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value_str(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_value_unquoted(struct json_parser_t *jpi, struct netbuf *nb);
static json_parser_error_t json_parser_parse_close_or_comma(struct json_parser_t *jpi, struct netbuf *nb);

struct json_parser_t *json_parser_ref(struct json_parser_t *jpi)
{
	jpi->refs++;
	return jpi;
}

ref_t json_parser_deref(struct json_parser_t *jpi)
{
	jpi->refs--;
	if (jpi->refs != 0) {
		return jpi->refs;
	}

	if (jpi->partial_nb) {
		netbuf_free(jpi->partial_nb);
	}

	netbuf_free(jpi->name_nb);
	netbuf_free(jpi->value_nb);
	heap_free(jpi);
	return 0;
}

static void json_parser_output_clear(struct json_parser_t *jpi)
{
	netbuf_reset(jpi->name_nb);
	netbuf_reset(jpi->value_nb);
}

static void json_parser_output_swap_name_value(struct json_parser_t *jpi)
{
	struct netbuf *name_nb = jpi->value_nb;
	struct netbuf *value_nb = jpi->name_nb;
	jpi->name_nb = name_nb;
	jpi->value_nb = value_nb;
}

static bool json_parser_output_char(struct json_parser_t *jpi, uint16_t c)
{
	if (netbuf_get_extent(jpi->value_nb) >= NETBUF_MAX_LENGTH) {
		DEBUG_ERROR("overlength");
		return false;
	}

	if (c <= 0x007F) {
		if (!netbuf_fwd_make_space(jpi->value_nb, 1)) {
			return false;
		}

		netbuf_fwd_write_u8(jpi->value_nb, (uint8_t)c);
		return true;
	}

	if (c <= 0x07FF) {
		if (!netbuf_fwd_make_space(jpi->value_nb, 2)) {
			return false;
		}

		netbuf_fwd_write_u8(jpi->value_nb, 0xC0 | (c >> 6));
		netbuf_fwd_write_u8(jpi->value_nb, 0x80 | ((c >> 0) & 0x003F));
		return true;
	}

	if (!netbuf_fwd_make_space(jpi->value_nb, 3)) {
		return false;
	}

	netbuf_fwd_write_u8(jpi->value_nb, 0xE0 | (c >> 12));
	netbuf_fwd_write_u8(jpi->value_nb, 0x80 | ((c >> 6) & 0x003F));
	netbuf_fwd_write_u8(jpi->value_nb, 0x80 | ((c >> 0) & 0x003F));
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

static uint16_t json_parser_read_char(struct json_parser_t *jpi, struct netbuf *nb)
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

static uint16_t json_parser_read_escaped_char(struct json_parser_t *jpi, struct netbuf *nb)
{
	uint16_t c = json_parser_read_char(jpi, nb);
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

static void json_parser_skip_whitespace(struct json_parser_t *jpi, struct netbuf *nb)
{
	while (1) {
		addr_t bookmark = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(jpi, nb);
		if (!json_parser_is_whitespace(c)) {
			netbuf_set_pos(nb, bookmark);
			return;
		}
	}
}

static json_parser_error_t json_parser_callback_internal_error(struct json_parser_t *jpi)
{
	DEBUG_WARN("%p json_parser_callback_internal_error: state %p", jpi, jpi->parse_func);
	json_parser_error_t ret = jpi->callback(jpi->callback_arg, JSON_PARSER_EVENT_INTERNAL_ERROR, NULL, NULL);
	DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", jpi, jpi->parse_func);

	if (jpi->parse_func == json_parser_parse_start) { /* json_parser_reset called */
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(jpi);
	jpi->parse_func = json_parser_parse_estop;
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_callback_parse_error(struct json_parser_t *jpi)
{
	DEBUG_WARN("%p json_parser_callback_parse_error: state %p", jpi, jpi->parse_func);
	json_parser_error_t ret = jpi->callback(jpi->callback_arg, JSON_PARSER_EVENT_PARSE_ERROR, NULL, NULL);
	DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", jpi, jpi->parse_func);

	if (jpi->parse_func == json_parser_parse_start) {
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(jpi);
	jpi->parse_func = json_parser_parse_estop;
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_callback_internal(struct json_parser_t *jpi, json_parser_event_t json_event, struct netbuf *name_nb, struct netbuf *value_nb, json_parser_parse_func_t next_parse_func)
{
	json_parser_error_t ret = jpi->callback(jpi->callback_arg, json_event, name_nb, value_nb);

	if (jpi->parse_func == json_parser_parse_start) { /* json_parser_reset called */
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", jpi, jpi->parse_func);
		return JSON_PARSER_ESTOP;
	}

	json_parser_output_clear(jpi);

	if (ret != JSON_PARSER_OK) {
		DEBUG_ASSERT(ret == JSON_PARSER_ESTOP, "%p unexpected return value from app: state %p", jpi, jpi->parse_func);
		jpi->parse_func = json_parser_parse_estop;
		return JSON_PARSER_ESTOP;
	}

	jpi->parse_func = next_parse_func;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_callback_basic(struct json_parser_t *jpi, json_parser_event_t json_event, json_parser_parse_func_t next_parse_func)
{
	return json_parser_callback_internal(jpi, json_event, NULL, NULL, next_parse_func);
}

static json_parser_error_t json_parser_callback_name(struct json_parser_t *jpi, json_parser_event_t json_event, json_parser_parse_func_t next_parse_func)
{
	/* Ensure netbuf always has memory allocated. */
	if (!netbuf_fwd_make_space(jpi->name_nb, 0)) {
		DEBUG_ERROR("out of memory");
		return json_parser_callback_internal_error(jpi);
	}

	netbuf_set_pos_to_start(jpi->name_nb);
	return json_parser_callback_internal(jpi, json_event, jpi->name_nb, NULL, next_parse_func);
}

static json_parser_error_t json_parser_callback_name_value(struct json_parser_t *jpi, json_parser_event_t json_event, json_parser_parse_func_t next_parse_func)
{
	/* Ensure netbuf always has memory allocated. */
	if (!netbuf_fwd_make_space(jpi->name_nb, 0)) {
		DEBUG_ERROR("out of memory");
		return json_parser_callback_internal_error(jpi);
	}

	if (!netbuf_fwd_make_space(jpi->value_nb, 0)) {
		DEBUG_ERROR("out of memory");
		return json_parser_callback_internal_error(jpi);
	}

	netbuf_set_pos_to_start(jpi->name_nb);
	netbuf_set_pos_to_start(jpi->value_nb);
	return json_parser_callback_internal(jpi, json_event, jpi->name_nb, jpi->value_nb, next_parse_func);
}

static json_parser_error_t json_parser_emoredata(struct netbuf *nb, addr_t start_bookmark)
{
	netbuf_set_start(nb, start_bookmark);
	return JSON_PARSER_EMOREDATA;
}

static json_parser_error_t json_parser_parse_estop(struct json_parser_t *jpi, struct netbuf *nb)
{
	DEBUG_WARN("%p recv called after estop", jpi);
	return JSON_PARSER_ESTOP;
}

static json_parser_error_t json_parser_parse_start(struct json_parser_t *jpi, struct netbuf *nb)
{
	jpi->parse_func = json_parser_parse_name_or_value;
	return json_parser_parse_name_or_value(jpi, nb);
}

static json_parser_error_t json_parser_parse_name_or_value(struct json_parser_t *jpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(jpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(jpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(jpi);

	case '{':
		DEBUG_ASSERT(netbuf_get_extent(jpi->name_nb) == 0, "name should be blank");
		return json_parser_callback_name(jpi, JSON_PARSER_EVENT_OBJECT_START, json_parser_parse_name_or_value);

	case '}':
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

	case '[':
		DEBUG_ASSERT(netbuf_get_extent(jpi->name_nb) == 0, "name should be blank");
		return json_parser_callback_name(jpi, JSON_PARSER_EVENT_ARRAY_START, json_parser_parse_name_or_value);

	case ']':
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

	case '"':
		jpi->parse_func = json_parser_parse_name_or_value_str;
		return json_parser_parse_name_or_value_str(jpi, nb);

	default:
		if (!json_parser_is_valid_unquoted_char(c)) {
			return json_parser_callback_parse_error(jpi);
		}

		if (!json_parser_output_char(jpi, c)) {
			return json_parser_callback_internal_error(jpi);
		}

		jpi->parse_func = json_parser_parse_value_unquoted;
		return json_parser_parse_value_unquoted(jpi, nb);
	}
}

static json_parser_error_t json_parser_parse_name_or_value_str(struct json_parser_t *jpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(jpi, nb);
		switch (c) {
		case JSON_PARSER_EMOREDATA:
			return json_parser_emoredata(nb, emoredata_start);

		case JSON_PARSER_ESTOP:
			return json_parser_callback_parse_error(jpi);

		case '"':
			jpi->parse_func = json_parser_parse_name_or_value_str_decider;
			return json_parser_parse_name_or_value_str_decider(jpi, nb);

		case '\\':
			c = json_parser_read_escaped_char(jpi, nb);
			if (c == JSON_PARSER_EMOREDATA) {
				return json_parser_emoredata(nb, emoredata_start);
			}
			if (c == JSON_PARSER_ESTOP) {
				return json_parser_callback_parse_error(jpi);
			}
			break;

		default:
			break;
		}

		if (!json_parser_output_char(jpi, c)) {
			return json_parser_callback_internal_error(jpi);
		}
	}
}

static json_parser_error_t json_parser_parse_name_or_value_str_decider(struct json_parser_t *jpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(jpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	json_parser_error_t ret;
	uint16_t c = json_parser_read_char(jpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(jpi);

	case ':':
		json_parser_output_swap_name_value(jpi); /* string was written to value - move to being the name */
		jpi->parse_func = json_parser_parse_value;
		return json_parser_parse_value(jpi, nb);

	case ',':
		DEBUG_ASSERT(netbuf_get_extent(jpi->name_nb) == 0, "name should be blank");
		return json_parser_callback_name_value(jpi, JSON_PARSER_EVENT_ELEMENT_STR, json_parser_parse_name_or_value);

	case '}':
		DEBUG_ASSERT(netbuf_get_extent(jpi->name_nb) == 0, "name should be blank");
		ret = json_parser_callback_name_value(jpi, JSON_PARSER_EVENT_ELEMENT_STR, json_parser_parse_close_or_comma);
		if (ret != JSON_PARSER_OK) {
			return ret;
		}
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

	case ']':
		DEBUG_ASSERT(netbuf_get_extent(jpi->name_nb) == 0, "name should be blank");
		ret = json_parser_callback_name_value(jpi, JSON_PARSER_EVENT_ELEMENT_STR, json_parser_parse_close_or_comma);
		if (ret != JSON_PARSER_OK) {
			return ret;
		}
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

	default:
		return json_parser_callback_parse_error(jpi);
	}
}

static json_parser_error_t json_parser_parse_value(struct json_parser_t *jpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(jpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(jpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(jpi);

	case '{':
		return json_parser_callback_name(jpi, JSON_PARSER_EVENT_OBJECT_START, json_parser_parse_name_or_value);

	case '[':
		return json_parser_callback_name(jpi, JSON_PARSER_EVENT_ARRAY_START, json_parser_parse_name_or_value);

	case '"':
		jpi->parse_func = json_parser_parse_value_str;
		return json_parser_parse_value_str(jpi, nb);

	default:
		if (!json_parser_is_valid_unquoted_char(c)) {
			return json_parser_callback_parse_error(jpi);
		}

		if (!json_parser_output_char(jpi, c)) {
			return json_parser_callback_internal_error(jpi);
		}

		jpi->parse_func = json_parser_parse_value_unquoted;
		return json_parser_parse_value_unquoted(jpi, nb);
	}
}

static json_parser_error_t json_parser_parse_value_str(struct json_parser_t *jpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(jpi, nb);
		switch (c) {
		case JSON_PARSER_EMOREDATA:
			return json_parser_emoredata(nb, emoredata_start);

		case JSON_PARSER_ESTOP:
			c = '?'; /* Treat invalid characters inside a quoted string value as non-fatal error. */
			break;

		case '"':
			return json_parser_callback_name_value(jpi, JSON_PARSER_EVENT_ELEMENT_STR, json_parser_parse_close_or_comma);

		case '\\':
			c = json_parser_read_escaped_char(jpi, nb);
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

		if (!json_parser_output_char(jpi, c)) {
			return json_parser_callback_internal_error(jpi);
		}
	}
}

static json_parser_error_t json_parser_parse_value_unquoted(struct json_parser_t *jpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = json_parser_read_char(jpi, nb);
		if (c == JSON_PARSER_EMOREDATA) {
			return json_parser_emoredata(nb, emoredata_start);
		}
		if (c == JSON_PARSER_ESTOP) {
			return json_parser_callback_parse_error(jpi);
		}

		if (!json_parser_is_valid_unquoted_char(c)) {
			json_parser_error_t ret = json_parser_callback_name_value(jpi, JSON_PARSER_EVENT_ELEMENT_UNQUOTED, json_parser_parse_close_or_comma);
			if (ret != JSON_PARSER_OK) {
				return ret;
			}

			switch (c) {
			case '}':
				return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

			case ']':
				return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

			case ',':
				jpi->parse_func = json_parser_parse_name_or_value;
				return JSON_PARSER_OK;

			default:
				if (!json_parser_is_whitespace(c)) {
					return json_parser_callback_parse_error(jpi);
				}

				jpi->parse_func = json_parser_parse_close_or_comma;
				return JSON_PARSER_OK;
			}
		}

		if (!json_parser_output_char(jpi, c)) {
			return json_parser_callback_internal_error(jpi);
		}
	}
}

static json_parser_error_t json_parser_parse_close_or_comma(struct json_parser_t *jpi, struct netbuf *nb)
{
	json_parser_skip_whitespace(jpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = json_parser_read_char(jpi, nb);
	switch (c) {
	case JSON_PARSER_EMOREDATA:
		return json_parser_emoredata(nb, emoredata_start);

	case JSON_PARSER_ESTOP:
		return json_parser_callback_parse_error(jpi);

	case '}':
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_OBJECT_END, json_parser_parse_close_or_comma);

	case ']':
		return json_parser_callback_basic(jpi, JSON_PARSER_EVENT_ARRAY_END, json_parser_parse_close_or_comma);

	case ',':
		jpi->parse_func = json_parser_parse_name_or_value;
		return json_parser_parse_name_or_value(jpi, nb);

	default:
		return json_parser_callback_parse_error(jpi);
	}
}

bool json_parser_recv_netbuf(struct json_parser_t *jpi, struct netbuf *nb)
{
	/* Is this part of a partially received request or response? */
	if (jpi->partial_nb) {
		netbuf_set_pos_to_start(jpi->partial_nb);
		size_t prev_size = netbuf_get_remaining(jpi->partial_nb);

		if (prev_size + netbuf_get_remaining(nb) > NETBUF_MAX_LENGTH) {
			DEBUG_ERROR("%p too long", jpi);
			json_parser_ref(jpi);
			json_parser_callback_parse_error(jpi);
			json_parser_deref(jpi);
			return false;
		}

		if (!netbuf_rev_make_space(nb, prev_size)) {
			DEBUG_ERROR("out of memory");
			json_parser_ref(jpi);
			json_parser_callback_internal_error(jpi);
			json_parser_deref(jpi);
			return false;
		}

		netbuf_rev_copy(nb, jpi->partial_nb, prev_size);

		netbuf_free(jpi->partial_nb);
		jpi->partial_nb = NULL;
	}

	json_parser_error_t ret;
	while (1) {
		DEBUG_TRACE("%p state = %p length = %u", jpi, jpi->parse_func, netbuf_get_remaining(nb));

		json_parser_ref(jpi);
		ret = jpi->parse_func(jpi, nb);
		if (json_parser_deref(jpi) <= 0) {
			return false;
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
			return true;
		}

		jpi->partial_nb = netbuf_alloc_and_steal(nb);
		if (!jpi->partial_nb) {
			DEBUG_ERROR("out of memory");
			json_parser_ref(jpi);
			json_parser_callback_internal_error(jpi);
			json_parser_deref(jpi);
			return false;
		}
	}

	return true;
}

static bool json_parser_recv_mem_internal(struct json_parser_t *jpi, const char *ptr, size_t length)
{
	struct netbuf *nb = netbuf_alloc_with_rev_space(length);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		json_parser_callback_internal_error(jpi);
		return false;
	}

	netbuf_rev_write(nb, ptr, length);
	bool result = json_parser_recv_netbuf(jpi, nb);

	netbuf_free(nb);
	return result;
}

bool json_parser_recv_mem(struct json_parser_t *jpi, uint8_t *ptr, uint8_t *end)
{
	size_t length = end - ptr;
	return json_parser_recv_mem_internal(jpi, (const char *)ptr, length);
}

bool json_parser_recv_str(struct json_parser_t *jpi, const char *str)
{
	size_t length = strlen(str);
	return json_parser_recv_mem_internal(jpi, str, length);
}

void json_parser_reset(struct json_parser_t *jpi)
{
	if (jpi->partial_nb) {
		netbuf_free(jpi->partial_nb);
		jpi->partial_nb = NULL;
	}

	json_parser_output_clear(jpi);
	jpi->parse_func = json_parser_parse_start;
}

struct json_parser_t *json_parser_alloc(json_parser_callback_t callback, void *callback_arg)
{
	struct json_parser_t *jpi = (struct json_parser_t *)heap_alloc_and_zero(sizeof(struct json_parser_t), PKG_OS, MEM_TYPE_OS_JSON_PARSER);
	if (!jpi) {
		return NULL;
	}

	jpi->name_nb = netbuf_alloc();
	if (!jpi->name_nb) {
		DEBUG_ERROR("out of memory");
		heap_free(jpi);
		return NULL;
	}

	jpi->value_nb = netbuf_alloc();
	if (!jpi->value_nb) {
		DEBUG_ERROR("out of memory");
		netbuf_free(jpi->name_nb);
		heap_free(jpi);
		return NULL;
	}

	jpi->refs = 1;
	jpi->callback = callback;
	jpi->callback_arg = callback_arg;
	json_parser_reset(jpi);

	return jpi;
}
