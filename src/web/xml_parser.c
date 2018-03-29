/*
 * ./src/web/xml_parser.c
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

THIS_FILE("xml_parser");

static xml_parser_error_t xml_parser_parse_estop(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_start(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_detect_utf(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_common_open(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_common_open_comment(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_pi_tag(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_start_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_start_name(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_attribute_start(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_attribute_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_attribute_name(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_attribute_value_single(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_attribute_value_quote(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_text(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_text_comment(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_end_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb);
static xml_parser_error_t xml_parser_parse_element_end_name(struct xml_parser_t *xpi, struct netbuf *nb);

struct xml_parser_t *xml_parser_ref(struct xml_parser_t *xpi)
{
	xpi->refs++;
	return xpi;
}

ref_t xml_parser_deref(struct xml_parser_t *xpi)
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

static void xml_parser_output_clear(struct xml_parser_t *xpi)
{
	netbuf_reset(xpi->output_nb);
}

static bool xml_parser_output_char(struct xml_parser_t *xpi, uint16_t c)
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

static uint16_t xml_parser_read_char_result(uint16_t c)
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

	return (uint16_t)XML_PARSER_ESTOP;
}

static uint16_t xml_parser_read_char(struct xml_parser_t *xpi, struct netbuf *nb)
{
	if (xpi->utf_mode == XML_PARSER_UTF16LE) {
		/*
		 * UTF-16LE
		 */
		if (!netbuf_fwd_check_space(nb, 2)) {
			return (uint16_t)XML_PARSER_EMOREDATA;
		}

		return xml_parser_read_char_result(netbuf_fwd_read_le_u16(nb));
	}

	if (xpi->utf_mode == XML_PARSER_UTF16BE) {
		/*
		 * UTF-16BE
		 */
		if (!netbuf_fwd_check_space(nb, 2)) {
			return (uint16_t)XML_PARSER_EMOREDATA;
		}

		return xml_parser_read_char_result(netbuf_fwd_read_u16(nb));
	}

	/*
	 * UTF-8
	 */
	if (!netbuf_fwd_check_space(nb, 1)) {
		return (uint16_t)XML_PARSER_EMOREDATA;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	if ((c & 0x80) == 0x00) {
		return xml_parser_read_char_result(c);
	}

	if ((c & 0xE0) == 0xC0) {
		uint16_t result = (uint16_t)(c & 0x1F) << 6;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 1);
			return (uint16_t)XML_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)XML_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 0;
		return xml_parser_read_char_result(result);
	}

	if ((c & 0xF0) == 0xE0) {
		uint16_t result = (uint16_t)(c & 0x0F) << 12;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 1);
			return (uint16_t)XML_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)XML_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 6;

		if (!netbuf_fwd_check_space(nb, 1)) {
			netbuf_retreat_pos(nb, 2);
			return (uint16_t)XML_PARSER_EMOREDATA;
		}

		c = netbuf_fwd_read_u8(nb);
		if ((c & 0xC0) != 0x80) {
			DEBUG_WARN("utf8 string corrupt");
			return (uint16_t)XML_PARSER_ESTOP;
		}

		result |= (uint16_t)(c & 0x3F) << 0;
		return xml_parser_read_char_result(result);
	}

	DEBUG_WARN("utf8 string corrupt");
	return (uint16_t)XML_PARSER_ESTOP;
}

static uint16_t xml_parser_read_escaped_char(struct xml_parser_t *xpi, struct netbuf *nb)
{
	char buffer[8];
	char *ptr = buffer;
	char *end = buffer + sizeof(buffer);

	while (1) {
		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return XML_PARSER_EMOREDATA;
		}

		if (c == ';') {
			*ptr = 0;
			break;
		}

		if ((c < 'a') || (c > 'z')) {
			DEBUG_WARN("not a valid escape string");
			return XML_PARSER_ESTOP;
		}

		*ptr++ = (char)(uint8_t)c;

		if (ptr >= end) {
			DEBUG_WARN("not a valid escape string");
			return XML_PARSER_ESTOP;
		}
	}

	if (strcmp(buffer, "lt") == 0) {
		return '<';
	}
	if (strcmp(buffer, "gt") == 0) {
		return '>';
	}
	if (strcmp(buffer, "amp") == 0) {
		return '&';
	}
	if (strcmp(buffer, "apos") == 0) {
		return '\'';
	}
	if (strcmp(buffer, "quot") == 0) {
		return '\"';
	}

	DEBUG_WARN("not a valid escape string");
	return XML_PARSER_ESTOP;
}

static bool xml_parser_is_whitespace(uint16_t c)
{
	return (c == ' ') || (c == '\t') || (c == '\r') || (c == '\n');
}

static bool xml_parser_is_valid_name_character(uint16_t c, bool first_char)
{
	if ((c >= 'A') && (c <= 'Z')) {
		return true;
	}
	if (c == '_') {
		return true;
	}
	if ((c >= 'a') && (c <= 'z')) {
		return true;
	}
	if ((c >= 0x00C0) && (c <= 0x00D6)) {
		return true;
	}
	if ((c >= 0x00D8) && (c <= 0x00F6)) {
		return true;
	}
	if ((c >= 0x00F8) && (c <= 0x02FF)) {
		return true;
	}
	if ((c >= 0x0370) && (c <= 0x037D)) {
		return true;
	}
	if ((c >= 0x037F) && (c <= 0x1FFF)) {
		return true;
	}
	if ((c >= 0x200C) && (c <= 0x200D)) {
		return true;
	}
	if ((c >= 0x2070) && (c <= 0x218F)) {
		return true;
	}
	if ((c >= 0x2C00) && (c <= 0x2FEF)) {
		return true;
	}
	if ((c >= 0x3001) && (c <= 0xD7FF)) {
		return true;
	}
	if ((c >= 0xF900) && (c <= 0xFDCF)) {
		return true;
	}
	if ((c >= 0xFDF0) && (c <= 0xFFFD)) {
		return true;
	}

	if (first_char) {
		return false;
	}

	if ((c == '-') || (c == '.')) {
		return true;
	}
	if ((c >= '0') && (c <= '9')) {
		return true;
	}
	if (c == 0x00B7) {
		return true;
	}
	if ((c >= 0x0300) && (c <= 0x036F)) {
		return true;
	}
	if ((c >= 0x203F) && (c <= 0x2040)) {
		return true;
	}

	return false;
}

static void xml_parser_skip_whitespace(struct xml_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t bookmark = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (!xml_parser_is_whitespace(c)) {
			netbuf_set_pos(nb, bookmark);
			return;
		}
	}
}

static xml_parser_error_t xml_parser_callback_internal_error(struct xml_parser_t *xpi)
{
	DEBUG_WARN("%p xml_parser_callback_internal_error: state %p", xpi, xpi->parse_func);
	xml_parser_error_t ret = xpi->callback(xpi->callback_arg, XML_PARSER_EVENT_INTERNAL_ERROR, NULL);
	DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);

	if (xpi->parse_func == xml_parser_parse_start) { /* xml_parser_reset called */
		return XML_PARSER_ESTOP;
	}

	xml_parser_output_clear(xpi);
	xpi->parse_func = xml_parser_parse_estop;
	return XML_PARSER_ESTOP;
}

static xml_parser_error_t xml_parser_callback_parse_error(struct xml_parser_t *xpi)
{
	DEBUG_WARN("%p xml_parser_callback_parse_error: state %p", xpi, xpi->parse_func);
	xml_parser_error_t ret = xpi->callback(xpi->callback_arg, XML_PARSER_EVENT_PARSE_ERROR, NULL);
	DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);

	if (xpi->parse_func == xml_parser_parse_start) {
		return XML_PARSER_ESTOP;
	}

	xml_parser_output_clear(xpi);
	xpi->parse_func = xml_parser_parse_estop;
	return XML_PARSER_ESTOP;
}

static xml_parser_error_t xml_parser_callback_null_nb(struct xml_parser_t *xpi, xml_parser_event_t xml_event, xml_parser_parse_func_t next_parse_func)
{
	xml_parser_error_t ret = xpi->callback(xpi->callback_arg, xml_event, NULL);

	if (xpi->parse_func == xml_parser_parse_start) { /* xml_parser_reset called */
		DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		return XML_PARSER_ESTOP;
	}

	xml_parser_output_clear(xpi);

	if (ret != XML_PARSER_OK) {
		DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		xpi->parse_func = xml_parser_parse_estop;
		return XML_PARSER_ESTOP;
	}

	xpi->parse_func = next_parse_func;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_parser_callback_with_nb(struct xml_parser_t *xpi, xml_parser_event_t xml_event, xml_parser_parse_func_t next_parse_func)
{
	/* Ensure netbuf always has memory allocated. */
	if (!netbuf_fwd_make_space(xpi->output_nb, 0)) {
		DEBUG_ERROR("out of memory");
		return xml_parser_callback_internal_error(xpi);
	}

	netbuf_set_pos_to_start(xpi->output_nb);
	xml_parser_error_t ret = xpi->callback(xpi->callback_arg, xml_event, xpi->output_nb);

	if (xpi->parse_func == xml_parser_parse_start) { /* xml_parser_reset called */
		DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		return XML_PARSER_ESTOP;
	}

	xml_parser_output_clear(xpi);

	if (ret != XML_PARSER_OK) {
		DEBUG_ASSERT(ret == XML_PARSER_ESTOP, "%p unexpected return value from app: state %p", xpi, xpi->parse_func);
		xpi->parse_func = xml_parser_parse_estop;
		return XML_PARSER_ESTOP;
	}

	xpi->parse_func = next_parse_func;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_parser_emoredata(struct netbuf *nb, addr_t start_bookmark)
{
	netbuf_set_start(nb, start_bookmark);
	return XML_PARSER_EMOREDATA;
}

static xml_parser_error_t xml_parser_parse_comment_internal(struct xml_parser_t *xpi, struct netbuf *nb, xml_parser_parse_func_t next_parse_func)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == '-') {
			addr_t advance_bookmark = netbuf_get_pos(nb);

			c = xml_parser_read_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}

			if (c == '-') {
				c = xml_parser_read_char(xpi, nb);
				if (c == XML_PARSER_EMOREDATA) {
					return xml_parser_emoredata(nb, emoredata_start);
				}

				if (c == '>') {
					xpi->parse_func = next_parse_func;
					return XML_PARSER_OK;
				}
			}

			netbuf_set_pos(nb, advance_bookmark);
		}

		if (c == XML_PARSER_ESTOP) {
			return xml_parser_callback_parse_error(xpi);
		}
	}
}

static xml_parser_error_t xml_parser_parse_bang_start_internal(struct xml_parser_t *xpi, struct netbuf *nb, xml_parser_parse_func_t comment_parse_func)
{
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = xml_parser_read_char(xpi, nb);
	if (c == XML_PARSER_EMOREDATA) {
		return xml_parser_emoredata(nb, emoredata_start);
	}

	if (c == '-') {
		c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c != '-') {
			return xml_parser_callback_parse_error(xpi);
		}

		xpi->parse_func = comment_parse_func;
		return XML_PARSER_OK;
	}

	DEBUG_ERROR("<! not supported");
	return xml_parser_callback_parse_error(xpi);
}

static xml_parser_error_t xml_parser_parse_estop(struct xml_parser_t *xpi, struct netbuf *nb)
{
	DEBUG_WARN("%p recv called after estop", xpi);
	return XML_PARSER_ESTOP;
}

static xml_parser_error_t xml_parser_parse_start(struct xml_parser_t *xpi, struct netbuf *nb)
{
	xpi->parse_func = xml_parser_parse_detect_utf;
	return xml_parser_parse_detect_utf(xpi, nb);
}

static xml_parser_error_t xml_parser_parse_detect_utf(struct xml_parser_t *xpi, struct netbuf *nb)
{
	addr_t emoredata_start = netbuf_get_pos(nb);

	if (!netbuf_fwd_check_space(nb, 2)) {
		return xml_parser_emoredata(nb, emoredata_start);
	}

	uint16_t c = netbuf_fwd_read_u16(nb);
	xpi->parse_func = xml_parser_parse_common_open;

	/* Check for 0xFEFF magic */
	if (c == 0xFEFF) {
		xpi->utf_mode = XML_PARSER_UTF16BE;
		return XML_PARSER_OK;
	}

	if (c == 0xFFFE) {
		xpi->utf_mode = XML_PARSER_UTF16LE;
		return XML_PARSER_OK;
	}

	netbuf_retreat_pos(nb, 2);

	/* Simple check for low value 16-bit characters */
	if ((c & 0xFF00) == 0x0000) {
		xpi->utf_mode = XML_PARSER_UTF16BE;
		return XML_PARSER_OK;
	}

	if ((c & 0x00FF) == 0x0000) {
		xpi->utf_mode = XML_PARSER_UTF16LE;
		return XML_PARSER_OK;
	}

	/* Everything else presume utf-8 */
	xpi->utf_mode = XML_PARSER_UTF8;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_parser_parse_common_open(struct xml_parser_t *xpi, struct netbuf *nb)
{
	xml_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = xml_parser_read_char(xpi, nb);
	if (c == XML_PARSER_EMOREDATA) {
		return xml_parser_emoredata(nb, emoredata_start);
	}

	if (c != '<') {
		return xml_parser_callback_parse_error(xpi);
	}

	addr_t post_open_bookmark = netbuf_get_pos(nb);
	c = xml_parser_read_char(xpi, nb);
	if (c == XML_PARSER_EMOREDATA) {
		return xml_parser_emoredata(nb, emoredata_start);
	}

	if (c == '?') {
		xpi->parse_func = xml_parser_parse_pi_tag;
		return XML_PARSER_OK;
	}

	if (c == '!') {
		return xml_parser_parse_bang_start_internal(xpi, nb, xml_parser_parse_common_open_comment);
	}

	if (xml_parser_is_valid_name_character(c, true)) {
		netbuf_set_pos(nb, post_open_bookmark);
		xpi->parse_func = xml_parser_parse_element_start_namespace_or_name;
		return XML_PARSER_OK;
	}

	if (c == '/') {
		xpi->parse_func = xml_parser_parse_element_end_namespace_or_name;
		return XML_PARSER_OK;
	}

	return xml_parser_callback_parse_error(xpi);
}

static xml_parser_error_t xml_parser_parse_common_open_comment(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_comment_internal(xpi, nb, xml_parser_parse_common_open);
}

static xml_parser_error_t xml_parser_parse_pi_tag(struct xml_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == '?') {
			c = xml_parser_read_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}

			if (c != '>') {
				return xml_parser_callback_parse_error(xpi);
			}

			xpi->parse_func = xml_parser_parse_common_open;
			return XML_PARSER_OK;
		}

		if ((c == '<') || (c == '>')) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (c == XML_PARSER_ESTOP) {
			return xml_parser_callback_parse_error(xpi);
		}
	}
}

static xml_parser_error_t xml_parser_parse_element_start_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	bool first_char = (netbuf_get_extent(xpi->output_nb) == 0);

	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == ':') {
			if (xpi->parse_func == xml_parser_parse_element_start_name) {
				return xml_parser_callback_parse_error(xpi);
			}

			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_START_NAMESPACE, xml_parser_parse_element_start_name);
		}

		if (c == '>') {
			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_START_NAME, xml_parser_parse_element_text);
		}

		if (c == '/') {
			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			c = xml_parser_read_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}

			if (c != '>') {
				return xml_parser_callback_parse_error(xpi);
			}

			xml_parser_error_t ret = xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_START_NAME, xml_parser_parse_common_open);
			if (ret != XML_PARSER_OK) {
				return ret;
			}

			return xml_parser_callback_null_nb(xpi, XML_PARSER_EVENT_ELEMENT_SELF_CLOSE, xml_parser_parse_common_open);
		}

		if (xml_parser_is_whitespace(c)) {
			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_START_NAME, xml_parser_parse_attribute_start);
		}

		if (!xml_parser_is_valid_name_character(c, first_char)) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_output_char(xpi, c)) {
			return xml_parser_callback_internal_error(xpi);
		}

		first_char = false;
	}
}

static xml_parser_error_t xml_parser_parse_element_start_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_element_start_namespace_or_name(xpi, nb);
}

static xml_parser_error_t xml_parser_parse_attribute_start(struct xml_parser_t *xpi, struct netbuf *nb)
{
	xml_parser_skip_whitespace(xpi, nb);
	addr_t emoredata_start = netbuf_get_pos(nb);

	uint16_t c = xml_parser_read_char(xpi, nb);
	if (c == XML_PARSER_EMOREDATA) {
		return xml_parser_emoredata(nb, emoredata_start);
	}

	if (c == '>') {
		xpi->parse_func = xml_parser_parse_element_text;
		return XML_PARSER_OK;
	}

	if (c == '/') {
		c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c != '>') {
			return xml_parser_callback_parse_error(xpi);
		}

		return xml_parser_callback_null_nb(xpi, XML_PARSER_EVENT_ELEMENT_SELF_CLOSE, xml_parser_parse_common_open);
	}

	if (xml_parser_is_valid_name_character(c, true)) {
		netbuf_set_pos(nb, emoredata_start);
		xpi->parse_func = xml_parser_parse_attribute_namespace_or_name;
		return XML_PARSER_OK;
	}

	return xml_parser_callback_parse_error(xpi);
}

static xml_parser_error_t xml_parser_parse_attribute_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	bool first_char = (netbuf_get_extent(xpi->output_nb) == 0);

	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == ':') {
			if (xpi->parse_func == xml_parser_parse_attribute_name) {
				return xml_parser_callback_parse_error(xpi);
			}

			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ATTRIBUTE_NAMESPACE, xml_parser_parse_attribute_name);
		}

		if (c == '=') {
			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			c = xml_parser_read_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}

			if (c == '\'') {
				return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ATTRIBUTE_NAME, xml_parser_parse_attribute_value_single);
			}
			if (c == '\"') {
				return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ATTRIBUTE_NAME, xml_parser_parse_attribute_value_quote);
			}

			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_is_valid_name_character(c, first_char)) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_output_char(xpi, c)) {
			return xml_parser_callback_internal_error(xpi);
		}

		first_char = false;
	}
}

static xml_parser_error_t xml_parser_parse_attribute_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_attribute_namespace_or_name(xpi, nb);
}

static xml_parser_error_t xml_parser_parse_attribute_value_internal(struct xml_parser_t *xpi, struct netbuf *nb, uint16_t complete_char)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == complete_char) {
			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ATTRIBUTE_VALUE, xml_parser_parse_attribute_start);
		}

		if ((c == '<') || (c == '>')) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (c == '&') {
			c = xml_parser_read_escaped_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}
		}

		if (c == XML_PARSER_ESTOP) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_output_char(xpi, c)) {
			return xml_parser_callback_internal_error(xpi);
		}
	}
}

static xml_parser_error_t xml_parser_parse_attribute_value_single(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_attribute_value_internal(xpi, nb, '\'');
}

static xml_parser_error_t xml_parser_parse_attribute_value_quote(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_attribute_value_internal(xpi, nb, '\"');
}

static xml_parser_error_t xml_parser_parse_element_text(struct xml_parser_t *xpi, struct netbuf *nb)
{
	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == '<') {
			addr_t post_open_bookmark = netbuf_get_pos(nb);
			c = xml_parser_read_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}

			if (c == '/') {
				return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_TEXT, xml_parser_parse_element_end_namespace_or_name);
			}

			if (c == '!') {
				return xml_parser_parse_bang_start_internal(xpi, nb, xml_parser_parse_element_text_comment);
			}

			if (xml_parser_is_valid_name_character(c, true)) {
				xml_parser_output_clear(xpi);
				netbuf_set_pos(nb, post_open_bookmark);
				xpi->parse_func = xml_parser_parse_element_start_namespace_or_name;
				return XML_PARSER_OK;
			}

			return xml_parser_callback_parse_error(xpi);
		}

		if (c == '>') {
			return xml_parser_callback_parse_error(xpi);
		}

		if (c == '&') {
			c = xml_parser_read_escaped_char(xpi, nb);
			if (c == XML_PARSER_EMOREDATA) {
				return xml_parser_emoredata(nb, emoredata_start);
			}
		}

		if (c == XML_PARSER_ESTOP) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_output_char(xpi, c)) {
			return xml_parser_callback_internal_error(xpi);
		}

		/*
		 * If we hit the ~8k max data limit then push it to the app even though we haven't got the end tag.
		 * This could result in the application getting an unexected element-text callback and result in the
		 * application rejecting the document if there is >8k of whitespace between two start tags.
		 */
		if (netbuf_get_extent(xpi->output_nb) >= NETBUF_MAX_LENGTH) {
			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_TEXT, xml_parser_parse_element_text);
		}
	}
}

static xml_parser_error_t xml_parser_parse_element_text_comment(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_comment_internal(xpi, nb, xml_parser_parse_element_text);
}

static xml_parser_error_t xml_parser_parse_element_end_namespace_or_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	bool first_char = (netbuf_get_extent(xpi->output_nb) == 0);

	while (1) {
		addr_t emoredata_start = netbuf_get_pos(nb);

		uint16_t c = xml_parser_read_char(xpi, nb);
		if (c == XML_PARSER_EMOREDATA) {
			return xml_parser_emoredata(nb, emoredata_start);
		}

		if (c == ':') {
			if (xpi->parse_func == xml_parser_parse_element_end_name) {
				return xml_parser_callback_parse_error(xpi);
			}

			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_END_NAMESPACE, xml_parser_parse_element_end_name);
		}

		if (c == '>') {
			if (first_char) {
				return xml_parser_callback_parse_error(xpi);
			}

			return xml_parser_callback_with_nb(xpi, XML_PARSER_EVENT_ELEMENT_END_NAME, xml_parser_parse_common_open);
		}

		if (!xml_parser_is_valid_name_character(c, first_char)) {
			return xml_parser_callback_parse_error(xpi);
		}

		if (!xml_parser_output_char(xpi, c)) {
			return xml_parser_callback_internal_error(xpi);
		}

		first_char = false;
	}
}

static xml_parser_error_t xml_parser_parse_element_end_name(struct xml_parser_t *xpi, struct netbuf *nb)
{
	return xml_parser_parse_element_end_namespace_or_name(xpi, nb);
}

void xml_parser_recv_netbuf(struct xml_parser_t *xpi, struct netbuf *nb)
{
	/* Is this part of a partially received request or response? */
	if (xpi->partial_nb) {
		netbuf_set_pos_to_start(xpi->partial_nb);
		size_t prev_size = netbuf_get_remaining(xpi->partial_nb);

		if (prev_size + netbuf_get_remaining(nb) > NETBUF_MAX_LENGTH) {
			DEBUG_ERROR("%p too long", xpi);
			xml_parser_ref(xpi);
			xml_parser_callback_parse_error(xpi);
			xml_parser_deref(xpi);
			return;
		}

		if (!netbuf_rev_make_space(nb, prev_size)) {
			DEBUG_ERROR("out of memory");
			xml_parser_ref(xpi);
			xml_parser_callback_internal_error(xpi);
			xml_parser_deref(xpi);
			return;
		}

		netbuf_rev_copy(nb, xpi->partial_nb, prev_size);

		netbuf_free(xpi->partial_nb);
		xpi->partial_nb = NULL;
	}

	xml_parser_error_t ret;
	while (1) {
		DEBUG_TRACE("%p state = %p length = %u", xpi, xpi->parse_func, netbuf_get_remaining(nb));

		xml_parser_ref(xpi);
		ret = xpi->parse_func(xpi, nb);
		if (xml_parser_deref(xpi) <= 0) {
			return;
		}

		if (ret != XML_PARSER_OK) {
			break;
		}

		if (netbuf_get_remaining(nb) == 0) {
			break;
		}
	}

	if (ret == XML_PARSER_EMOREDATA) {
		if (netbuf_get_extent(nb) == 0) {
			return;
		}

		xpi->partial_nb = netbuf_alloc_and_steal(nb);
		if (!xpi->partial_nb) {
			DEBUG_ERROR("out of memory");
			xml_parser_ref(xpi);
			xml_parser_callback_internal_error(xpi);
			xml_parser_deref(xpi);
			return;
		}
	}
}

void xml_parser_recv_str(struct xml_parser_t *xpi, const char *str)
{
	size_t length = strlen(str);

	struct netbuf *nb = netbuf_alloc_with_rev_space(length);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		xml_parser_callback_internal_error(xpi);
		return;
	}

	netbuf_rev_write(nb, str, length);
	xml_parser_recv_netbuf(xpi, nb);
	netbuf_free(nb);
}

void xml_parser_reset(struct xml_parser_t *xpi)
{
	if (xpi->partial_nb) {
		netbuf_free(xpi->partial_nb);
		xpi->partial_nb = NULL;
	}

	xml_parser_output_clear(xpi);
	xpi->parse_func = xml_parser_parse_start;
}

struct xml_parser_t *xml_parser_alloc(xml_parser_callback_t callback, void *callback_arg)
{
	struct xml_parser_t *xpi = (struct xml_parser_t *)heap_alloc_and_zero(sizeof(struct xml_parser_t), PKG_OS, MEM_TYPE_OS_XML_PARSER);
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
	xml_parser_reset(xpi);

	return xpi;
}
