/*
 * http_parser.c
 *
 * Copyright © 2012-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("http_parser");

static http_parser_error_t http_parser_parse_estop(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_start(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_method_protocol(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_request_uri(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_request_params(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_request_protocol(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_request_version(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_response_version(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_response_status_code(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_response_reason_phrase(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_headers_name(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_headers_value(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_headers_complete(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_payload_data(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_payload_chunked_header(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_payload_chunked_data(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_payload_chunked_separator(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_payload_chunked_complete(struct http_parser_t *hpi, struct netbuf *nb);
static http_parser_error_t http_parser_parse_transaction_complete(struct http_parser_t *hpi, struct netbuf *nb);

static http_parser_error_t http_parser_tag_content_length(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t http_parser_tag_transfer_encodding(void *arg, const char *header, struct netbuf *nb);

static const struct http_parser_tag_lookup_t http_parser_tag_list[] = {
	{"Content-Length", http_parser_tag_content_length},
	{"Transfer-Encoding", http_parser_tag_transfer_encodding},
	{NULL, NULL}
};

struct http_parser_t *http_parser_ref(struct http_parser_t *hpi)
{
	hpi->refs++;
	return hpi;
}

ref_t http_parser_deref(struct http_parser_t *hpi) {

	hpi->refs--;
	if (hpi->refs != 0) {
		return hpi->refs;
	}

	if (hpi->partial_nb) {
		netbuf_free(hpi->partial_nb);
	}

	heap_free(hpi);
	return 0;
}

static inline bool http_parser_is_subline_badchar(uint8_t c)
{
	return (c < ' ') && (c != '\t');
}

static inline bool http_parser_is_subline_whitespace(uint8_t c)
{
	return (c == ' ') || (c == '\t');
}

static void http_parser_skip_subline_whitespace(struct netbuf *nb)
{
	addr_t pos = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);
		if (!http_parser_is_subline_whitespace(c)) {
			netbuf_retreat_pos(nb, 1);
			return;
		}

		pos++;
	}
}

static http_parser_error_t http_parser_callback_internal_error(struct http_parser_t *hpi)
{
	DEBUG_WARN("%p http_parser_callback_internal_error: state %p", hpi, hpi->parse_func);
	http_parser_error_t ret = hpi->event_callback(hpi->event_callback_arg, HTTP_PARSER_EVENT_INTERNAL_ERROR, NULL);
	DEBUG_ASSERT(ret == HTTP_PARSER_ESTOP, "%p unexpected return value from app: state %p", hpi, hpi->parse_func);

	if (hpi->parse_func == http_parser_parse_start) { /* http_parser_reset called */
		return HTTP_PARSER_ESTOP;
	}

	hpi->parse_func = http_parser_parse_estop;
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t http_parser_callback_parse_error(struct http_parser_t *hpi)
{
	DEBUG_WARN("%p http_parser_callback_parse_error: state %p", hpi, hpi->parse_func);
	http_parser_error_t ret = hpi->event_callback(hpi->event_callback_arg, HTTP_PARSER_EVENT_PARSE_ERROR, NULL);
	DEBUG_ASSERT(ret == HTTP_PARSER_ESTOP, "%p unexpected return value from app: state %p", hpi, hpi->parse_func);

	if (hpi->parse_func == http_parser_parse_start) {
		return HTTP_PARSER_ESTOP;
	}

	hpi->parse_func = http_parser_parse_estop;
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t http_parser_callback_null_nb(struct http_parser_t *hpi, http_parser_event_t header_event, http_parser_parse_func_t next_parse_func)
{
	http_parser_error_t ret = hpi->event_callback(hpi->event_callback_arg, header_event, NULL);

	if (hpi->parse_func == http_parser_parse_start) { /* http_parser_reset called */
		return HTTP_PARSER_ESTOP;
	}

	if (ret != HTTP_PARSER_OK) {
		DEBUG_ASSERT(ret == HTTP_PARSER_ESTOP, "%p unexpected return value from app: state %p", hpi, hpi->parse_func);
		hpi->parse_func = http_parser_parse_estop;
		return HTTP_PARSER_ESTOP;
	}

	hpi->parse_func = next_parse_func;
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_callback_with_nb(struct http_parser_t *hpi, http_parser_event_t header_event, struct netbuf *nb, addr_t begin, addr_t end, http_parser_parse_func_t next_parse_func)
{
	size_t length = end - begin;
	struct netbuf *callback_nb = netbuf_alloc_with_rev_space(length);
	if (!callback_nb) {
		DEBUG_ERROR("out of memory");
		return http_parser_callback_internal_error(hpi);
	}

	if (length > 0) {
		addr_t bookmark = netbuf_get_pos(nb);
		netbuf_set_pos(nb, begin);
		netbuf_rev_copy(callback_nb, nb, length);
		netbuf_set_pos(nb, bookmark);
	}

	http_parser_error_t ret = hpi->event_callback(hpi->event_callback_arg, header_event, callback_nb);
	netbuf_free(callback_nb);

	if (hpi->parse_func == http_parser_parse_start) { /* http_parser_reset called */
		return HTTP_PARSER_ESTOP;
	}

	if (ret != HTTP_PARSER_OK) {
		DEBUG_ASSERT(ret == HTTP_PARSER_ESTOP, "%p unexpected return value from app: state %p", hpi, hpi->parse_func);
		hpi->parse_func = http_parser_parse_estop;
		return HTTP_PARSER_ESTOP;
	}

	hpi->parse_func = next_parse_func;
	return HTTP_PARSER_OK;
}

static const struct http_parser_tag_lookup_t *http_parser_lookup_list_entry(const struct http_parser_tag_lookup_t *list, const char *lookup)
{
	const struct http_parser_tag_lookup_t *entry = list;

	while (entry->header) {
		if (strcasecmp(entry->header, lookup) == 0) {
			return entry;
		}

		entry++;
	}

	return NULL;
}

static http_parser_error_t http_parser_callback_headers_name(struct http_parser_t *hpi, struct netbuf *nb, addr_t begin, addr_t end, http_parser_parse_func_t next_parse_func)
{
	size_t length = end - begin;

	char lookup[64];
	if ((length == 0) || (length >= sizeof(lookup))) {
		hpi->internal_list_entry = NULL;
		hpi->app_list_entry = NULL;
		hpi->parse_func = next_parse_func;
		return HTTP_PARSER_OK;
	}

	addr_t bookmark = netbuf_get_pos(nb);
	netbuf_set_pos(nb, begin);
	netbuf_fwd_read(nb, lookup, length);
	netbuf_set_pos(nb, bookmark);
	lookup[length] = 0;

	hpi->internal_list_entry = http_parser_lookup_list_entry(http_parser_tag_list, lookup);
	hpi->app_list_entry = (hpi->app_list) ? http_parser_lookup_list_entry(hpi->app_list, lookup) : NULL;

	hpi->parse_func = next_parse_func;
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_callback_headers_value(struct http_parser_t *hpi, struct netbuf *nb, addr_t begin, addr_t end, http_parser_parse_func_t next_parse_func)
{
	const struct http_parser_tag_lookup_t *internal_list_entry = hpi->internal_list_entry;
	const struct http_parser_tag_lookup_t *app_list_entry = hpi->app_list_entry;
	hpi->internal_list_entry = NULL;
	hpi->app_list_entry = NULL;

	if (!internal_list_entry && !app_list_entry) {
		hpi->parse_func = next_parse_func;
		return HTTP_PARSER_OK;
	}

	size_t length = end - begin;
	struct netbuf *callback_nb = netbuf_alloc_with_rev_space(length);
	if (!callback_nb) {
		DEBUG_ERROR("out of memory");
		return http_parser_callback_internal_error(hpi);
	}
	if (length > 0) {
		addr_t bookmark = netbuf_get_pos(nb);
		netbuf_set_pos(nb, begin);
		netbuf_rev_copy(callback_nb, nb, length);
		netbuf_set_pos(nb, bookmark);
	}

	if (internal_list_entry) {
		internal_list_entry->func(hpi, internal_list_entry->header, callback_nb);

		if (!app_list_entry) {
			netbuf_free(callback_nb);
			hpi->parse_func = next_parse_func;
			return HTTP_PARSER_OK;
		}

		netbuf_set_pos_to_start(callback_nb);
	}

	http_parser_error_t ret = app_list_entry->func(hpi->app_list_callback_arg, app_list_entry->header, callback_nb);
	netbuf_free(callback_nb);

	if (hpi->parse_func == http_parser_parse_start) { /* http_parser_reset called */
		return HTTP_PARSER_ESTOP;
	}

	if (ret != HTTP_PARSER_OK) {
		DEBUG_ASSERT(ret == HTTP_PARSER_ESTOP, "%p unexpected return value from app: state %p", hpi, hpi->parse_func);
		hpi->parse_func = http_parser_parse_estop;
		return HTTP_PARSER_ESTOP;
	}

	hpi->parse_func = next_parse_func;
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_tag_content_length(void *arg, const char *header, struct netbuf *nb)
{
	struct http_parser_t *hpi = (struct http_parser_t *)arg;

	hpi->length_remaining = netbuf_fwd_strtoull(nb, NULL, 0);
	DEBUG_TRACE("%p content length = %llu", hpi, hpi->length_remaining);

	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_tag_transfer_encodding(void *arg, const char *header, struct netbuf *nb)
{
	struct http_parser_t *hpi = (struct http_parser_t *)arg;

	if (netbuf_fwd_strcasecmp(nb, "chunked") == 0) {
		DEBUG_INFO("%p chunked encoding", hpi);
		hpi->chunked_encoding = true;
		return HTTP_PARSER_OK;
	}

	DEBUG_WARN("%p unknown transfer encoding", hpi);
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_emoredata(struct netbuf *nb, addr_t start_bookmark)
{
	netbuf_set_start(nb, start_bookmark);
	return HTTP_PARSER_EMOREDATA;
}

static http_parser_error_t http_parser_parse_estop(struct http_parser_t *hpi, struct netbuf *nb)
{
	DEBUG_WARN("%p recv called after estop", hpi);
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t http_parser_parse_start(struct http_parser_t *hpi, struct netbuf *nb)
{
	hpi->parse_func = http_parser_parse_method_protocol;
	return http_parser_parse_method_protocol(hpi, nb);
}

static http_parser_error_t http_parser_parse_method_protocol(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (http_parser_is_subline_whitespace(c)) {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_METHOD, nb, begin, pos, http_parser_parse_request_uri);
		}

		if (c == '/') {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_PROTOCOL, nb, begin, pos, http_parser_parse_response_version);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_request_uri(struct http_parser_t *hpi, struct netbuf *nb)
{
	http_parser_skip_subline_whitespace(nb);
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '?') {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_URI, nb, begin, pos, http_parser_parse_request_params);
		}

		if (http_parser_is_subline_whitespace(c)) {
			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_URI, nb, begin, pos, http_parser_parse_request_protocol);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_request_params(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (http_parser_is_subline_whitespace(c)) {
			if (pos == begin) { /* ? (by itself) */
				hpi->parse_func = http_parser_parse_request_protocol;
				return HTTP_PARSER_OK;
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_PARAMS, nb, begin, pos, http_parser_parse_request_protocol);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_request_protocol(struct http_parser_t *hpi, struct netbuf *nb)
{
	http_parser_skip_subline_whitespace(nb);
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '/') {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_PROTOCOL, nb, begin, pos, http_parser_parse_request_version);
		}

		if (http_parser_is_subline_whitespace(c) || http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_request_version(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '\r') {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_VERSION, nb, begin, pos, http_parser_parse_headers_name);
		}

		if (http_parser_is_subline_whitespace(c) || http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_response_version(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (http_parser_is_subline_whitespace(c)) {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_VERSION, nb, begin, pos, http_parser_parse_response_status_code);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static void http_parser_parse_response_status_code_process(struct http_parser_t *hpi, struct netbuf *nb, addr_t begin, addr_t end)
{
	size_t len = end - begin;
	if (len != 3) {
		return;
	}

	addr_t bookmark = netbuf_get_pos(nb);
	netbuf_set_pos(nb, begin);

	/* Implied no payload data for 100-continue */
	if (netbuf_fwd_strncmp(nb, "100", 3) == 0) {
		hpi->length_remaining = 0;
	}

	netbuf_set_pos(nb, bookmark);
}

static http_parser_error_t http_parser_parse_response_status_code(struct http_parser_t *hpi, struct netbuf *nb)
{
	http_parser_skip_subline_whitespace(nb);
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '\r') {
			if (pos == begin) {
				return http_parser_callback_parse_error(hpi);
			}

			http_parser_parse_response_status_code_process(hpi, nb, begin, pos);
			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_STATUS_CODE, nb, begin, pos, http_parser_parse_headers_name);
		}

		if (http_parser_is_subline_whitespace(c)) {
			http_parser_parse_response_status_code_process(hpi, nb, begin, pos);
			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_STATUS_CODE, nb, begin, pos, http_parser_parse_response_reason_phrase);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_response_reason_phrase(struct http_parser_t *hpi, struct netbuf *nb)
{
	http_parser_skip_subline_whitespace(nb);
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '\r') {
			if (pos == begin) {
				hpi->parse_func = http_parser_parse_headers_name;
				return HTTP_PARSER_OK;
			}

			return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_REASON_PHRASE, nb, begin, pos, http_parser_parse_headers_name);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_headers_name(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	if (netbuf_fwd_read_u8(nb) != '\n') {
		return http_parser_callback_parse_error(hpi);
	}

	addr_t pos = begin + 1;
	if (pos >= end) {
		return http_parser_emoredata(nb, begin);
	}

	addr_t name_begin = pos;
	uint8_t c = netbuf_fwd_read_u8(nb);
	pos++;

	if (c == '\r') {
		hpi->parse_func = http_parser_parse_headers_complete;
		return HTTP_PARSER_OK;
	}

	if (http_parser_is_subline_whitespace(c)) {
		/* Ignore additional lines of a multi-line header entry. */
		while (pos < end) {
			c = netbuf_fwd_read_u8(nb);
			if (c == '\r') {
				return HTTP_PARSER_OK;
			}

			if (http_parser_is_subline_badchar(c)) {
				return http_parser_callback_parse_error(hpi);
			}

			pos++;
		}

		return http_parser_emoredata(nb, begin);
	}

	if (http_parser_is_subline_badchar(c)) {
		return http_parser_callback_parse_error(hpi);
	}

	if (c == ':') {
		return http_parser_callback_parse_error(hpi);
	}

	addr_t name_end = pos;
	while (pos < end) {
		c = netbuf_fwd_read_u8(nb);
		if (c == '\r') {
			return HTTP_PARSER_OK; /* No colon found - ignore line and move on. */
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		if (c == ':') {
			return http_parser_callback_headers_name(hpi, nb, name_begin, name_end, http_parser_parse_headers_value);
		}

		pos++;

		if (!http_parser_is_subline_whitespace(c)) {
			name_end = pos;
		}
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_headers_value(struct http_parser_t *hpi, struct netbuf *nb)
{
	http_parser_skip_subline_whitespace(nb);
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (pos < end) {
		uint8_t c = netbuf_fwd_read_u8(nb);

		if (c == '\r') {
			return http_parser_callback_headers_value(hpi, nb, begin, pos, http_parser_parse_headers_name);
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	return http_parser_emoredata(nb, begin);
}

static http_parser_error_t http_parser_parse_headers_complete(struct http_parser_t *hpi, struct netbuf *nb)
{
	if (netbuf_fwd_read_u8(nb) != '\n') {
		return http_parser_callback_parse_error(hpi);
	}

	if (hpi->chunked_encoding) {
		return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_HEADER_COMPLETE, http_parser_parse_payload_chunked_header);
	}
	
	if (hpi->length_remaining > 0) {
		return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_HEADER_COMPLETE, http_parser_parse_payload_data);
	}

	http_parser_error_t ret = http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_HEADER_COMPLETE, http_parser_parse_transaction_complete);
	if (ret != HTTP_PARSER_OK) {
		return ret;
	}

	return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_DATA_COMPLETE, http_parser_parse_transaction_complete);
}

static http_parser_error_t http_parser_parse_payload_data(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	size_t length = netbuf_get_remaining(nb);

	if ((uint64_t)length > hpi->length_remaining) {
		length = (size_t)hpi->length_remaining;
	}

	netbuf_advance_pos(nb, length);

	if (hpi->length_remaining != 0xFFFFFFFFFFFFFFFFULL) {
		hpi->length_remaining -= length;
	}

	if (hpi->length_remaining == 0) {
		http_parser_error_t ret = http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_DATA, nb, begin, begin + length, http_parser_parse_transaction_complete);
		if (ret != HTTP_PARSER_OK) {
			return ret;
		}

		return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_DATA_COMPLETE, http_parser_parse_transaction_complete);
	}

	return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_DATA, nb, begin, begin + length, http_parser_parse_payload_data);
}

static http_parser_error_t http_parser_parse_payload_chunked_header(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	addr_t end = netbuf_get_end(nb);

	addr_t pos = begin;
	while (1) {
		if (pos >= end) {
			return http_parser_emoredata(nb, begin);
		}

		uint8_t c = netbuf_fwd_read_u8(nb);
		if (c == '\r') {
			pos++;
			break;
		}

		if (http_parser_is_subline_badchar(c)) {
			return http_parser_callback_parse_error(hpi);
		}

		pos++;
	}

	if (pos >= end) {
		return http_parser_emoredata(nb, begin);
	}

	if (netbuf_fwd_read_u8(nb) != '\n') {
		return http_parser_callback_parse_error(hpi);
	}

	pos++;

	addr_t error;
	netbuf_set_pos(nb, begin);
	hpi->length_remaining = netbuf_fwd_strtoull(nb, &error, 16);

	netbuf_set_pos(nb, error);
	uint8_t c = netbuf_fwd_read_u8(nb);
	netbuf_set_pos(nb, pos);

	if (error == begin) {
		return http_parser_callback_parse_error(hpi);
	}
	if ((c != '\r') && (c != ';')) {
		return http_parser_callback_parse_error(hpi);
	}

	if (hpi->length_remaining == 0) {
		hpi->parse_func = http_parser_parse_payload_chunked_complete;
		return HTTP_PARSER_OK;
	}

	hpi->parse_func = http_parser_parse_payload_chunked_data;
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_parse_payload_chunked_data(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);
	size_t length = netbuf_get_remaining(nb);

	if ((uint64_t)length > hpi->length_remaining) {
		length = (size_t)hpi->length_remaining;
	}

	netbuf_advance_pos(nb, length);
	hpi->length_remaining -= length;

	if (hpi->length_remaining == 0) {
		return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_DATA, nb, begin, begin + length, http_parser_parse_payload_chunked_separator);
	}

	return http_parser_callback_with_nb(hpi, HTTP_PARSER_EVENT_DATA, nb, begin, begin + length, http_parser_parse_payload_chunked_data);
}

static http_parser_error_t http_parser_parse_payload_chunked_separator(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);

	if (netbuf_fwd_read_u8(nb) != '\r') {
		return http_parser_callback_parse_error(hpi);
	}

	if (!netbuf_fwd_check_space(nb, 1)) {
		return http_parser_emoredata(nb, begin);
	}

	if (netbuf_fwd_read_u8(nb) != '\n') {
		return http_parser_callback_parse_error(hpi);
	}

	hpi->parse_func = http_parser_parse_payload_chunked_header;
	return HTTP_PARSER_OK;
}

static http_parser_error_t http_parser_parse_payload_chunked_complete(struct http_parser_t *hpi, struct netbuf *nb)
{
	addr_t begin = netbuf_get_pos(nb);

	if (netbuf_fwd_read_u8(nb) != '\r') {
		return http_parser_callback_parse_error(hpi);
	}

	if (!netbuf_fwd_check_space(nb, 1)) {
		return http_parser_emoredata(nb, begin);
	}

	if (netbuf_fwd_read_u8(nb) != '\n') {
		return http_parser_callback_parse_error(hpi);
	}

	return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_DATA_COMPLETE, http_parser_parse_transaction_complete);
}

static http_parser_error_t http_parser_parse_transaction_complete(struct http_parser_t *hpi, struct netbuf *nb)
{
	hpi->length_remaining = 0xFFFFFFFFFFFFFFFFULL;
	hpi->chunked_encoding = false;

	return http_parser_callback_null_nb(hpi, HTTP_PARSER_EVENT_RESET, http_parser_parse_method_protocol);
}

void http_parser_recv_netbuf(struct http_parser_t *hpi, struct netbuf *nb) 
{
	/* Is this part of a partially received request or response? */
	if (hpi->partial_nb) {
		netbuf_set_pos_to_start(hpi->partial_nb);
		size_t prev_size = netbuf_get_remaining(hpi->partial_nb);

		if (prev_size + netbuf_get_remaining(nb) > NETBUF_MAX_LENGTH) {
			DEBUG_ERROR("%p too long", hpi);
			http_parser_ref(hpi);
			http_parser_callback_parse_error(hpi);
			http_parser_deref(hpi);
			return;
		}

		if (!netbuf_rev_make_space(nb, prev_size)) {
			DEBUG_ERROR("out of memory");
			http_parser_ref(hpi);
			http_parser_callback_internal_error(hpi);
			http_parser_deref(hpi);
			return;
		}

		netbuf_rev_copy(nb, hpi->partial_nb, prev_size);

		netbuf_free(hpi->partial_nb);
		hpi->partial_nb = NULL;
	}

	http_parser_error_t ret;
	while (1) {
		DEBUG_TRACE("%p state = %p length = %u", hpi, hpi->parse_func, netbuf_get_remaining(nb));

		http_parser_ref(hpi);
		ret = hpi->parse_func(hpi, nb);
		if (http_parser_deref(hpi) <= 0) {
			return;
		}

		if (ret != HTTP_PARSER_OK) {
			break;
		}

		if (netbuf_get_remaining(nb) == 0) {
			break;
		}
	}

	if (ret == HTTP_PARSER_EMOREDATA) {
		if (netbuf_get_extent(nb) == 0) {
			return;
		}

		hpi->partial_nb = netbuf_alloc_and_steal(nb);
		if (!hpi->partial_nb) {
			DEBUG_ERROR("out of memory");
			http_parser_ref(hpi);
			http_parser_callback_internal_error(hpi);
			http_parser_deref(hpi);
			return;
		}
	}
}

bool http_parser_is_valid_complete(struct http_parser_t *hpi)
{
	if (hpi->parse_func == http_parser_parse_transaction_complete) {
		return true;
	}

	if ((hpi->parse_func == http_parser_parse_payload_data) && (hpi->length_remaining == 0xFFFFFFFFFFFFFFFFULL)) {
		return true;
	}

	return false;
}

void http_parser_reset(struct http_parser_t *hpi)
{
	DEBUG_TRACE("%p http_parser_reset", hpi);

	if (hpi->partial_nb) {
		netbuf_free(hpi->partial_nb);
		hpi->partial_nb = NULL;
	}

	hpi->parse_func = http_parser_parse_start;
	hpi->internal_list_entry = NULL;
	hpi->app_list_entry = NULL;
	hpi->length_remaining = 0xFFFFFFFFFFFFFFFFULL;
	hpi->chunked_encoding = false;
}

void http_parser_set_tag_list(struct http_parser_t *hpi, const struct http_parser_tag_lookup_t *hle, void *callback_arg)
{
	hpi->app_list = hle;
	hpi->app_list_callback_arg = callback_arg;
}

struct http_parser_t *http_parser_alloc(http_parser_event_callback_t event_callback, void *callback_arg)
{
	struct http_parser_t *hpi = (struct http_parser_t *)heap_alloc_and_zero(sizeof(struct http_parser_t), PKG_OS, MEM_TYPE_OS_HTTP_PARSER);
	if (!hpi) {
		return NULL;
	}

	hpi->refs = 1;
	hpi->event_callback = event_callback;
	hpi->event_callback_arg = callback_arg;
	http_parser_reset(hpi);

	return hpi;
}
