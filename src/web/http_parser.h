/*
 * http_parser.h
 *
 * Copyright © 2012-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	HTTP_PARSER_OK = 0,
	HTTP_PARSER_EMOREDATA,
	HTTP_PARSER_ESTOP,
} http_parser_error_t;

typedef enum {
	HTTP_PARSER_EVENT_INTERNAL_ERROR = 0,
	HTTP_PARSER_EVENT_PARSE_ERROR,
	HTTP_PARSER_EVENT_METHOD,
	HTTP_PARSER_EVENT_URI,
	HTTP_PARSER_EVENT_PARAMS,
	HTTP_PARSER_EVENT_PROTOCOL,
	HTTP_PARSER_EVENT_VERSION,
	HTTP_PARSER_EVENT_STATUS_CODE,
	HTTP_PARSER_EVENT_REASON_PHRASE,
	HTTP_PARSER_EVENT_HEADER_COMPLETE,
	HTTP_PARSER_EVENT_DATA,
	HTTP_PARSER_EVENT_DATA_COMPLETE,
	HTTP_PARSER_EVENT_RESET,
} http_parser_event_t;

typedef http_parser_error_t (*http_parser_func_t)(void *app_data, const char *header, struct netbuf *nb);
typedef http_parser_error_t (*http_parser_event_callback_t)(void *app_data, http_parser_event_t header_event, struct netbuf *nb);

struct http_parser_tag_lookup_t {
	const char *header;
	http_parser_func_t func;
};

struct http_parser_t;

extern struct http_parser_t *http_parser_alloc(http_parser_event_callback_t event_callback, void *callback_arg);
extern struct http_parser_t *http_parser_ref(struct http_parser_t *hpi);
extern ref_t http_parser_deref(struct http_parser_t *hpi);
extern void http_parser_set_tag_list(struct http_parser_t *hpi, const struct http_parser_tag_lookup_t *hle, void *callback_arg);
extern void http_parser_recv_netbuf(struct http_parser_t *hpi, struct netbuf *nb);
extern bool http_parser_is_valid_complete(struct http_parser_t *hpi);
extern void http_parser_reset(struct http_parser_t *hpi); 

/* Internal */
typedef http_parser_error_t (*http_parser_parse_func_t)(struct http_parser_t *hpi, struct netbuf *nb);

struct http_parser_t {
	http_parser_parse_func_t parse_func;
	struct netbuf *partial_nb;
	ref_t refs;

	const struct http_parser_tag_lookup_t *internal_list_entry;
	const struct http_parser_tag_lookup_t *app_list_entry;
	uint64_t length_remaining;
	bool chunked_encoding;

	const struct http_parser_tag_lookup_t *app_list;
	void *app_list_callback_arg;

	http_parser_event_callback_t event_callback;
	void *event_callback_arg;
};
