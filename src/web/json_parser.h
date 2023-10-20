/*
 * json_parser.h
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	JSON_PARSER_EVENT_INTERNAL_ERROR,
	JSON_PARSER_EVENT_PARSE_ERROR,

	JSON_PARSER_EVENT_ARRAY_START,
	JSON_PARSER_EVENT_ARRAY_END,
	JSON_PARSER_EVENT_OBJECT_START,
	JSON_PARSER_EVENT_OBJECT_END,
	JSON_PARSER_EVENT_ELEMENT_STR,
	JSON_PARSER_EVENT_ELEMENT_UNQUOTED,

} json_parser_event_t;

typedef enum {
	JSON_PARSER_OK = 0,
	JSON_PARSER_EMOREDATA = 1,
	JSON_PARSER_ESTOP = 2,
} json_parser_error_t;

struct json_parser_t;

typedef json_parser_error_t (*json_parser_callback_t)(void *app_data, json_parser_event_t json_event, struct netbuf *name_nb, struct netbuf *value_nb);

extern struct json_parser_t *json_parser_alloc(json_parser_callback_t callback, void *callback_arg);
extern struct json_parser_t *json_parser_ref(struct json_parser_t *jpi);
extern ref_t json_parser_deref(struct json_parser_t *jpi);
extern bool json_parser_recv_netbuf(struct json_parser_t *jpi, struct netbuf *nb);
extern bool json_parser_recv_mem(struct json_parser_t *jpi, uint8_t *ptr, uint8_t *end);
extern bool json_parser_recv_str(struct json_parser_t *jpi, const char *str);
extern void json_parser_reset(struct json_parser_t *jpi);

/* Internal */
typedef json_parser_error_t (*json_parser_parse_func_t)(struct json_parser_t *jpi, struct netbuf *nb);

struct json_parser_t {
	json_parser_parse_func_t parse_func;
	struct netbuf *partial_nb;
	struct netbuf *name_nb;
	struct netbuf *value_nb;
	ref_t refs;

	json_parser_callback_t callback;
	void *callback_arg;
};
