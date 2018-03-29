/*
 * ./src/web/xml_parser.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	XML_PARSER_EVENT_INTERNAL_ERROR,
	XML_PARSER_EVENT_PARSE_ERROR,

	XML_PARSER_EVENT_ELEMENT_START_NAMESPACE,
	XML_PARSER_EVENT_ELEMENT_START_NAME,
	XML_PARSER_EVENT_ELEMENT_SELF_CLOSE,
	XML_PARSER_EVENT_ELEMENT_TEXT,
	XML_PARSER_EVENT_ELEMENT_END_NAMESPACE,
	XML_PARSER_EVENT_ELEMENT_END_NAME,
	XML_PARSER_EVENT_ATTRIBUTE_NAMESPACE,
	XML_PARSER_EVENT_ATTRIBUTE_NAME,
	XML_PARSER_EVENT_ATTRIBUTE_VALUE,

} xml_parser_event_t;

typedef enum {
	XML_PARSER_OK = 0,
	XML_PARSER_EMOREDATA = 1,
	XML_PARSER_ESTOP = 2,
} xml_parser_error_t;

struct xml_parser_t;

typedef xml_parser_error_t (*xml_parser_callback_t)(void *app_data, xml_parser_event_t xml_event, struct netbuf *nb);

extern struct xml_parser_t *xml_parser_alloc(xml_parser_callback_t callback, void *callback_arg);
extern struct xml_parser_t *xml_parser_ref(struct xml_parser_t *xpi);
extern ref_t xml_parser_deref(struct xml_parser_t *xpi);
extern void xml_parser_recv_netbuf(struct xml_parser_t *xpi, struct netbuf *nb);
extern void xml_parser_recv_str(struct xml_parser_t *xpi, const char *str);
extern void xml_parser_reset(struct xml_parser_t *xpi);

/* Internal */
typedef enum {
	XML_PARSER_UTF8 = 0,
	XML_PARSER_UTF16LE,
	XML_PARSER_UTF16BE,
} xml_parser_utf_mode_t;

typedef xml_parser_error_t (*xml_parser_parse_func_t)(struct xml_parser_t *xpi, struct netbuf *nb);

struct xml_parser_t {
	xml_parser_parse_func_t parse_func;
	struct netbuf *partial_nb;
	struct netbuf *output_nb;
	xml_parser_utf_mode_t utf_mode;
	ref_t refs;

	xml_parser_callback_t callback;
	void *callback_arg;
};
