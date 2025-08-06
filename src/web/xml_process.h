/*
 * xml_process.h
 *
 * Copyright © 2019-2024 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * A callback is invoked any time an element is completed that matches the given path.
 *
 * The callback element contains all attributes and sub-elements under that element. The attributes of parent elements can be accessed via
 * the parent property.
 *
 * Once a container has triggered a callback it is deleted.
 * Containers that do not match a callback are deleted.
 */

typedef enum {
	XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS = 0,
	XML_PROCESS_MODE_BUILD_CONTENT = 1,
	XML_PROCESS_MODE_IGNORE_ELEMENT = 2,
} xml_process_mode_t;

struct xml_process_t;

typedef void (*xml_process_callback_t)(void *arg, struct xml_element_t *element);

struct xml_process_callback_entry_t {
	const char *path;
	xml_process_callback_t callback;
};

extern struct xml_process_t *xml_process_alloc(void);
extern struct xml_process_t *xml_process_ref(struct xml_process_t *xpi);
extern ref_t xml_process_deref(struct xml_process_t *xpi);
extern void xml_process_register_callbacks(struct xml_process_t *xpi, const struct xml_process_callback_entry_t callbacks[], void *callback_arg);
extern bool xml_process_recv_netbuf(struct xml_process_t *xpi, struct netbuf *nb);
extern bool xml_process_recv_mem(struct xml_process_t *xpi, uint8_t *ptr, uint8_t *end);
extern bool xml_process_recv_str(struct xml_process_t *xpi, const char *str);
extern bool xml_process_verify_success(struct xml_process_t *xpi);
extern void xml_process_reset(struct xml_process_t *xpi);

/* Internal */
struct xml_process_t {
	struct xml_parser_t *xml_parser;
	ref_t refs;
	bool error;
	struct xml_element_t document;
	struct xml_element_t attributes;
	struct xml_element_t *current_container;
	struct xml_element_t *current_element;
	char element_name[32];
	char attribute_name[32];
	char path[256];

	const struct xml_process_callback_entry_t *callbacks;
	void *callback_arg;
};
