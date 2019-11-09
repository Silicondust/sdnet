/*
 * xml_process.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Simple XML elements are delivered using the completed_element callback. The content list includes all attributes of the element as well as the value.
 * To find the value lookup "" (empty string) in the contents list.
 *
 * XML elements containing other elements are first notified using the open_element callback. The contents list includes the attributes of the element.
 * If the application returns XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS callbacks continue to be invoked for each sub-element. The completed_element callback does not return content.
 * If the application returns XML_PROCESS_MODE_BUILD_CONTENT the sub-elements are processed without callbacks. The completed_element callback provides the full contents of the element.
 * If the application returns XML_PROCESS_MODE_IGNORE_ELEMENT the sub-elements are ignored and the completed_element callback is not invoked.
 */

typedef enum {
	XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS = 0,
	XML_PROCESS_MODE_BUILD_CONTENT = 1,
	XML_PROCESS_MODE_IGNORE_ELEMENT = 2,
} xml_process_mode_t;

struct xml_process_t;

typedef xml_process_mode_t (*xml_process_open_element_callback_t)(void *arg, const char *path, struct slist_t *contents);
typedef void (*xml_process_completed_element_callback_t)(void *arg, const char *path, struct slist_t *contents);

extern struct xml_process_t *xml_process_alloc(void);
extern struct xml_process_t *xml_process_ref(struct xml_process_t *xpi);
extern ref_t xml_process_deref(struct xml_process_t *xpi);
extern void xml_process_register_callbacks(struct xml_process_t *xpi, xml_process_open_element_callback_t open_element_callback, xml_process_completed_element_callback_t completed_element_callback, void *callback_arg);
extern bool xml_process_recv_netbuf(struct xml_process_t *xpi, struct netbuf *nb);
extern bool xml_process_recv_mem(struct xml_process_t *xpi, uint8_t *ptr, uint8_t *end);
extern bool xml_process_recv_str(struct xml_process_t *xpi, const char *str);
extern bool xml_process_verify_success(struct xml_process_t *xpi);
extern void xml_process_reset(struct xml_process_t *xpi);
extern void xml_process_debug_print(const char *this_file, int line, const char *prefix, const char *path, struct slist_t *contents);

#define DEBUG_PRINT_XML_PROCESS(prefix, path, contents) \
{ \
	if (RUNTIME_DEBUG) { \
		xml_process_debug_print(__this_file, __LINE__, prefix, path, contents); \
	} \
}

/* Internal */
struct xml_process_t {
	struct xml_parser_t *xml_parser;
	ref_t refs;

	xml_process_mode_t mode;
	bool error;
	bool element_found;
	struct slist_t contents;
	char path[256];
	char *path_match_ptr;

	xml_process_open_element_callback_t open_element_callback;
	xml_process_completed_element_callback_t completed_element_callback;
	void *callback_arg;
};
