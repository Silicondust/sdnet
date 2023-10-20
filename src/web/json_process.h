/*
 * json_process.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Simple JSON elements are delivered using the completed_element callback. To find the value lookup "" (empty string) in the contents list.
 *
 * JSON elements containing other elements are first notified using the open_element callback.
 * If the application returns JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS callbacks continue to be invoked for each sub-element. The completed_element callback does not return content.
 * If the application returns JSON_PROCESS_MODE_BUILD_CONTENT the sub-elements are processed without callbacks. The completed_element callback provides the full contents of the element.
 * If the application returns JSON_PROCESS_MODE_IGNORE_ELEMENT the sub-elements are ignored and the completed_element callback is not invoked.
 */

typedef enum {
	JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS = 0,
	JSON_PROCESS_MODE_BUILD_CONTENT = 1,
	JSON_PROCESS_MODE_IGNORE_ELEMENT = 2,
} json_process_mode_t;

struct json_process_t;

typedef json_process_mode_t (*json_process_open_element_callback_t)(void *arg, const char *path);
typedef void (*json_process_completed_element_callback_t)(void *arg, const char *path, struct slist_t *contents);

extern struct json_process_t *json_process_alloc(void);
extern struct json_process_t *json_process_ref(struct json_process_t *jpi);
extern ref_t json_process_deref(struct json_process_t *jpi);
extern void json_process_register_callbacks(struct json_process_t *jpi, json_process_open_element_callback_t open_element_callback, json_process_completed_element_callback_t completed_element_callback, void *callback_arg);
extern bool json_process_recv_netbuf(struct json_process_t *jpi, struct netbuf *nb);
extern bool json_process_recv_mem(struct json_process_t *jpi, uint8_t *ptr, uint8_t *end);
extern bool json_process_recv_str(struct json_process_t *jpi, const char *str);
extern bool json_process_verify_success(struct json_process_t *jpi);
extern void json_process_reset(struct json_process_t *jpi);
extern void json_process_debug_print(const char *this_file, int line, const char *prefix, const char *path, struct slist_t *contents);

#define DEBUG_PRINT_JSON_PROCESS(prefix, path, contents) \
{ \
	if (RUNTIME_DEBUG) { \
		json_process_debug_print(__this_file, __LINE__, prefix, path, contents); \
	} \
}

/* Internal */
struct json_process_t {
	struct json_parser_t *json_parser;
	ref_t refs;

	json_process_mode_t mode;
	uint32_t next_array_index;
	bool error;
	struct slist_t contents;
	char path[256];
	char *path_match_ptr;

	json_process_open_element_callback_t open_element_callback;
	json_process_completed_element_callback_t completed_element_callback;
	void *callback_arg;
};
