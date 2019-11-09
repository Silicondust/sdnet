/*
 * json_process.c
 *
 * Copyright © 2015-2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("json_process");

struct json_process_t *json_process_ref(struct json_process_t *jpi)
{
	jpi->refs++;
	return jpi;
}

ref_t json_process_deref(struct json_process_t *jpi)
{
	jpi->refs--;
	if (jpi->refs != 0) {
		return jpi->refs;
	}

	json_parser_deref(jpi->json_parser);
	heap_free(jpi);
	return 0;
}

void json_process_debug_print(const char *this_file, int line, const char *prefix, const char *path, struct slist_t *contents)
{
	debug_printf(this_file, line, "%s %s", prefix, path);

	struct nvlist_entry_t *entry = slist_get_head(struct nvlist_entry_t, contents);
	while (entry) {
		if (entry->value_str) {
			debug_printf(this_file, line, "\t%s=%s", entry->name, entry->value_str);
		} else {
			debug_printf(this_file, line, "\t%s=%lld", entry->name, entry->value_int64);
		}

		entry = slist_get_next(struct nvlist_entry_t, entry);
	}
}

static void json_process_autodetect_set_value(struct json_process_t *jpi, const char *name, struct netbuf *nb)
{
	size_t length = netbuf_get_remaining(nb);
	if (length == 0) {
		nvlist_set_str(&jpi->contents, name, "");
		return;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	if (c == '0') {
		if (length > 1) {
			netbuf_set_pos_to_start(nb);
			nvlist_set_str_nb(&jpi->contents, name, nb);
		}

		nvlist_set_int64(&jpi->contents, name, 0);
		return;
	}

	if (c == '-') {
		if (length == 1) {
			netbuf_set_pos_to_start(nb);
			nvlist_set_str_nb(&jpi->contents, name, nb);
			return;
		}

		c = netbuf_fwd_read_u8(nb);
	}

	netbuf_set_pos_to_start(nb);

	if ((c >= '1') && (c <= '9')) {
		addr_t end;
		int64_t value = netbuf_fwd_strtoll(nb, &end, 10);
		if (end != netbuf_get_end(nb)) {
			nvlist_set_str_nb(&jpi->contents, name, nb);
			return;
		}

		nvlist_set_int64(&jpi->contents, name, value);
		return;
	}

	nvlist_set_str_nb(&jpi->contents, name, nb);
}

static json_parser_error_t json_parser_apply_group_start(struct json_process_t *jpi, char tag, struct netbuf *nb)
{
	char *ptr = strchr(jpi->path, 0);
	char *end = jpi->path + sizeof(jpi->path);

	size_t name_length = netbuf_get_remaining(nb);
	if (ptr + name_length + 2 >= end) {
		DEBUG_WARN("path too long");
		jpi->error = true;
		return JSON_PARSER_ESTOP;
	}

	if (name_length > 0) {
		netbuf_fwd_read(nb, ptr, name_length);
		ptr += name_length;
	}

	*ptr++ = tag;
	*ptr = 0;

	if (jpi->mode == JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS) {
		if (jpi->open_element_callback) {
			json_process_ref(jpi);
			jpi->mode = jpi->open_element_callback(jpi->callback_arg, jpi->path);
			if (json_process_deref(jpi) <= 0) {
				return JSON_PARSER_ESTOP;
			}
		}

		switch (jpi->mode) {
		case JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS:
			nvlist_clear_all(&jpi->contents);
			break;

		case JSON_PROCESS_MODE_BUILD_CONTENT:
			jpi->path_match_ptr = ptr;
			break;

		case JSON_PROCESS_MODE_IGNORE_ELEMENT:
			nvlist_clear_all(&jpi->contents);
			jpi->path_match_ptr = ptr;
			break;
		}
	}

	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_apply_end_notify(struct json_process_t *jpi, char *ptr)
{
	switch (jpi->mode) {
	case JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS:
		if (jpi->completed_element_callback) {
			json_process_ref(jpi);
			jpi->completed_element_callback(jpi->callback_arg, jpi->path, &jpi->contents);
			if (json_process_deref(jpi) <= 0) {
				return JSON_PARSER_ESTOP;
			}
		}

		nvlist_clear_all(&jpi->contents);
		return JSON_PARSER_OK;

	case JSON_PROCESS_MODE_BUILD_CONTENT:
		if (ptr < jpi->path_match_ptr) {
			if (jpi->completed_element_callback) {
				json_process_ref(jpi);
				jpi->completed_element_callback(jpi->callback_arg, jpi->path, &jpi->contents);
				if (json_process_deref(jpi) <= 0) {
					return JSON_PARSER_ESTOP;
				}
			}

			jpi->mode = JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
			jpi->path_match_ptr = NULL;
			nvlist_clear_all(&jpi->contents);
		}

		return JSON_PARSER_OK;

	case JSON_PROCESS_MODE_IGNORE_ELEMENT:
		if (ptr < jpi->path_match_ptr) {
			jpi->mode = JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
			jpi->path_match_ptr = NULL;
			nvlist_clear_all(&jpi->contents);
		}

		return JSON_PARSER_OK;

	default:
		return JSON_PARSER_OK;
	}
}

static json_parser_error_t json_parser_apply_group_end(struct json_process_t *jpi, char tag)
{
	char *ptr = strchr(jpi->path, 0);

	ptr--;
	if (ptr < jpi->path) {
		DEBUG_WARN("close '%x' doesn't match path %s", tag, jpi->path);
		jpi->error = true;
		return JSON_PARSER_ESTOP;
	}
	if (*ptr != tag) {
		DEBUG_WARN("close '%x' doesn't match path %s", tag, jpi->path);
		jpi->error = true;
		return JSON_PARSER_ESTOP;
	}

	while (ptr > jpi->path) {
		ptr--;
		if ((*ptr == '{') || (*ptr == '[')) {
			ptr++;
			break;
		}
	}

	json_parser_error_t ret = json_parser_apply_end_notify(jpi, ptr);
	if (ret != JSON_PARSER_OK) {
		return ret;
	}

	*ptr = 0;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_apply_element_name(struct json_process_t *jpi, struct netbuf *nb)
{
	char *ptr = strchr(jpi->path, 0);
	char *end = jpi->path + sizeof(jpi->path);

	size_t name_length = netbuf_get_remaining(nb);
	if (ptr + name_length + 1 >= end) {
		DEBUG_WARN("path too long");
		jpi->error = true;
		return JSON_PARSER_ESTOP;
	}

	if (name_length > 0) {
		netbuf_fwd_read(nb, ptr, name_length);
		ptr += name_length;
	}

	*ptr = 0;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_apply_element_value_str(struct json_process_t *jpi, struct netbuf *nb)
{
	if (jpi->mode != JSON_PROCESS_MODE_IGNORE_ELEMENT) {
		const char *name = (jpi->path_match_ptr) ? jpi->path_match_ptr : "";
		nvlist_set_str_nb(&jpi->contents, name, nb);
	}

	char *ptr = strchr(jpi->path, 0);
	while (ptr > jpi->path) {
		ptr--;
		if ((*ptr == '{') || (*ptr == '[')) {
			ptr++;
			break;
		}
	}

	json_parser_error_t ret = json_parser_apply_end_notify(jpi, ptr);
	if (ret != JSON_PARSER_OK) {
		return ret;
	}

	*ptr = 0;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_parser_apply_element_value_unquoted(struct json_process_t *jpi, struct netbuf *nb)
{
	if (jpi->mode != JSON_PROCESS_MODE_IGNORE_ELEMENT) {
		const char *name = (jpi->path_match_ptr) ? jpi->path_match_ptr : "";
		json_process_autodetect_set_value(jpi, name, nb);
	}

	char *ptr = strchr(jpi->path, 0);
	while (ptr > jpi->path) {
		ptr--;
		if ((*ptr == '{') || (*ptr == '[')) {
			ptr++;
			break;
		}
	}

	json_parser_error_t ret = json_parser_apply_end_notify(jpi, ptr);
	if (ret != JSON_PARSER_OK) {
		return ret;
	}

	*ptr = 0;
	return JSON_PARSER_OK;
}

static json_parser_error_t json_process_parser_callback(void *arg, json_parser_event_t json_event, struct netbuf *nb)
{
	struct json_process_t *jpi = (struct json_process_t *)arg;

	switch (json_event) {
	case JSON_PARSER_EVENT_ARRAY_START:
		return json_parser_apply_group_start(jpi, '[', nb);

	case JSON_PARSER_EVENT_ARRAY_END:
		return json_parser_apply_group_end(jpi, '[');

	case JSON_PARSER_EVENT_OBJECT_START:
		return json_parser_apply_group_start(jpi, '{', nb);

	case JSON_PARSER_EVENT_OBJECT_END:
		return json_parser_apply_group_end(jpi, '{');

	case JSON_PARSER_EVENT_ELEMENT_NAME:
		return json_parser_apply_element_name(jpi, nb);

	case JSON_PARSER_EVENT_ELEMENT_VALUE_STR:
		return json_parser_apply_element_value_str(jpi, nb);

	case JSON_PARSER_EVENT_ELEMENT_VALUE_UNQUOTED:
		return json_parser_apply_element_value_unquoted(jpi, nb);

	case JSON_PARSER_EVENT_PARSE_ERROR:
		DEBUG_WARN("json parse error");
		jpi->error = true;
		return JSON_PARSER_ESTOP;

	case JSON_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_WARN("json internal error");
		jpi->error = true;
		return JSON_PARSER_ESTOP;

	default:
		return JSON_PARSER_OK;
	}
}

bool json_process_recv_netbuf(struct json_process_t *jpi, struct netbuf *nb)
{
	return json_parser_recv_netbuf(jpi->json_parser, nb);
}

bool json_process_recv_mem(struct json_process_t *jpi, uint8_t *ptr, uint8_t *end)
{
	return json_parser_recv_mem(jpi->json_parser, ptr, end);
}

bool json_process_recv_str(struct json_process_t *jpi, const char *str)
{
	return json_parser_recv_str(jpi->json_parser, str);
}

bool json_process_verify_success(struct json_process_t *jpi)
{
	return !jpi->error && (jpi->path[0] == 0);
}

void json_process_reset(struct json_process_t *jpi)
{
	json_parser_reset(jpi->json_parser);
	nvlist_clear_all(&jpi->contents);

	jpi->mode = JSON_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
	jpi->error = false;
	jpi->path[0] = 0;
	jpi->path_match_ptr = NULL;
}

void json_process_register_callbacks(struct json_process_t *jpi, json_process_open_element_callback_t open_element_callback, json_process_completed_element_callback_t completed_element_callback, void *callback_arg)
{
	jpi->open_element_callback = open_element_callback;
	jpi->completed_element_callback = completed_element_callback;
	jpi->callback_arg = callback_arg;
}

struct json_process_t *json_process_alloc(void)
{
	struct json_process_t *jpi = (struct json_process_t *)heap_alloc_and_zero(sizeof(struct json_process_t), PKG_OS, MEM_TYPE_OS_JSON_PROCESS);
	if (!jpi) {
		return NULL;
	}

	jpi->json_parser = json_parser_alloc(json_process_parser_callback, jpi);
	if (!jpi->json_parser) {
		heap_free(jpi);
		return NULL;
	}

	jpi->refs = 1;
	return jpi;
}
