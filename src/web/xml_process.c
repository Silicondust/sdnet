/*
 * xml_process.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("xml_process");

struct xml_process_t *xml_process_ref(struct xml_process_t *xpi)
{
	xpi->refs++;
	return xpi;
}

ref_t xml_process_deref(struct xml_process_t *xpi)
{
	xpi->refs--;
	if (xpi->refs != 0) {
		return xpi->refs;
	}

	xml_parser_deref(xpi->xml_parser);
	heap_free(xpi);
	return 0;
}

void xml_process_debug_print(const char *this_file, int line, const char *prefix, const char *path, struct slist_t *contents)
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

static void xml_process_autodetect_set_value(struct xml_process_t *xpi, const char *name, struct netbuf *nb)
{
	size_t length = netbuf_get_remaining(nb);
	if (length == 0) {
		nvlist_set_str(&xpi->contents, name, "");
		return;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	if (c == '0') {
		if (length > 1) {
			netbuf_set_pos_to_start(nb);
			nvlist_set_str_nb(&xpi->contents, name, nb);
		}

		nvlist_set_int64(&xpi->contents, name, 0);
		return;
	}

	if (c == '-') {
		if (length == 1) {
			netbuf_set_pos_to_start(nb);
			nvlist_set_str_nb(&xpi->contents, name, nb);
			return;
		}

		c = netbuf_fwd_read_u8(nb);
	}

	netbuf_set_pos_to_start(nb);

	if ((c >= '1') && (c <= '9')) {
		addr_t end;
		int64_t value = netbuf_fwd_strtoll(nb, &end, 10);
		if (end != netbuf_get_end(nb)) {
			nvlist_set_str_nb(&xpi->contents, name, nb);
			return;
		}

		nvlist_set_int64(&xpi->contents, name, value);
		return;
	}

	nvlist_set_str_nb(&xpi->contents, name, nb);
}

static xml_parser_error_t xml_process_apply_element_start_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	char *ptr = strchr(xpi->path, 0);
	char *end = xpi->path + sizeof(xpi->path);

	if ((xpi->mode == XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS) && xpi->element_found) {
		if (xpi->open_element_callback) {
			xml_process_ref(xpi);
			xpi->mode = xpi->open_element_callback(xpi->callback_arg, xpi->path, &xpi->contents);
			if (xml_process_deref(xpi) <= 0) {
				return XML_PARSER_ESTOP;
			}
		}

		switch (xpi->mode) {
		case XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS:
			nvlist_clear_all(&xpi->contents);
			break;

		case XML_PROCESS_MODE_BUILD_CONTENT:
			xpi->path_match_ptr = ptr;
			break;

		case XML_PROCESS_MODE_IGNORE_ELEMENT:
			nvlist_clear_all(&xpi->contents);
			xpi->path_match_ptr = ptr;
			break;
		}
	}

	size_t name_length = netbuf_get_remaining(nb);
	if (name_length == 0) {
		DEBUG_WARN("empty name");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (ptr + name_length + 2 >= end) {
		DEBUG_WARN("path too long");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (ptr > xpi->path) {
		*ptr++ = '|';
	}

	netbuf_fwd_read(nb, ptr, name_length);
	ptr[name_length] = 0;

	xpi->element_found = true;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_apply_element_end_notify(struct xml_process_t *xpi, char *ptr)
{
	switch (xpi->mode) {
	case XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS:
		if (xpi->completed_element_callback) {
			xml_process_ref(xpi);
			xpi->completed_element_callback(xpi->callback_arg, xpi->path, &xpi->contents);
			if (xml_process_deref(xpi) <= 0) {
				return XML_PARSER_ESTOP;
			}
		}

		nvlist_clear_all(&xpi->contents);
		return XML_PARSER_OK;

	case XML_PROCESS_MODE_BUILD_CONTENT:
		if (ptr < xpi->path_match_ptr) {
			if (xpi->completed_element_callback) {
				xml_process_ref(xpi);
				xpi->completed_element_callback(xpi->callback_arg, xpi->path, &xpi->contents);
				if (xml_process_deref(xpi) <= 0) {
					return XML_PARSER_ESTOP;
				}
			}

			xpi->mode = XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
			xpi->path_match_ptr = NULL;
			nvlist_clear_all(&xpi->contents);
		}

		return XML_PARSER_OK;

	case XML_PROCESS_MODE_IGNORE_ELEMENT:
		if (ptr < xpi->path_match_ptr) {
			xpi->mode = XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
			xpi->path_match_ptr = NULL;
			nvlist_clear_all(&xpi->contents);
		}

		return XML_PARSER_OK;

	default:
		return XML_PARSER_OK;
	}
}

static xml_parser_error_t xml_process_apply_element_end_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	size_t name_length = netbuf_get_remaining(nb);
	if (name_length == 0) {
		DEBUG_WARN("empty name");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	char *end = strchr(xpi->path, 0);
	char *ptr = end - name_length;
	if (ptr < xpi->path) {
		DEBUG_WARN("close miss-match: %s", xpi->path);
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (netbuf_fwd_memcmp(nb, ptr, name_length) != 0) {
		DEBUG_WARN("close miss-match: %s", xpi->path);
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (ptr > xpi->path) {
		ptr--;
		if (*ptr != '|') {
			DEBUG_WARN("close miss-match: %s", xpi->path);
			xpi->error = true;
			return XML_PARSER_ESTOP;
		}
	}

	xml_parser_error_t ret = xml_process_apply_element_end_notify(xpi, ptr);
	if (ret != XML_PARSER_OK) {
		return ret;
	}

	*ptr = 0;
	xpi->element_found = false;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_apply_element_self_close(struct xml_process_t *xpi)
{
	char *ptr = strrchr(xpi->path, '|');
	if (!ptr) {
		ptr = xpi->path;
	}

	if (xpi->mode != XML_PROCESS_MODE_IGNORE_ELEMENT) {
		const char *name = (xpi->path_match_ptr) ? xpi->path_match_ptr + 1 : "";
		nvlist_set_str(&xpi->contents, name, "");
	}

	xml_parser_error_t ret = xml_process_apply_element_end_notify(xpi, ptr);
	if (ret != XML_PARSER_OK) {
		return ret;
	}

	*ptr = 0;
	xpi->element_found = false;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_apply_element_text(struct xml_process_t *xpi, struct netbuf *nb)
{
	if (xpi->mode != XML_PROCESS_MODE_IGNORE_ELEMENT) {
		const char *name = (xpi->path_match_ptr) ? xpi->path_match_ptr + 1 : "";
		xml_process_autodetect_set_value(xpi, name, nb);
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_apply_attribute_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	size_t name_length = netbuf_get_remaining(nb);
	if (name_length == 0) {
		DEBUG_WARN("empty name");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	char *ptr = strchr(xpi->path, 0);
	char *end = xpi->path + sizeof(xpi->path);

	if (ptr + name_length + 3 >= end) {
		DEBUG_WARN("path too long");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	*ptr++ = '|';
	*ptr++ = '@';

	netbuf_fwd_read(nb, ptr, name_length);
	ptr[name_length] = 0;

	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_apply_attribute_value(struct xml_process_t *xpi, struct netbuf *nb)
{
	char *ptr = strrchr(xpi->path, '|');
	if (!ptr) {
		DEBUG_WARN("path error");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (xpi->mode != XML_PROCESS_MODE_IGNORE_ELEMENT) {
		const char *name = (xpi->path_match_ptr) ? xpi->path_match_ptr + 1 : ptr + 1;
		xml_process_autodetect_set_value(xpi, name, nb);
	}

	*ptr = 0;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_parser_callback(void *arg, xml_parser_event_t xml_event, struct netbuf *nb)
{
	struct xml_process_t *xpi = (struct xml_process_t *)arg;

	switch (xml_event) {
	case XML_PARSER_EVENT_ELEMENT_START_NAMESPACE:
	case XML_PARSER_EVENT_ELEMENT_END_NAMESPACE:
	case XML_PARSER_EVENT_ATTRIBUTE_NAMESPACE:
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		return xml_process_apply_element_start_name(xpi, nb);

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
		return xml_process_apply_element_end_name(xpi, nb);

	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		return xml_process_apply_element_self_close(xpi);

	case XML_PARSER_EVENT_ELEMENT_TEXT:
		return xml_process_apply_element_text(xpi, nb);

	case XML_PARSER_EVENT_ATTRIBUTE_NAME:
		return xml_process_apply_attribute_name(xpi, nb);

	case XML_PARSER_EVENT_ATTRIBUTE_VALUE:
		return xml_process_apply_attribute_value(xpi, nb);

	case XML_PARSER_EVENT_PARSE_ERROR:
		DEBUG_WARN("xml parse error");
		xpi->error = true;
		return XML_PARSER_ESTOP;

	case XML_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_WARN("xml internal error");
		xpi->error = true;
		return XML_PARSER_ESTOP;

	default:
		return XML_PARSER_OK;
	}
}

bool xml_process_recv_netbuf(struct xml_process_t *xpi, struct netbuf *nb)
{
	return xml_parser_recv_netbuf(xpi->xml_parser, nb);
}

bool xml_process_recv_mem(struct xml_process_t *xpi, uint8_t *ptr, uint8_t *end)
{
	return xml_parser_recv_mem(xpi->xml_parser, ptr, end);
}

bool xml_process_recv_str(struct xml_process_t *xpi, const char *str)
{
	return xml_parser_recv_str(xpi->xml_parser, str);
}

bool xml_process_verify_success(struct xml_process_t *xpi)
{
	return !xpi->error && (xpi->path[0] == 0);
}

void xml_process_reset(struct xml_process_t *xpi)
{
	xml_parser_reset(xpi->xml_parser);
	nvlist_clear_all(&xpi->contents);

	xpi->mode = XML_PROCESS_MODE_CALLBACK_SUB_ELEMENTS;
	xpi->error = false;
	xpi->element_found = false;
	xpi->path[0] = 0;
	xpi->path_match_ptr = NULL;
}

void xml_process_register_callbacks(struct xml_process_t *xpi, xml_process_open_element_callback_t open_element_callback, xml_process_completed_element_callback_t completed_element_callback, void *callback_arg)
{
	xpi->open_element_callback = open_element_callback;
	xpi->completed_element_callback = completed_element_callback;
	xpi->callback_arg = callback_arg;
}

struct xml_process_t *xml_process_alloc(void)
{
	struct xml_process_t *xpi = (struct xml_process_t *)heap_alloc_and_zero(sizeof(struct xml_process_t), PKG_OS, MEM_TYPE_OS_XML_PROCESS);
	if (!xpi) {
		return NULL;
	}

	xpi->xml_parser = xml_parser_alloc(xml_process_parser_callback, xpi);
	if (!xpi->xml_parser) {
		heap_free(xpi);
		return NULL;
	}

	xpi->refs = 1;
	return xpi;
}
