/*
 * xml_process.c
 *
 * Copyright © 2019-2024 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

	xml_element_free_attributes_and_children(&xpi->document);
	xml_element_free_attributes_and_children(&xpi->attributes);
	xml_parser_deref(xpi->xml_parser);
	heap_free(xpi);
	return 0;
}

static bool xml_process_path_push(struct xml_process_t *xpi, const char *name)
{
	char *ptr = strchr(xpi->path, 0);
	char *end = xpi->path + sizeof(xpi->path);
	return sprintf_custom(ptr, end, "|%s", name);
}

static bool xml_process_path_pop(struct xml_process_t *xpi)
{
	char *ptr = strrchr(xpi->path, '|');
	if (!ptr) {
		return false;
	}

	*ptr = 0;
	return true;
}

static xml_process_callback_t xml_process_find_callback(struct xml_process_t *xpi, bool *pdispose)
{
	if (!xpi->callbacks) {
		*pdispose = true;
		return NULL;
	}

	const char *path = xpi->path + 1; /* skip leading '|' */
	const struct xml_process_callback_entry_t *entry = xpi->callbacks;
	while (entry->path) {
		if (strprefixcmp(path, entry->path) == 0) {
			if (strcmp(path, entry->path) == 0) {
				*pdispose = true;
				return entry->callback;
			}

			*pdispose = false;
			return NULL;
		}

		entry++;
	}

	*pdispose = true;
	return NULL;
}

static xml_parser_error_t xml_process_event_element_start_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	if (xpi->element_name[0]) {
		xpi->current_element = xml_element_append_container(xpi->current_container, xpi->element_name);
		if (!xpi->current_element) {
			DEBUG_ERROR("out of memory");
			xpi->error = true;
			return XML_PARSER_ESTOP;
		}

		slist_steal(&xpi->current_element->attributes, &xpi->attributes.attributes);
		xpi->element_name[0] = 0;

		xpi->current_container = xpi->current_element;
		xpi->current_element = NULL;
	}

	size_t name_length = netbuf_get_remaining(nb);
	if (name_length == 0) {
		DEBUG_WARN("element name empty");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}
	if (name_length >= sizeof(xpi->attribute_name)) {
		DEBUG_WARN("element name too long");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	netbuf_fwd_read(nb, xpi->element_name, name_length);
	xpi->element_name[name_length] = 0;

	if (!xml_process_path_push(xpi, xpi->element_name)) {
		DEBUG_WARN("path too long");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_event_element_end_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	if (xpi->element_name[0]) {
		xpi->current_element = xml_element_append_name_value_blank(xpi->current_container, xpi->element_name);
		if (!xpi->current_element) {
			DEBUG_ERROR("out of memory");
			xpi->error = true;
			return XML_PARSER_ESTOP;
		}

		slist_steal(&xpi->current_element->attributes, &xpi->attributes.attributes);
		xpi->element_name[0] = 0;
	}

	struct xml_element_t *callback_element;

	if (xpi->current_element) {
		/* close of a non-container element */
		callback_element = xpi->current_element;
		xpi->current_element = NULL;
	} else {
		/* close of a container - move up one level making its parent the new current */
		callback_element = xpi->current_container;
		xpi->current_container = xpi->current_container->parent;
	}

	bool dispose = false;
	xml_process_callback_t callback = xml_process_find_callback(xpi, &dispose);
	if (callback) {
		xml_process_ref(xpi);
		callback(xpi->callback_arg, callback_element);
		if (xml_process_deref(xpi) <= 0) {
			return XML_PARSER_ESTOP;
		}
	}

	if (!xml_process_path_pop(xpi)) {
		DEBUG_WARN("path error");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	if (dispose) {
		xml_element_detach_from_parent(callback_element);
		xml_element_free(callback_element);
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_event_element_text(struct xml_process_t *xpi, struct netbuf *nb)
{
	DEBUG_ASSERT(xpi->element_name[0], "element state error");

	xpi->current_element = xml_element_append_name_value_nb(xpi->current_container, xpi->element_name, nb);
	if (!xpi->current_element) {
		DEBUG_ERROR("out of memory");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	slist_steal(&xpi->current_element->attributes, &xpi->attributes.attributes);
	xpi->element_name[0] = 0;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_event_attribute_name(struct xml_process_t *xpi, struct netbuf *nb)
{
	DEBUG_ASSERT(xpi->attribute_name[0] == 0, "attribute state error");

	size_t name_length = netbuf_get_remaining(nb);
	if (name_length == 0) {
		DEBUG_WARN("attribute name empty");
		return XML_PARSER_ESTOP;
	}
	if (name_length >= sizeof(xpi->attribute_name)) {
		DEBUG_WARN("attribute name too long");
		return XML_PARSER_ESTOP;
	}

	netbuf_fwd_read(nb, xpi->attribute_name, name_length);
	xpi->attribute_name[name_length] = 0;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_event_attribute_value(struct xml_process_t *xpi, struct netbuf *nb)
{
	DEBUG_ASSERT(xpi->attribute_name[0], "attribute state error");

	if (!xml_element_append_attribute_nb(&xpi->attributes, xpi->attribute_name, nb)) {
		DEBUG_ERROR("out of memory");
		xpi->error = true;
		return XML_PARSER_ESTOP;
	}

	xpi->attribute_name[0] = 0;
	return XML_PARSER_OK;
}

static xml_parser_error_t xml_process_parser_callback(void *arg, xml_parser_event_t xml_event, struct netbuf *nb)
{
	struct xml_process_t *xpi = (struct xml_process_t *)arg;

	switch (xml_event) {
	default:
	case XML_PARSER_EVENT_ELEMENT_START_NAMESPACE:
	case XML_PARSER_EVENT_ELEMENT_END_NAMESPACE:
	case XML_PARSER_EVENT_ATTRIBUTE_NAMESPACE:
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		return xml_process_event_element_start_name(xpi, nb);

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		return xml_process_event_element_end_name(xpi, nb);

	case XML_PARSER_EVENT_ELEMENT_TEXT:
		return xml_process_event_element_text(xpi, nb);

	case XML_PARSER_EVENT_ATTRIBUTE_NAME:
		return xml_process_event_attribute_name(xpi, nb);

	case XML_PARSER_EVENT_ATTRIBUTE_VALUE:
		return xml_process_event_attribute_value(xpi, nb);

	case XML_PARSER_EVENT_PARSE_ERROR:
		DEBUG_WARN("xml parse error");
		xpi->error = true;
		return XML_PARSER_ESTOP;

	case XML_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_WARN("xml internal error");
		xpi->error = true;
		return XML_PARSER_ESTOP;
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
	return !xpi->error && (xpi->current_container == &xpi->document);
}

void xml_process_reset(struct xml_process_t *xpi)
{
	xml_parser_reset(xpi->xml_parser);
	xml_element_free_attributes_and_children(&xpi->document);
	xml_element_free_attributes_and_children(&xpi->attributes);

	xpi->error = false;
	xpi->current_container = &xpi->document;
	xpi->current_element = NULL;
	xpi->element_name[0] = 0;
	xpi->attribute_name[0] = 0;
	xpi->path[0] = 0;
}

void xml_process_register_callbacks(struct xml_process_t *xpi, const struct xml_process_callback_entry_t callbacks[], void *callback_arg)
{
	xpi->callbacks = callbacks;
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

	xpi->current_container = &xpi->document;
	xpi->refs = 1;
	return xpi;
}
