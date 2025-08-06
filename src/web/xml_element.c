/*
 * xml_element.c
 *
 * Copyright © 2024 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("nvtree");

#if (RUNTIME_DEBUG)
static void xml_element_debug_print_internal(struct xml_element_t *element, const char *indent)
{
	if (element->value) {
		DEBUG_INFO("%s%s=%s", indent, element->name, element->value);
	} else {
		DEBUG_INFO("%s%s:", indent, element->name);
	}

	struct xml_attribute_t *attribute = slist_get_head(struct xml_attribute_t, &element->attributes);
	struct xml_element_t *child = slist_get_head(struct xml_element_t, &element->children);
	if (!attribute && !child) {
		return;
	}

	size_t child_level = strlen(indent) + 1;
	if (child_level > 15) {
		child_level = 15;
	}

	char child_indent[16];
	memset(child_indent, '\t', child_level);
	child_indent[child_level] = 0;

	while (attribute) {
		DEBUG_INFO("%s@%s=%s", child_indent, attribute->name, attribute->value);
		attribute = slist_get_next(struct xml_attribute_t, attribute);
	}

	while (child) {
		xml_element_debug_print_internal(child, child_indent);
		child = slist_get_next(struct xml_element_t, child);
	}
}

void xml_element_debug_print(struct xml_element_t *element)
{
	xml_element_debug_print_internal(element, "");
}
#endif

void xml_element_free(struct xml_element_t *element)
{
	slist_clear(struct xml_attribute_t, &element->attributes, heap_free);
	slist_clear(struct xml_element_t, &element->children, xml_element_free);
	heap_free(element);
}

void xml_element_free_attributes_and_children(struct xml_element_t *element)
{
	slist_clear(struct xml_attribute_t, &element->attributes, heap_free);
	slist_clear(struct xml_element_t, &element->children, xml_element_free);
}

void xml_element_detach_from_parent(struct xml_element_t *element)
{
	struct xml_element_t *parent = element->parent;
	(void)slist_detach_item(struct xml_element_t, &parent->children, element);
}

const char *xml_element_get_value(struct xml_element_t *element, const char *value_on_error)
{
	if (!element->value) {
		return value_on_error;
	}

	return element->value;
}

int64_t xml_element_get_int64(struct xml_element_t *element, int64_t value_on_error)
{
	if (!element->value) {
		return value_on_error;
	}

	char *end;
	int64_t result = strtoll(element->value, &end, 10);
	if (*end != 0) {
		return value_on_error;
	}

	return result;
}

bool xml_element_get_bool(struct xml_element_t *element)
{
	if (!element->value) {
		return false;
	}

	if (strcmp(element->value, "1") == 0) {
		return true;
	}
	if (strcasecmp(element->value, "true") == 0) {
		return true;
	}

	return false;
}

struct xml_element_t *xml_element_get_parent(struct xml_element_t *element)
{
	return element->parent;
}

struct xml_element_t *xml_element_get_child_first(struct xml_element_t *parent)
{
	return slist_get_head(struct xml_element_t, &parent->children);
}

struct xml_element_t *xml_element_get_child_next(struct xml_element_t *prev)
{
	return slist_get_next(struct xml_element_t, prev);
}

struct xml_element_t *xml_element_get_child_by_name(struct xml_element_t *parent, const char *name)
{
	struct xml_element_t *element = slist_get_head(struct xml_element_t, &parent->children);
	while (element) {
		if (strcmp(name, element->name) == 0) {
			return element;
		}

		element = slist_get_next(struct xml_element_t, element);
	}

	return NULL;
}

struct xml_element_t *xml_element_get_child_by_name_next(struct xml_element_t *prev)
{
	struct xml_element_t *element = slist_get_next(struct xml_element_t, prev);
	while (element) {
		if (strcmp(prev->name, element->name) == 0) {
			return element;
		}

		element = slist_get_next(struct xml_element_t, element);
	}

	return NULL;
}

const char *xml_element_get_child_value(struct xml_element_t *parent, const char *name, const char *value_on_error)
{
	struct xml_element_t *element = xml_element_get_child_by_name(parent, name);
	if (!element) {
		return value_on_error;
	}
	if (!element->value) {
		return value_on_error;
	}

	return element->value;
}

int64_t xml_element_get_child_int64(struct xml_element_t *parent, const char *name, int64_t value_on_error)
{
	const char *value = xml_element_get_child_value(parent, name, NULL);
	if (!value) {
		return value_on_error;
	}

	char *end;
	int64_t result = strtoll(value, &end, 10);
	if (*end != 0) {
		return value_on_error;
	}

	return result;
}

bool xml_element_get_child_bool(struct xml_element_t *parent, const char *name)
{
	const char *value = xml_element_get_child_value(parent, name, NULL);
	if (!value) {
		return false;
	}

	if (strcmp(value, "1") == 0) {
		return true;
	}
	if (strcasecmp(value, "true") == 0) {
		return true;
	}

	return false;
}

static struct xml_attribute_t *xml_element_get_attribute(struct xml_element_t *element, const char *name)
{
	struct xml_attribute_t *attribute = slist_get_head(struct xml_attribute_t, &element->attributes);
	while (attribute) {
		if (strcmp(name, attribute->name) == 0) {
			return attribute;
		}

		attribute = slist_get_next(struct xml_attribute_t, attribute);
	}

	return NULL;
}

const char *xml_element_get_attribute_value(struct xml_element_t *element, const char *name, const char *value_on_error)
{
	struct xml_attribute_t *attribute = xml_element_get_attribute(element, name);
	if (!attribute) {
		return value_on_error;
	}

	return attribute->value;
}

int64_t xml_element_get_attribute_int64(struct xml_element_t *element, const char *name, int64_t value_on_error)
{
	struct xml_attribute_t *attribute = xml_element_get_attribute(element, name);
	if (!attribute) {
		return value_on_error;
	}

	char *end;
	int64_t result = strtoll(attribute->value, &end, 10);
	if (*end != 0) {
		return value_on_error;
	}

	return result;
}

bool xml_element_get_attribute_bool_strong(struct xml_element_t *element, const char *name)
{
	struct xml_attribute_t *attribute = xml_element_get_attribute(element, name);
	if (!attribute) {
		return false;
	}

	if (strcmp(attribute->value, "1") == 0) {
		return true;
	}
	if (strcasecmp(attribute->value, "true") == 0) {
		return true;
	}
	
	return false;
}

struct xml_element_t *xml_element_append_container(struct xml_element_t *parent, const char *name)
{
	DEBUG_ASSERT(!parent->value, "cannot append child to an element with a value");

	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;

	struct xml_element_t *element = (struct xml_element_t *)heap_alloc_and_zero(sizeof(struct xml_element_t) + name_space, PKG_OS, MEM_TYPE_OS_XML_ELEMENT);
	if (!element) {
		return NULL;
	}

	element->name = (char *)(element + 1);
	memcpy(element->name, name, name_len + 1);

	element->parent = parent;
	slist_attach_tail(struct xml_element_t, &parent->children, element);
	return element;
}

struct xml_element_t *xml_element_append_name_value(struct xml_element_t *parent, const char *name, const char *value)
{
	uint8_t *ptr = (uint8_t *)value;
	uint8_t *end = ptr + strlen(value);
	return xml_element_append_name_value_mem(parent, name, ptr, end);
}

struct xml_element_t *xml_element_append_name_value_mem(struct xml_element_t *parent, const char *name, uint8_t *ptr, uint8_t *end)
{
	DEBUG_ASSERT(!parent->value, "cannot append child to an element with a value");

	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = end - ptr;
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct xml_element_t *element = (struct xml_element_t *)heap_alloc_and_zero(sizeof(struct xml_element_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_XML_ELEMENT);
	if (!element) {
		return NULL;
	}

	element->name = (char *)(element + 1);
	memcpy(element->name, name, name_len + 1);

	element->value = element->name + name_space;
	if (value_len > 0) {
		memcpy(element->value, ptr, value_len);
	}
	element->value[value_len] = 0;

	element->parent = parent;
	slist_attach_tail(struct xml_element_t, &parent->children, element);
	return element;
}

struct xml_element_t *xml_element_append_name_value_nb(struct xml_element_t *parent, const char *name, struct netbuf *nb)
{
	DEBUG_ASSERT(!parent->value, "cannot append child to an element with a value");

	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = netbuf_get_remaining(nb);
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct xml_element_t *element = (struct xml_element_t *)heap_alloc_and_zero(sizeof(struct xml_element_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_XML_ELEMENT);
	if (!element) {
		return NULL;
	}

	element->name = (char *)(element + 1);
	memcpy(element->name, name, name_len + 1);

	element->value = element->name + name_space;
	if (value_len > 0) {
		netbuf_fwd_read(nb, element->value, value_len);
	}
	element->value[value_len] = 0;

	element->parent = parent;
	slist_attach_tail(struct xml_element_t, &parent->children, element);
	return element;
}

struct xml_element_t *xml_element_append_name_value_blank(struct xml_element_t *parent, const char *name)
{
	return xml_element_append_name_value_mem(parent, name, NULL, NULL);
}

bool xml_element_append_attribute(struct xml_element_t *element, const char *name, const char *value)
{
	uint8_t *ptr = (uint8_t *)value;
	uint8_t *end = ptr + strlen(value);
	return xml_element_append_attribute_mem(element, name, ptr, end);
}

bool xml_element_append_attribute_mem(struct xml_element_t *element, const char *name, uint8_t *ptr, uint8_t *end)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = end - ptr;
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct xml_attribute_t *attribute = (struct xml_attribute_t *)heap_alloc_and_zero(sizeof(struct xml_attribute_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_XML_ATTRIBUTE);
	if (!attribute) {
		return false;
	}

	attribute->name = (char *)(attribute + 1);
	memcpy(attribute->name, name, name_len + 1);

	attribute->value = attribute->name + name_space;
	if (value_len > 0) {
		memcpy(attribute->value, ptr, value_len);
	}
	attribute->value[value_len] = 0;

	slist_attach_tail(struct xml_attribute_t, &element->attributes, attribute);
	return true;
}

bool xml_element_append_attribute_nb(struct xml_element_t *element, const char *name, struct netbuf *nb)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = netbuf_get_remaining(nb);
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct xml_attribute_t *attribute = (struct xml_attribute_t *)heap_alloc_and_zero(sizeof(struct xml_attribute_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_XML_ATTRIBUTE);
	if (!attribute) {
		return false;
	}

	attribute->name = (char *)(attribute + 1);
	memcpy(attribute->name, name, name_len + 1);

	attribute->value = attribute->name + name_space;
	if (value_len > 0) {
		netbuf_fwd_read(nb, attribute->value, value_len);
	}
	attribute->value[value_len] = 0;

	slist_attach_tail(struct xml_attribute_t, &element->attributes, attribute);
	return true;
}
