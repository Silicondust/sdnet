/*
 * xml_element.h
 *
 * Copyright © 2024 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct xml_attribute_t {
	struct slist_prefix_t slist_prefix;
	char *name;
	char *value;
};

struct xml_element_t {
	struct slist_prefix_t slist_prefix;
	struct xml_element_t *parent;
	struct slist_t attributes;
	char *name;
	char *value; /* null for a container element */
	struct slist_t children; /* empty for a value element */
};

extern void xml_element_debug_print(struct xml_element_t *element);

extern const char *xml_element_get_value(struct xml_element_t *element, const char *value_on_error);
extern int64_t xml_element_get_int64(struct xml_element_t *element, int64_t value_on_error);
extern bool xml_element_get_bool(struct xml_element_t *element);

extern struct xml_element_t *xml_element_get_parent(struct xml_element_t *element);

extern struct xml_element_t *xml_element_get_child_first(struct xml_element_t *parent);
extern struct xml_element_t *xml_element_get_child_next(struct xml_element_t *prev);
extern struct xml_element_t *xml_element_get_child_by_name(struct xml_element_t *parent, const char *name);
extern struct xml_element_t *xml_element_get_child_by_name_next(struct xml_element_t *prev);
extern const char *xml_element_get_child_value(struct xml_element_t *parent, const char *name, const char *value_on_error);
extern int64_t xml_element_get_child_int64(struct xml_element_t *parent, const char *name, int64_t value_on_error);
extern bool xml_element_get_child_bool(struct xml_element_t *parent, const char *name);

extern const char *xml_element_get_attribute_value(struct xml_element_t *element, const char *name, const char *value_on_error);
extern int64_t xml_element_get_attribute_int64(struct xml_element_t *element, const char *name, int64_t value_on_error);
extern bool xml_element_get_attribute_bool_strong(struct xml_element_t *element, const char *name);

extern struct xml_element_t *xml_element_append_container(struct xml_element_t *parent, const char *name);
extern struct xml_element_t *xml_element_append_name_value(struct xml_element_t *parent, const char *name, const char *value);
extern struct xml_element_t *xml_element_append_name_value_mem(struct xml_element_t *parent, const char *name, uint8_t *ptr, uint8_t *end);
extern struct xml_element_t *xml_element_append_name_value_nb(struct xml_element_t *parent, const char *name, struct netbuf *nb);
extern struct xml_element_t *xml_element_append_name_value_blank(struct xml_element_t *parent, const char *name);

extern bool xml_element_append_attribute(struct xml_element_t *element, const char *name, const char *value);
extern bool xml_element_append_attribute_mem(struct xml_element_t *element, const char *name, uint8_t *ptr, uint8_t *end);
extern bool xml_element_append_attribute_nb(struct xml_element_t *element, const char *name, struct netbuf *nb);

extern void xml_element_detach_from_parent(struct xml_element_t *element);
extern void xml_element_free(struct xml_element_t *element);
extern void xml_element_free_attributes_and_children(struct xml_element_t *element);

#if defined(DEBUG)
#define XML_ELEMENT_DEBUG_PRINT(element) xml_element_debug_print(element)
#else
#define XML_ELEMENT_DEBUG_PRINT(element)
#endif
