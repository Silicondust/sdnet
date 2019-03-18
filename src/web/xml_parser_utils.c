/*
 * xml_parser_utils.c
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

THIS_FILE("xml_parser_utils");

bool xml_parser_nb_to_str(char *str, char *end, struct netbuf *nb)
{
	DEBUG_ASSERT(str < end, "bad buffer");

	bool success = true;
	size_t len = netbuf_get_remaining(nb);

	if (str + len >= end) {
		len = end - str - 1;
		success = false;
	}

	if (LIKELY(len > 0)) {
		netbuf_fwd_read(nb, str, len);
	}

	str[len] = 0;
	return success;
}

static bool xml_parser_path_apply_element_start(char *path, char *end, struct netbuf *name_nb)
{
	size_t name_length = netbuf_get_remaining(name_nb);
	if (name_length == 0) {
		DEBUG_WARN("empty name");
		return false;
	}

	char *ptr = strchr(path, 0);

	if (ptr + name_length + 2 >= end) {
		DEBUG_WARN("path too long");
		return false;
	}

	if (ptr > path) {
		*ptr++ = '|';
	}

	netbuf_fwd_read(name_nb, ptr, name_length);
	ptr[name_length] = 0;
	return true;
}

static bool xml_parser_path_apply_element_end(char *path, struct netbuf *name_nb)
{
	if (!name_nb) {
		char *ptr = strrchr(path, '|');
		if (!ptr) {
			path[0] = 0;
			return true;
		}

		*ptr = 0;
		return true;
	}

	size_t name_length = netbuf_get_remaining(name_nb);
	if (name_length == 0) {
		DEBUG_WARN("empty name");
		return false;
	}

	char *end = strchr(path, 0);
	char *ptr = end - name_length;
	if (ptr < path) {
		DEBUG_WARN("close miss-match: %s", path);
		return false;
	}

	if (netbuf_fwd_memcmp(name_nb, ptr, name_length) != 0) {
		DEBUG_WARN("close miss-match: %s", path);
		return false;
	}

	if (ptr > path) {
		ptr--;
		if (*ptr != '|') {
			DEBUG_WARN("close miss-match: %s", path);
			return false;
		}
	}

	*ptr = 0;
	return true;
}

bool xml_parser_path_apply(xml_parser_event_t xml_event, char *path, char *end, struct netbuf *nb)
{
	switch (xml_event) {
	case XML_PARSER_EVENT_ELEMENT_START_NAMESPACE:
	case XML_PARSER_EVENT_ELEMENT_END_NAMESPACE:
	case XML_PARSER_EVENT_ATTRIBUTE_NAMESPACE:
	case XML_PARSER_EVENT_ELEMENT_TEXT:
		return true;

	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		return xml_parser_path_apply_element_start(path, end, nb);

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
		return xml_parser_path_apply_element_end(path, nb);

	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		return xml_parser_path_apply_element_end(path, NULL);

	case XML_PARSER_EVENT_ATTRIBUTE_NAME:
		return xml_parser_path_apply_element_start(path, end, nb);

	case XML_PARSER_EVENT_ATTRIBUTE_VALUE:
		return xml_parser_path_apply_element_end(path, NULL);

	case XML_PARSER_EVENT_INTERNAL_ERROR:
	case XML_PARSER_EVENT_PARSE_ERROR:
	default:
		return false;
	}
}
