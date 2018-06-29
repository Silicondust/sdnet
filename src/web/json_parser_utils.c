/*
 * json_parser_utils.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("json_parser_utils");

bool json_parser_nb_to_str(char *str, char *end, struct netbuf *nb)
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

static bool json_parser_path_apply_element_start(char *path, char *end, char tag, struct netbuf *name_nb)
{
	size_t name_length = netbuf_get_remaining(name_nb);
	char *ptr = strchr(path, 0);

	if (ptr + name_length + 1 >= end) {
		DEBUG_WARN("path too long");
		return false;
	}

	if (name_length > 0) {
		netbuf_fwd_read(name_nb, ptr, name_length);
		ptr += name_length;
	}

	*ptr++ = tag;
	*ptr = 0;
	return true;
}

static bool json_parser_path_apply_element_end(char *path, char tag)
{
	char *end = strchr(path, 0);
	char *ptr = end;

	if (tag != 0) {
		ptr--;
		if (ptr < path) {
			DEBUG_WARN("close '%x' doesn't match path %s", tag, path);
			return false;
		}
		if (*ptr != tag) {
			DEBUG_WARN("close '%x' doesn't match path %s", tag, path);
			return false;
		}
	}

	while (ptr > path) {
		ptr--;
		if ((*ptr == '{') || (*ptr == '[')) {
			ptr++;
			break;
		}
	}

	if (ptr == end) {
		DEBUG_WARN("close '%x' doesn't match path %s", tag, path);
		return false;
	}

	*ptr = 0;
	return true;
}

bool json_parser_path_apply(json_parser_event_t json_event, char *path, char *end, struct netbuf *nb)
{
	switch (json_event) {
	case JSON_PARSER_EVENT_ARRAY_START:
		return json_parser_path_apply_element_start(path, end, '[', nb);

	case JSON_PARSER_EVENT_ARRAY_END:
		return json_parser_path_apply_element_end(path, '[');

	case JSON_PARSER_EVENT_OBJECT_START:
		return json_parser_path_apply_element_start(path, end, '{', nb);

	case JSON_PARSER_EVENT_OBJECT_END:
		return json_parser_path_apply_element_end(path, '{');

	case JSON_PARSER_EVENT_ELEMENT_NAME:
		return json_parser_path_apply_element_start(path, end, 0, nb);

	case JSON_PARSER_EVENT_ELEMENT_VALUE_STR:
	case JSON_PARSER_EVENT_ELEMENT_VALUE_UNQUOTED:
		return json_parser_path_apply_element_end(path, 0);

	case JSON_PARSER_EVENT_INTERNAL_ERROR:
	case JSON_PARSER_EVENT_PARSE_ERROR:
	default:
		return false;
	}
}
