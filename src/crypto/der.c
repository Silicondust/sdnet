/*
 * der.c
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("der");

static const char *der_level_indent(int level)
{
	static char level_indent[32];
	memset(level_indent, '\t', level);
	level_indent[level] = 0;
	return level_indent;
}

static bool der_parse_length(uint8_t **pptr, uint8_t *end, size_t *plength)
{
	uint8_t *ptr = *pptr;
	if (ptr >= end) {
		DEBUG_WARN("bad length");
		return false;
	}

	size_t length = (size_t)(*ptr++);

	if (length >= 0x80) {
		uint8_t sz = length & 0x7F;
		if ((sz < 1) || (sz > 4) || (ptr + sz > end)) {
			DEBUG_WARN("bad length");
			return false;
		}

		length = 0;
		while (sz--) {
			length <<= 8;
			length |= (size_t)(*ptr++);
		}
	}

	if (ptr + length > end) {
		DEBUG_WARN("bad length");
		return false;
	}

	*pptr = ptr;
	*plength = length;
	return true;
}

bool der_block_get_boolean(struct der_block_t *block, bool *presult)
{
	if (block->type != DER_TYPE_BOOLEAN) {
		DEBUG_ERROR("der block not boolean");
		return false;
	}

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr + 1 != end) {
		DEBUG_WARN("bad boolean format");
		return false;
	}

	*presult = (*ptr != 0);
	return true;
}

bool der_block_get_integer_int32(struct der_block_t *block, int32_t *presult)
{
	if (block->type != DER_TYPE_INTEGER) {
		DEBUG_ERROR("der block not integer");
		return false;
	}

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr >= end) {
		DEBUG_WARN("bad integer format");
		return false;
	}

	if (ptr + 4 < end) {
		DEBUG_WARN("integer larger than int32");
		return false;
	}

	int32_t result = 0;
	while (ptr < end) {
		result <<= 8;
		result |= *ptr++;
	}

	*presult = result;
	return true;
}

bool der_block_get_bit_string(struct der_block_t *block, uint8_t **pptr, uint8_t **pend, size_t *punused_bits)
{
	if (block->type != DER_TYPE_BIT_STRING) {
		DEBUG_ERROR("der block not bit string");
		return false;
	}

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr + 2 > end) {
		DEBUG_WARN("bad bit string format");
		return false;
	}

	size_t unused_bits = (size_t)*ptr++;
	if (unused_bits > 7) {
		DEBUG_WARN("bad bit string format");
		return false;
	}

	*pptr = ptr;
	*pend = end;
	*punused_bits = unused_bits;
	return true;
}

bool der_block_get_octet_string(struct der_block_t *block, uint8_t **pptr, uint8_t **pend)
{
	if (block->type != DER_TYPE_OCTET_STRING) {
		DEBUG_ERROR("der block not octet string");
		return false;
	}

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr >= end) {
		DEBUG_WARN("bad octet string format");
		return false;
	}

	*pptr = ptr;
	*pend = end;
	return true;
}

static bool der_block_get_text_string_utf8(struct der_block_t *block, char *str, char *str_end)
{
	if (block->payload >= block->end) {
		DEBUG_WARN("bad utf8 string format");
		return false;
	}

	size_t length = min(block->end - block->payload, str_end - str - 1);
	memcpy(str, block->payload, length);
	str[length] = 0;
	return true;
}

static bool der_block_get_text_string_printable(struct der_block_t *block, char *str, char *str_end)
{
	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr >= end) {
		DEBUG_WARN("bad printable string format");
		return false;
	}

	while (ptr < end) {
		uint8_t c = *ptr++;
		utf8_put_wchar(&str, str_end, (uint16_t)c);
	}

	utf8_put_null(str, str_end);
	return true;
}

bool der_block_get_text_string(struct der_block_t *block, char *str, char *str_end)
{
	switch (block->type) {
	case DER_TYPE_UTF8_STRING:
		return der_block_get_text_string_utf8(block, str, str_end);

	case DER_TYPE_PRINTABLE_STRING:
		return der_block_get_text_string_printable(block, str, str_end);

	default:
		DEBUG_ASSERT(0, "der block not text");
		return false;
	}
}

static int der_block_get_utc_time_part(uint8_t **pptr, uint8_t *end, int min, int max, bool *psuccess)
{
	uint8_t *ptr = *pptr;
	if (ptr + 2 > end) {
		*psuccess = false;
		return 0;
	}

	uint8_t c = *ptr++;
	if ((c < '0') || (c > '9')) {
		*psuccess = false;
		return 0;
	}

	int result = (int)(c - '0') * 10;

	c = *ptr++;
	if ((c < '0') || (c > '9')) {
		*psuccess = false;
		return 0;
	}

	result += (int)(c - '0');
	if ((result < min) || (result > max)) {
		*psuccess = false;
		return 0;
	}

	*pptr = ptr;
	return (int)result;
}

bool der_block_get_utc_time(struct der_block_t *block, time64_t *ptime_v)
{
	if (block->type != DER_TYPE_UTC_TIME) {
		DEBUG_ERROR("der block not utc time");
		return false;
	}

	struct tm tm_v;
	memset(&tm_v, 0, sizeof(tm_v));

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	bool success = true;

	tm_v.tm_year = der_block_get_utc_time_part(&ptr, end, 0, 99, &success);
	if (tm_v.tm_year < 50) {
		tm_v.tm_year += 100;
	}

	tm_v.tm_mon = der_block_get_utc_time_part(&ptr, end, 1, 12, &success) - 1;
	tm_v.tm_mday = der_block_get_utc_time_part(&ptr, end, 1, 31, &success);
	tm_v.tm_hour = der_block_get_utc_time_part(&ptr, end, 0, 24, &success);
	tm_v.tm_min = der_block_get_utc_time_part(&ptr, end, 0, 60, &success);

	if (!success) {
		DEBUG_WARN("bad utc time format");
		return false;
	}

	tm_v.tm_sec = der_block_get_utc_time_part(&ptr, end, 0, 60, &success); /* Optional field - ignore success/failure */

	*ptime_v = unix_tm_to_time(&tm_v);
	return true;
}

bool der_block_get_object_id(struct der_block_t *block, char *id, char *id_end)
{
	if (block->type != DER_TYPE_OBJECT_IDENTIFIER) {
		DEBUG_ERROR("der block not object identifier");
		return false;
	}

	uint8_t *ptr = block->payload;
	uint8_t *end = block->end;
	if (ptr >= end) {
		DEBUG_WARN("bad object identifier format");
		return false;
	}

	uint8_t first = *ptr++;
	sprintf_custom(id, id_end, "%u.%u", first / 40, first % 40);
	id = strchr(id, 0);

	while (ptr < end) {
		uint32_t v = 0;

		while (1) {
			uint8_t b = *ptr++;
			v <<= 7;
			v |= b & 0x7F;

			if (b < 128) {
				break;
			}

			if (ptr >= end) {
				DEBUG_WARN("bad object identifier format");
				return false;
			}
		}

		sprintf_custom(id, id_end, ".%u", v);
		id = strchr(id, 0);
	}

	return true;
}

bool der_block_is_matching_object_id(struct der_block_t *block, char *id)
{
	char object_id[64];
	if (!der_block_get_object_id(block, object_id, object_id + sizeof(object_id))) {
		return false;
	}

	return (strcmp(id, object_id) == 0);
}

bool der_find_object_in_set(struct der_block_t *parent_block, char *id, struct der_block_t *object_block)
{
	der_child_iterator_reset(parent_block);

	while (1) {
		struct der_block_t set_entry;
		if (!der_child_iterator_next(parent_block, &set_entry)) {
			return false;
		}
		if (set_entry.type != DER_TYPE_SET) {
			DEBUG_WARN("bad structure");
			continue;
		}

		struct der_block_t set_content_block;
		if (!der_child_iterator_next(&set_entry, &set_content_block)) {
			DEBUG_WARN("bad structure");
			continue;
		}

		struct der_block_t entry_id_block;
		if (!der_child_iterator_next_and_verify_type(&set_content_block, DER_TYPE_OBJECT_IDENTIFIER, &entry_id_block)) {
			DEBUG_WARN("not object id");
			continue;
		}

		if (!der_block_is_matching_object_id(&entry_id_block, id)) {
			continue;
		}

		der_child_iterator_reset(&set_content_block);
		*object_block = set_content_block;
		return true;
	}
}

static bool der_block_type_is_iteratable(struct der_block_t *block)
{
	return (block->type == DER_TYPE_SEQUENCE) || (block->type == DER_TYPE_SET) || (block->type == DER_TYPE_A0) || (block->type == DER_TYPE_A3);
}

bool der_child_iterator_skip(struct der_block_t *parent_block, size_t count)
{
	DEBUG_ASSERT(der_block_type_is_iteratable(parent_block), "not iteratable type");
	uint8_t *ptr = parent_block->child_iterator_next;
	uint8_t *end = parent_block->end;

	while (count--) {
		if (ptr >= end) {
			return false;
		}

		ptr++; /* skip block type */

		size_t length;
		if (!der_parse_length(&ptr, end, &length)) {
			return false;
		}

		ptr += length;
	}

	parent_block->child_iterator_next = ptr;
	return true;
}

bool der_child_iterator_next(struct der_block_t *parent_block, struct der_block_t *next_block)
{
	DEBUG_ASSERT(der_block_type_is_iteratable(parent_block), "not iteratable type");
	if (!der_block_init(next_block, parent_block->child_iterator_next, parent_block->end)) {
		return false;
	}

	parent_block->child_iterator_next = next_block->end;
	return true;
}

bool der_child_iterator_next_and_verify_type(struct der_block_t *parent_block, uint8_t type, struct der_block_t *next_block)
{
	if (!der_child_iterator_next(parent_block, next_block)) {
		return false;
	}

	return (next_block->type == type);
}

void der_child_iterator_reset(struct der_block_t *parent_block)
{
	DEBUG_ASSERT(der_block_type_is_iteratable(parent_block), "not iteratable type");
	parent_block->child_iterator_next = parent_block->payload;
}

static void der_block_debug_print_internal(int level, struct der_block_t *block)
{
	switch (block->type) {
	case DER_TYPE_BOOLEAN:
		DEBUG_INFO("%sboolean: len=%u", der_level_indent(level), block->end - block->payload);
		break;

	case DER_TYPE_INTEGER:
		DEBUG_INFO("%sinteger len=%u", der_level_indent(level), block->end - block->payload);
		break;

	case DER_TYPE_BIT_STRING:
		{
			uint8_t *ptr;
			uint8_t *end;
			size_t unused_bits;
			if (!der_block_get_bit_string(block, &ptr, &end, &unused_bits)) {
				break;
			}

			DEBUG_INFO("%sbit string: bits=%u", der_level_indent(level), (end - ptr) * 8 - unused_bits);
		}
		break;

	case DER_TYPE_OCTET_STRING:
		{
			DEBUG_INFO("%soctet string: len=%u", der_level_indent(level), block->end - block->payload);
		}
		break;

	case DER_TYPE_NULL:
		DEBUG_INFO("%snull", der_level_indent(level));
		break;

	case DER_TYPE_OBJECT_IDENTIFIER:
		{
			char id[64];
			if (!der_block_get_object_id(block, id, id + sizeof(id))) {
				break;
			}
	
			DEBUG_INFO("%sobject-identifier=%s", der_level_indent(level), id);
		}
		break;

	case DER_TYPE_UTF8_STRING:
	case DER_TYPE_PRINTABLE_STRING:
	{
			char str[128];
			if (!der_block_get_text_string(block, str, str + sizeof(str))) {
				break;
			}
	
			DEBUG_INFO("%sprintable-string=%s", der_level_indent(level), str);
		}
		break;

	case DER_TYPE_UTC_TIME:
		{
			time64_t time_v;
			if (!der_block_get_utc_time(block, &time_v)) {
				break;
			}

			char str[64];
			unix_time_to_str(time_v, str);
			DEBUG_INFO("%stime=%s", der_level_indent(level), str);
		}
		break;

	case DER_TYPE_SEQUENCE:
		{
			DEBUG_INFO("%ssequence", der_level_indent(level));
			while (1) {
				struct der_block_t child_block;
				if (!der_child_iterator_next(block, &child_block)) {
					break;
				}

				der_block_debug_print_internal(level + 1, &child_block);
			}
		}
		break;

	case DER_TYPE_SET:
		{
			DEBUG_INFO("%sset", der_level_indent(level));
			while (1) {
				struct der_block_t child_block;
				if (!der_child_iterator_next(block, &child_block)) {
					break;
				}

				der_block_debug_print_internal(level + 1, &child_block);
			}
		}
		break;

	case DER_TYPE_A0:
	case DER_TYPE_A3:
		{
			DEBUG_INFO("%s%02x", der_level_indent(level), block->type);
			while (1) {
				struct der_block_t child_block;
				if (!der_child_iterator_next(block, &child_block)) {
					break;
				}

				der_block_debug_print_internal(level + 1, &child_block);
			}
		}
		break;

	default:
		DEBUG_INFO("%s0x%02x", der_level_indent(level), block->type);
		break;
	}
}

void der_block_debug_print(struct der_block_t *block)
{
	struct der_block_t block_local = *block;

	block_local.child_iterator_next = block_local.payload;
	der_block_debug_print_internal(0, &block_local);
}

bool der_block_init(struct der_block_t *block, uint8_t *ptr, uint8_t *end)
{
	if (ptr >= end) {
		return false;
	}

	block->type = *ptr++;

	size_t length;
	if (!der_parse_length(&ptr, end, &length)) {
		return false;
	}

	block->payload = ptr;
	block->end = ptr + length;
	block->child_iterator_next = ptr;

	return true;
}
