/*
 * der.h
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DER_TYPE_BOOLEAN 0x01
#define DER_TYPE_INTEGER 0x02
#define DER_TYPE_BIT_STRING 0x03
#define DER_TYPE_OCTET_STRING 0x04
#define DER_TYPE_NULL 0x05
#define DER_TYPE_UTF8_STRING 0x0C
#define DER_TYPE_OBJECT_IDENTIFIER 0x06
#define DER_TYPE_PRINTABLE_STRING 0x13
#define DER_TYPE_UTC_TIME 0x17
#define DER_TYPE_SEQUENCE 0x30
#define DER_TYPE_SET 0x31
#define DER_TYPE_A0 0xA0
#define DER_TYPE_A3 0xA3
#define DER_TYPE_ERROR 0xFF

struct der_block_t {
	uint8_t *payload;
	uint8_t *end;
	uint8_t *child_iterator_next;
	uint8_t type;
};

extern bool der_block_init(struct der_block_t *block, uint8_t *ptr, uint8_t *end);
extern void der_block_debug_print(struct der_block_t *block);

extern bool der_block_get_boolean(struct der_block_t *block, bool *presult);
extern bool der_block_get_integer_int32(struct der_block_t *block, int32_t *presult);
extern bool der_block_get_bit_string(struct der_block_t *block, uint8_t **pptr, uint8_t **pend, size_t *punused_bits);
extern bool der_block_get_octet_string(struct der_block_t *block, uint8_t **pptr, uint8_t **pend);
extern bool der_block_get_text_string(struct der_block_t *block, char *str, char *str_end);
extern bool der_block_get_utc_time(struct der_block_t *block, time64_t *ptime_v);
extern bool der_block_get_object_id(struct der_block_t *block, char *id, char *id_end);
extern bool der_block_is_matching_object_id(struct der_block_t *block, char *id);

extern void der_child_iterator_reset(struct der_block_t *parent_block);
extern bool der_child_iterator_next(struct der_block_t *parent_block, struct der_block_t *next_block);
extern bool der_child_iterator_next_and_verify_type(struct der_block_t *parent_block, uint8_t type, struct der_block_t *next_block);
extern bool der_child_iterator_skip(struct der_block_t *parent_block, size_t count);

extern bool der_find_object_in_set(struct der_block_t *parent_block, char *id, struct der_block_t *value_block);
