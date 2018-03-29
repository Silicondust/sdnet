/*
 * ./src/utils/hash32.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern uint32_t hash32_create(const void *ptr, size_t length);
extern uint32_t hash32_create_str(const char *str);
extern uint32_t hash32_create_nb(struct netbuf *nb, size_t length);
extern uint32_t hash32_append(uint32_t hash, const void *ptr, size_t length);
extern uint32_t hash32_append_str(uint32_t hash, const char *str);
extern uint32_t hash32_append_nb(uint32_t hash, struct netbuf *nb, size_t length);

extern inline uint32_t hash32_create(const void *ptr, size_t length)
{
	return hash32_append(0xFFFFFFFF, ptr, length);
}

extern inline uint32_t hash32_create_str(const char *str)
{
	return hash32_append_str(0xFFFFFFFF, str);
}

extern inline uint32_t hash32_create_nb(struct netbuf *nb, size_t length)
{
	return hash32_append_nb(0xFFFFFFFF, nb, length);
}
