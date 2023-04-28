/*
 * hash64.h
 *
 * Copyright © 2013-2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern uint64_t hash64_create(const void *ptr, size_t length);
extern uint64_t hash64_create_str(const char *str);
extern uint64_t hash64_create_nb(struct netbuf *nb, size_t length);
extern uint64_t hash64_append(uint64_t hash, const void *ptr, size_t length);
extern uint64_t hash64_append_str(uint64_t hash, const char *str);
extern uint64_t hash64_append_nb(uint64_t hash, struct netbuf *nb, size_t length);

extern inline uint64_t hash64_create(const void *ptr, size_t length)
{
	return hash64_append(0xFFFFFFFFFFFFFFFFULL, ptr, length);
}

extern inline uint64_t hash64_create_str(const char *str)
{
	return hash64_append_str(0xFFFFFFFFFFFFFFFFULL, str);
}

extern inline uint64_t hash64_create_nb(struct netbuf *nb, size_t length)
{
	return hash64_append_nb(0xFFFFFFFFFFFFFFFFULL, nb, length);
}
