/*
 * hmap.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("hmap");

uint32_t hamp_get_count(struct hmap_t *map)
{
	uint32_t count = 0;

	for (uint32_t index = 0; index <= map->hash_mask; index++) {
		struct hmap_prefix_t *p = map->hash_array[index];
		while (p) {
			count++;
			p = p->next;
		}
	}

	return count;
}

struct hmap_prefix_t *hmap_find_impl(struct hmap_t *map, uint32_t hash)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");

	struct hmap_prefix_t *item = map->hash_array[hash & map->hash_mask];
	while (item) {
		if (item->hash == hash) {
			return item;
		}

		item = item->next;
	}

	return NULL;
}

struct hmap_prefix_t *hmap_next_impl(struct hmap_t *map, uint32_t hash)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");

	uint32_t index = 0;
	if (LIKELY(hash != 0)) {
		struct hmap_prefix_t *item = hmap_find_impl(map, hash);
		if (!item) {
			return NULL;
		}

		if (item->next) {
			return item->next;
		}

		index = (hash & map->hash_mask) + 1;
	}

	while (index <= map->hash_mask) {
		struct hmap_prefix_t *item = map->hash_array[index];
		if (item) {
			return item;
		}

		index++;
	}

	return NULL;
}

bool hmap_add_impl(struct hmap_t *map, struct hmap_prefix_t *item, uint32_t hash)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");
	DEBUG_ASSERT(!item->next, "item already attached?");

	struct hmap_prefix_t **pprev = &map->hash_array[hash & map->hash_mask];
	struct hmap_prefix_t *p = *pprev;
	while (p) {
		if (p->hash == hash) {
			return false;
		}

		pprev = &p->next;
		p = p->next;
	}

	*pprev = item;
	item->hash = hash;
	item->next = NULL;
	return true;
}

struct hmap_prefix_t *hmap_remove_impl(struct hmap_t *map, uint32_t hash)
{
	struct hmap_prefix_t **pprev = &map->hash_array[hash & map->hash_mask];
	struct hmap_prefix_t *p = *pprev;
	while (p) {
		if (p->hash == hash) {
			*pprev = p->next;
			p->next = NULL;
			return p;
		}

		pprev = &p->next;
		p = p->next;
	}

	return NULL;
}

struct hmap_prefix_t *hmap_remove_top_impl(struct hmap_t *map)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");

	for (uint32_t index = 0; index <= map->hash_mask; index++) {
		if (map->hash_array[index]) {
			struct hmap_prefix_t *p = map->hash_array[index];
			map->hash_array[index] = p->next;
			p->next = NULL;
			return p;
		}
	}

	return NULL;
}

struct hmap_prefix_t *hmap_replace_impl(struct hmap_t *map, struct hmap_prefix_t *item, uint32_t hash)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");
	DEBUG_ASSERT(!item->next, "item already attached?");

	struct hmap_prefix_t **pprev = &map->hash_array[hash & map->hash_mask];
	struct hmap_prefix_t *p = *pprev;
	while (p) {
		if (p->hash == hash) {
			*pprev = item;
			item->hash = hash;
			item->next = p->next;
			p->next = NULL;
			return p;
		}

		pprev = &p->next;
		p = p->next;
	}

	*pprev = item;
	item->hash = hash;
	item->next = NULL;
	return NULL;
}

void hmap_clear_impl(struct hmap_t *map, hmap_callback_func_t callback_func)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");

	for (uint32_t index = 0; index <= map->hash_mask; index++) {
		struct hmap_prefix_t **pprev = &map->hash_array[index];
		struct hmap_prefix_t *p = *pprev;
		while (p) {
			*pprev = p->next;
			p->next = NULL;
			callback_func(p);
			p = *pprev;
		}
	}
}

void hmap_clear_custom_impl(struct hmap_t *map, struct hmap_prefix_t *match_item, hmap_match_func_t match_func, hmap_callback_func_t callback_func)
{
	DEBUG_ASSERT(map->hash_array, "hmap not initialized");

	for (uint32_t index = 0; index <= map->hash_mask; index++) {
		struct hmap_prefix_t **pprev = &map->hash_array[index];
		struct hmap_prefix_t *p = *pprev;
		while (p) {
			if (match_func(p, match_item)) {
				*pprev = p->next;
				p->next = NULL;
				callback_func(p);
				p = *pprev;
				continue;
			}

			pprev = &p->next;
			p = p->next;
		}
	}
}

void hmap_dispose(struct hmap_t *map)
{
	if (map->hash_array) {
		heap_free(map->hash_array);
		map->hash_array = NULL;
	}

	map->hash_mask = 0;
}

bool hmap_init(struct hmap_t *map, uint32_t hash_size)
{
	switch (hash_size) {
	case 16:
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
		break;
	default:
		DEBUG_ASSERT(0, "invalid hash size %u", hash_size);
		break;
	}

	map->hash_array = (struct hmap_prefix_t **)heap_alloc_and_zero(sizeof(struct hmap_prefix_t *) * hash_size, PKG_OS, MEM_TYPE_OS_HMAP_ARRAY);
	if (!map->hash_array) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	map->hash_mask = hash_size - 1;
	return true;
}
