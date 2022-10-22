/*
 * hmap.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct hmap_prefix_t
{
	struct hmap_prefix_t *next;
	uint32_t hash;
};

struct hmap_t
{
	struct hmap_prefix_t **hash_array;
	uint32_t hash_mask;
};

typedef bool (*hmap_clear_custom_func_t)(struct hmap_prefix_t *item, void *state);
typedef void (*hmap_clear_callback_func_t)(struct hmap_prefix_t *item);

extern bool hmap_init(struct hmap_t *map, uint32_t hash_size);
extern bool hmap_exchange(struct hmap_t *map1, struct hmap_t *map2);
extern void hmap_dispose(struct hmap_t *map);

extern uint32_t hmap_hash_create(const void *ptr, size_t length);
extern uint32_t hmap_hash_create_str(const char *ptr);
extern uint32_t hmap_hash_append(uint32_t hash, const void *ptr, size_t length);
extern uint32_t hmap_hash_append_str(uint32_t hash, const char *ptr);

extern bool hmap_initialized(struct hmap_t *map);
extern uint32_t hmap_get_count(struct hmap_t *map);

#define hmap_find(type, map, hash) (type *)(void *)hmap_find_impl(map, hash)
#define hmap_next(type, map, hash) (type *)(void *)hmap_next_impl(map, hash)
#define hmap_add(type, map, item, hash) hmap_add_impl(map, (struct hmap_prefix_t *)(void *)item, hash)
#define hmap_remove(type, map, hash) (type *)(void *)hmap_remove_impl(map, hash)
#define hmap_remove_top(type, map) (type *)(void *)hmap_remove_top_impl(map)
#define hmap_replace(type, map, item, hash) (type *)(void *)hmap_replace_impl(map, (struct hmap_prefix_t *)(void *)item, hash)
#define hmap_clear(type, map, callback_func) hmap_clear_impl(map, (hmap_clear_callback_func_t)callback_func)
#define hmap_clear_custom(type, map, state, custom_func, callback_func) hmap_clear_custom_impl(map, state, (hmap_clear_custom_func_t)custom_func, (hmap_clear_callback_func_t)callback_func)

/* Implementation. */
extern struct hmap_prefix_t *hmap_find_impl(struct hmap_t *map, uint32_t hash);
extern struct hmap_prefix_t *hmap_next_impl(struct hmap_t *map, uint32_t hash);
extern bool hmap_add_impl(struct hmap_t *map, struct hmap_prefix_t *item, uint32_t hash);
extern struct hmap_prefix_t *hmap_remove_impl(struct hmap_t *map, uint32_t hash);
extern struct hmap_prefix_t *hmap_remove_top_impl(struct hmap_t *map);
extern struct hmap_prefix_t *hmap_replace_impl(struct hmap_t *map, struct hmap_prefix_t *item, uint32_t hash);
extern void hmap_clear_impl(struct hmap_t *map, hmap_clear_callback_func_t callback_func);
extern void hmap_clear_custom_impl(struct hmap_t *map, void *state, hmap_clear_custom_func_t custom_func, hmap_clear_callback_func_t callback_func);

extern inline uint32_t hmap_hash_create(const void *ptr, size_t length) { return hash32_create(ptr, length); }
extern inline uint32_t hmap_hash_create_str(const char *ptr) { return hash32_create_str(ptr); }
extern inline uint32_t hmap_hash_append(uint32_t hash, const void *ptr, size_t length) { return hash32_append(hash, ptr, length); }
extern inline uint32_t hmap_hash_append_str(uint32_t hash, const char *ptr) { return hash32_append_str(hash, ptr); }
