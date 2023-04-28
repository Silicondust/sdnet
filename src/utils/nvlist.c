/*
 * nvlist.c
 *
 * Copyright © 2015-2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("nvlist");

#if (RUNTIME_DEBUG)
void nvlist_debug_print(struct slist_t *list)
{
	struct nvlist_entry_t *entry = slist_get_head(struct nvlist_entry_t, list);
	while (entry) {
		if (entry->value_str) {
			DEBUG_INFO("%s=%s", entry->name, entry->value_str);
		} else {
			DEBUG_INFO("%s=%lld", entry->name, entry->value_int64);
		}

		entry = slist_get_next(struct nvlist_entry_t, entry);
	}
}
#endif

void nvlist_clear_all(struct slist_t *list)
{
	slist_clear(struct nvlist_entry_t, list, heap_free);
}

struct nvlist_entry_t *nvlist_lookup(struct slist_t *list, const char *name)
{
	struct nvlist_entry_t *entry = slist_get_head(struct nvlist_entry_t, list);
	while (entry) {
		int cmp = strcmp(entry->name, name);
		if (cmp >= 0) {
			return (cmp == 0) ? entry : NULL;
		}

		entry = slist_get_next(struct nvlist_entry_t, entry);
	}

	return NULL;
}

struct nvlist_entry_t *nvlist_lookup_prefix(struct slist_t *list, const char *name_prefix)
{
	struct nvlist_entry_t *entry = slist_get_head(struct nvlist_entry_t, list);
	while (entry) {
		int cmp = strprefixcmp(entry->name, name_prefix);
		if (cmp >= 0) {
			return (cmp == 0) ? entry : NULL;
		}

		entry = slist_get_next(struct nvlist_entry_t, entry);
	}

	return NULL;
}

const char *nvlist_lookup_str(struct slist_t *list, const char *name)
{
	struct nvlist_entry_t *entry = nvlist_lookup(list, name);
	if (!entry) {
		return NULL;
	}

	return entry->value_str;
}

const char *nvlist_lookup_str_with_fallback(struct slist_t *list, const char *name, const char *value_on_error)
{
	struct nvlist_entry_t *entry = nvlist_lookup(list, name);
	if (!entry) {
		return value_on_error;
	}

	if (!entry->value_str) {
		return value_on_error;
	}

	return entry->value_str;
}

int64_t nvlist_lookup_int64(struct slist_t *list, const char *name, int64_t value_on_error)
{
	struct nvlist_entry_t *entry = nvlist_lookup(list, name);
	if (!entry) {
		return value_on_error;
	}

	if (entry->value_str) {
		return value_on_error;
	}

	return entry->value_int64;
}

bool nvlist_lookup_bool_strong(struct slist_t *list, const char *name)
{
	struct nvlist_entry_t *entry = nvlist_lookup(list, name);
	if (!entry) {
		return false;
	}

	if (entry->value_str) {
		return (strcasecmp(entry->value_str, "true") == 0);
	}

	return (entry->value_int64 == 1);
}

static void nvlist_replace_internal(struct slist_t *list, struct nvlist_entry_t *entry)
{
	struct nvlist_entry_t **pprev = slist_get_phead(struct nvlist_entry_t, list);
	struct nvlist_entry_t *p = slist_get_head(struct nvlist_entry_t, list);
	while (p) {
		int cmp = strcmp(p->name, entry->name);
		if (cmp >= 0) {
			if (cmp == 0) {
				(void)slist_detach_pprev(struct nvlist_entry_t, pprev, p);
				heap_free(p);
			}
			break;
		}

		pprev = slist_get_pnext(struct nvlist_entry_t, p);
		p = slist_get_next(struct nvlist_entry_t, p);
	}

	slist_insert_pprev(struct nvlist_entry_t, pprev, entry);
}

const char *nvlist_set_str(struct slist_t *list, const char *name, const char *str)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = strlen(str);
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct nvlist_entry_t *entry = (struct nvlist_entry_t *)heap_alloc_and_zero(sizeof(struct nvlist_entry_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_NVLIST_ENTRY);
	if (!entry) {
		return NULL;
	}

	entry->name = (char *)(entry + 1);
	memcpy(entry->name, name, name_len + 1);
	entry->value_str = entry->name + name_space;
	memcpy(entry->value_str, str, value_len + 1);

	nvlist_replace_internal(list, entry);
	return entry->value_str;
}

const char *nvlist_set_str_mem(struct slist_t *list, const char *name, uint8_t *str, uint8_t *end)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = end - str;
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct nvlist_entry_t *entry = (struct nvlist_entry_t *)heap_alloc_and_zero(sizeof(struct nvlist_entry_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_NVLIST_ENTRY);
	if (!entry) {
		return NULL;
	}

	entry->name = (char *)(entry + 1);
	memcpy(entry->name, name, name_len + 1);
	entry->value_str = entry->name + name_space;
	memcpy(entry->value_str, str, value_len);
	entry->value_str[value_len] = 0;

	nvlist_replace_internal(list, entry);
	return entry->value_str;
}

const char *nvlist_set_str_nb(struct slist_t *list, const char *name, struct netbuf *nb)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;
	size_t value_len = netbuf_get_remaining(nb);
	size_t value_space = (value_len + 1 + 3) & ~3;

	struct nvlist_entry_t *entry = (struct nvlist_entry_t *)heap_alloc_and_zero(sizeof(struct nvlist_entry_t) + name_space + value_space, PKG_OS, MEM_TYPE_OS_NVLIST_ENTRY);
	if (!entry) {
		return NULL;
	}

	entry->name = (char *)(entry + 1);
	memcpy(entry->name, name, name_len + 1);
	entry->value_str = entry->name + name_space;
	if (value_len > 0) {
		netbuf_fwd_read(nb, entry->value_str, value_len);
	}
	entry->value_str[value_len] = 0;

	nvlist_replace_internal(list, entry);
	return entry->value_str;
}

void nvlist_set_int64(struct slist_t *list, const char *name, int64_t value)
{
	size_t name_len = strlen(name);
	size_t name_space = (name_len + 1 + 3) & ~3;

	struct nvlist_entry_t *entry = (struct nvlist_entry_t *)heap_alloc_and_zero(sizeof(struct nvlist_entry_t) + name_space, PKG_OS, MEM_TYPE_OS_NVLIST_ENTRY);
	if (!entry) {
		return;
	}

	entry->name = (char *)(entry + 1);
	memcpy(entry->name, name, name_len + 1);
	entry->value_int64 = value;

	nvlist_replace_internal(list, entry);
}

bool nvlist_unset(struct slist_t *list, const char *name)
{
	struct nvlist_entry_t **pprev = slist_get_phead(struct nvlist_entry_t, list);
	struct nvlist_entry_t *p = slist_get_head(struct nvlist_entry_t, list);
	while (p) {
		int cmp = strcmp(p->name, name);
		if (cmp >= 0) {
			if (cmp == 0) {
				(void)slist_detach_pprev(struct nvlist_entry_t, pprev, p);
				heap_free(p);
				return true;
			}
			break;
		}

		pprev = slist_get_pnext(struct nvlist_entry_t, p);
		p = slist_get_next(struct nvlist_entry_t, p);
	}

	return false;
}

void nvlist_copy(struct slist_t *dst_list, struct slist_t *src_list, const char *name)
{
	struct nvlist_entry_t *entry = nvlist_lookup(src_list, name);
	if (!entry) {
		return;
	}

	if (entry->value_str) {
		nvlist_set_str(dst_list, name, entry->value_str);
	} else {
		nvlist_set_int64(dst_list, name, entry->value_int64);
	}
}
