/*
 * nvlist.h
 *
 * Copyright © 2015-2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct nvlist_entry_t {
	struct slist_prefix_t slist_prefix;
	char *name;
	char *value_str;
	int64_t value_int64;
};

extern void nvlist_debug_print(struct slist_t *list);
extern void nvlist_clear_all(struct slist_t *list);
extern struct nvlist_entry_t *nvlist_lookup(struct slist_t *list, const char *name);
extern struct nvlist_entry_t *nvlist_lookup_prefix(struct slist_t *list, const char *name_prefix);
extern const char *nvlist_lookup_str(struct slist_t *list, const char *name);
extern const char *nvlist_lookup_str_with_fallback(struct slist_t *list, const char *name, const char *value_on_error);
extern int64_t nvlist_lookup_int64(struct slist_t *list, const char *name, int64_t value_on_error);
extern bool nvlist_lookup_bool_strong(struct slist_t *list, const char *name);
extern const char *nvlist_set_str(struct slist_t *list, const char *name, const char *str);
extern const char *nvlist_set_str_mem(struct slist_t *list, const char *name, uint8_t *str, uint8_t *end);
extern const char *nvlist_set_str_nb(struct slist_t *list, const char *name, struct netbuf *nb);
extern void nvlist_set_int64(struct slist_t *list, const char *name, int64_t value);
extern bool nvlist_unset(struct slist_t *list, const char *name);
extern void nvlist_copy(struct slist_t *dst_list, struct slist_t *src_list, const char *name);

#if defined(DEBUG)
#define NVLIST_DEBUG_PRINT(list) nvlist_debug_print(list)
#else
#define NVLIST_DEBUG_PRINT(list)
#endif
