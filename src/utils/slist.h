/*
 * slist.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct slist_prefix_t
{
	struct slist_prefix_t *next;
};

struct slist_t
{
	struct slist_prefix_t *head;
};

typedef int8_t (*slist_insert_before_func_t)(struct slist_prefix_t *list_item, struct slist_prefix_t *item);
typedef bool (*slist_clear_custom_func_t)(struct slist_prefix_t *item, uint32_t index, void *state);
typedef void (*slist_clear_callback_func_t)(struct slist_prefix_t *item);

/*
 * list information.
 */
extern uint32_t slist_get_count(struct slist_t *list);

/*
 * list iteration.
 */
#define slist_get_phead(type, list) (type **)(void *)slist_get_phead_impl(list)
#define slist_get_pnext(type, item) (type **)(void *)slist_get_pnext_impl((struct slist_prefix_t *)(void *)item)
#define slist_get_head(type, list) (type *)(void *)slist_get_head_impl(list)
#define slist_get_next(type, item) (type *)(void *)slist_get_next_impl((struct slist_prefix_t *)(void *)item)
#define slist_get_tail(type, list) (type *)(void *)slist_get_tail_impl(list)

/*
 * insert_custom: scan list calling insert_before_func for each item. When insert_before_func returns true insert the item before the current item. If the end of the list is reached then the item is added to the end of the list.
 */
#define slist_insert_pprev(type, pprev, item) slist_insert_pprev_impl((struct slist_prefix_t **)(void *)pprev, (struct slist_prefix_t *)(void *)item)
#define slist_insert_custom(type, list, item, insert_before_func) slist_insert_custom_impl(list, (struct slist_prefix_t *)(void *)item, (slist_insert_before_func_t)insert_before_func)

/*
 * attach_head: fast attach of item to head of list. No return value.
 * attach_head_detach_tail_over_limit: attach item to head of the list. Detach tail only if there are more than max_count entries in the list. Returns unlinked item or NULL if list contains less than or equal to max_count items.
 * attach_tail: scan list until end is reached, attach the item to end. No return value.
 * attach_tail_limit: scan list until end is reached, if less than max_count items then attach the item to end of the list. Returns true if attached, false if the list has max_count or more items already.
 */
#define slist_attach_head(type, list, item) slist_attach_head_impl(list, (struct slist_prefix_t *)(void *)item)
#define slist_attach_head_detach_tail_over_limit(type, list, item, max_count) (type *)(void *)slist_attach_head_detach_tail_over_limit_impl(list, (struct slist_prefix_t *)(void *)item, max_count)
#define slist_attach_tail(type, list, item) slist_attach_tail_impl(list, (struct slist_prefix_t *)(void *)item)
#define slist_attach_tail_limit(type, list, item, max_count) slist_attach_tail_limit_impl(list, (struct slist_prefix_t *)(void *)item, max_count)

/*
 * detach_head: fast unlink of head. Returns unlinked item or NULL if the list is empty.
 * detach_item: scan list until item is found then remove. Returns unlinked item or NULL if not found.
 */
#define slist_detach_head(type, list) (type *)(void *)slist_detach_head_impl(list)
#define slist_detach_item(type, list, item) (type *)(void *)slist_detach_item_impl(list, (struct slist_prefix_t *)(void *)item)
#define slist_detach_pprev(type, pprev, item) (type *)(void *)slist_detach_pprev_impl((struct slist_prefix_t **)(void *)pprev, (struct slist_prefix_t *)(void *)item)

/*
 * clear: remove all items from the list calling the given callback function for each item.
 * clear_custom: remove all matching items from the list calling the given callback function for each item.
 */
#define slist_clear(type, list, callback_func) slist_clear_impl(list, (slist_clear_callback_func_t)callback_func)
#define slist_clear_custom(type, list, state, custom_func, callback_func) slist_clear_custom_impl(list, state, (slist_clear_custom_func_t)custom_func, (slist_clear_callback_func_t)callback_func)

/* Implementation. */
static inline struct slist_prefix_t **slist_get_phead_impl(struct slist_t *list) { return &list->head; }
static inline struct slist_prefix_t **slist_get_pnext_impl(struct slist_prefix_t *item) { return &item->next; }
static inline struct slist_prefix_t *slist_get_head_impl(struct slist_t *list) { return list->head; }
static inline struct slist_prefix_t *slist_get_next_impl(struct slist_prefix_t *item) { return item->next; }
extern struct slist_prefix_t *slist_get_tail_impl(struct slist_t *list);

extern void slist_insert_pprev_impl(struct slist_prefix_t **pprev, struct slist_prefix_t *item);
extern void slist_insert_custom_impl(struct slist_t *list, struct slist_prefix_t *item, slist_insert_before_func_t insert_before_func);

extern void slist_attach_head_impl(struct slist_t *list, struct slist_prefix_t *item);
extern struct slist_prefix_t *slist_attach_head_detach_tail_over_limit_impl(struct slist_t *list, struct slist_prefix_t *item, uint32_t max_count);
extern void slist_attach_tail_impl(struct slist_t *list, struct slist_prefix_t *item);
extern bool slist_attach_tail_limit_impl(struct slist_t *list, struct slist_prefix_t *item, uint32_t max_count);

extern struct slist_prefix_t *slist_detach_head_impl(struct slist_t *list);
extern struct slist_prefix_t *slist_detach_item_impl(struct slist_t *list, struct slist_prefix_t *item);
extern struct slist_prefix_t *slist_detach_pprev_impl(struct slist_prefix_t **pprev, struct slist_prefix_t *item);

extern void slist_clear_impl(struct slist_t *list, slist_clear_callback_func_t callback_func);
extern void slist_clear_custom_impl(struct slist_t *list, void *state, slist_clear_custom_func_t custom_func, slist_clear_callback_func_t callback_func);
