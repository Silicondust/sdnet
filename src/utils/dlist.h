/*
 * dlist.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct dlist_prefix_t
{
	struct dlist_prefix_t *next;
	struct dlist_prefix_t *prev;
};

struct dlist_t
{
	struct dlist_prefix_t *head;
	struct dlist_prefix_t *tail;
};

/*
 * list iteration.
 */
#define dlist_get_head(type, list) (type *)(void *)dlist_get_head_impl(list)
#define dlist_get_tail(type, list) (type *)(void *)dlist_get_tail_impl(list)
#define dlist_get_prev(type, item) (type *)(void *)dlist_get_prev_impl((struct dlist_prefix_t *)(void *)item)
#define dlist_get_next(type, item) (type *)(void *)dlist_get_next_impl((struct dlist_prefix_t *)(void *)item)

/*
 * attach_head: fast attach of item to head of list. No return value.
 */
#define dlist_attach_head(type, list, item) dlist_attach_head_impl(list, (struct dlist_prefix_t *)(void *)item)
#define dlist_attach_tail(type, list, item) dlist_attach_tail_impl(list, (struct dlist_prefix_t *)(void *)item)

/*
 * detach_item: remove item from list. Returns unlinked item or NULL if not found.
 */
#define dlist_detach_head(type, list) (type *)(void *)dlist_detach_head_impl(list)
#define dlist_detach_item(type, list, item) (type *)(void *)dlist_detach_item_impl(list, (struct dlist_prefix_t *)(void *)item)

/* Implementation. */
static inline struct dlist_prefix_t *dlist_get_head_impl(struct dlist_t *list) { return list->head; }
static inline struct dlist_prefix_t *dlist_get_tail_impl(struct dlist_t *list) { return list->tail; }
static inline struct dlist_prefix_t *dlist_get_prev_impl(struct dlist_prefix_t *item) { return item->prev; }
static inline struct dlist_prefix_t *dlist_get_next_impl(struct dlist_prefix_t *item) { return item->next; }

extern void dlist_attach_head_impl(struct dlist_t *list, struct dlist_prefix_t *item);
extern void dlist_attach_tail_impl(struct dlist_t *list, struct dlist_prefix_t *item);
extern struct dlist_prefix_t *dlist_detach_head_impl(struct dlist_t *list);
extern struct dlist_prefix_t *dlist_detach_item_impl(struct dlist_t *list, struct dlist_prefix_t *item);
