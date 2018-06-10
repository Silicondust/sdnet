/*
 * dlist.c
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

THIS_FILE("dlist");

void dlist_attach_head_impl(struct dlist_t *list, struct dlist_prefix_t *item)
{
	DEBUG_ASSERT(!item->next, "item already attached?");
	DEBUG_ASSERT(!item->prev, "item already attached?");

	struct dlist_prefix_t *next_item = list->head;

	list->head = item;
	item->next = next_item;
	item->prev = NULL;

	if (next_item) {
		next_item->prev = item;
	} else {
		list->tail = item;
	}
}

void dlist_attach_tail_impl(struct dlist_t *list, struct dlist_prefix_t *item)
{
	DEBUG_ASSERT(!item->next, "item already attached?");
	DEBUG_ASSERT(!item->prev, "item already attached?");

	struct dlist_prefix_t *prev_item = list->tail;

	list->tail = item;
	item->prev = prev_item;
	item->next = NULL;

	if (prev_item) {
		prev_item->next = item;
	} else {
		list->head = item;
	}
}

struct dlist_prefix_t *dlist_detach_head_impl(struct dlist_t *list)
{
	struct dlist_prefix_t *item = list->head;
	if (!item) {
		return NULL;
	}

	struct dlist_prefix_t *next_item = item->next;
	if (next_item) {
		next_item->prev = NULL;
		item->next = NULL;
	} else {
		list->tail = NULL;
	}

	list->head = next_item;

	return item;
}

struct dlist_prefix_t *dlist_detach_item_impl(struct dlist_t *list, struct dlist_prefix_t *item)
{
	struct dlist_prefix_t *next_item = item->next;
	struct dlist_prefix_t *prev_item = item->prev;

	if (!prev_item && (list->head != item)) {
		return NULL;
	}

	if (next_item) {
		next_item->prev = prev_item;
		item->next = NULL;
	} else {
		list->tail = prev_item;
	}

	if (prev_item) {
		prev_item->next = next_item;
		item->prev = NULL;
	} else {
		list->head = next_item;
	}

	return item;
}
