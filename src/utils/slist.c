/*
 * ./src/utils/slist.c
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

THIS_FILE("slist");

uint32_t slist_get_count(struct slist_t *list)
{
	uint32_t count = 0;

	struct slist_prefix_t *p = list->head;
	while (p) {
		count++;
		p = p->next;
	}

	return count;
}

struct slist_prefix_t *slist_get_tail_impl(struct slist_t *list)
{
	struct slist_prefix_t *p = list->head;
	if (!p) {
		return NULL;
	}

	while (p->next) {
		p = p->next;
	}

	return p;
}

void slist_insert_pprev_impl(struct slist_prefix_t **pprev, struct slist_prefix_t *item)
{
	item->next = *pprev;
	*pprev = item;
}

void slist_insert_custom_impl(struct slist_t *list, struct slist_prefix_t *item, slist_insert_before_func_t insert_before_func)
{
	DEBUG_ASSERT(!item->next, "item already attached?");

	struct slist_prefix_t **pprev = &list->head;
	struct slist_prefix_t *p = list->head;

	while (p) {
		int8_t result = insert_before_func(p, item);
		if (result) {
			if (result < 0) {
				return;
			}
			break;
		}

		pprev = &p->next;
		p = p->next;
	}

	item->next = p;
	*pprev = item;
}

void slist_attach_head_impl(struct slist_t *list, struct slist_prefix_t *item)
{
	DEBUG_ASSERT(!item->next, "item already attached?");

	item->next = list->head;
	list->head = item;
}

struct slist_prefix_t *slist_attach_head_detach_tail_over_limit_impl(struct slist_t *list, struct slist_prefix_t *item, uint32_t max_count)
{
	DEBUG_ASSERT(!item->next, "item already attached?");

	item->next = list->head;
	list->head = item;

	struct slist_prefix_t **pprev = &item->next;
	struct slist_prefix_t *p = item->next;
	if (!p) {
		return NULL;
	}

	uint32_t count = 2;
	while (p->next) {
		pprev = &p->next;
		p = p->next;
		count++;
	}

	if (count >= max_count) {
		*pprev = NULL;
		return p;
	}

	return NULL;
}

void slist_attach_tail_impl(struct slist_t *list, struct slist_prefix_t *item)
{
	DEBUG_ASSERT(!item->next, "item already attached?");

	struct slist_prefix_t **pprev = &list->head;
	struct slist_prefix_t *p = list->head;

	while (p) {
		pprev = &p->next;
		p = p->next;
	}

	*pprev = item;
	item->next = NULL;
}

bool slist_attach_tail_limit_impl(struct slist_t *list, struct slist_prefix_t *item, uint32_t max_count)
{
	DEBUG_ASSERT(!item->next, "item already attached?");

	struct slist_prefix_t **pprev = &list->head;
	struct slist_prefix_t *p = list->head;
	uint32_t count = 0;

	while (p) {
		count++;
		pprev = &p->next;
		p = p->next;
	}

	if (count >= max_count) {
		return false;
	}

	*pprev = item;
	item->next = NULL;
	return true;
}

struct slist_prefix_t *slist_detach_head_impl(struct slist_t *list)
{
	struct slist_prefix_t *p = list->head;
	if (!p) {
		return NULL;
	}

	list->head = p->next;
	p->next = NULL;
	return p;
}

struct slist_prefix_t *slist_detach_item_impl(struct slist_t *list, struct slist_prefix_t *item)
{
	struct slist_prefix_t **pprev = &list->head;
	struct slist_prefix_t *p = list->head;

	while (p) {
		if (p == item) {
			*pprev = p->next;
			p->next = NULL;
			return p;
		}

		pprev = &p->next;
		p = p->next;
	}

	return NULL;
}

struct slist_prefix_t *slist_detach_pprev_impl(struct slist_prefix_t **pprev, struct slist_prefix_t *item)
{
	DEBUG_ASSERT(*pprev == item, "invalid p/pprev");

	*pprev = item->next;
	item->next = NULL;

	return item;
}

void slist_clear_impl(struct slist_t *list, slist_clear_callback_func_t callback_func)
{
	while (list->head) {
		struct slist_prefix_t *item = list->head;
		list->head = item->next;
		item->next = NULL;
		callback_func(item);
	}
}

void slist_clear_custom_impl(struct slist_t *list, void *state, slist_clear_custom_func_t custom_func, slist_clear_callback_func_t callback_func)
{
	struct slist_prefix_t **pprev = &list->head;
	struct slist_prefix_t *p = list->head;
	uint32_t index = 0;
	while (p) {
		if (custom_func(p, index, state)) {
			*pprev = p->next;
			p->next = NULL;
			callback_func(p);
			p = *pprev;
			continue;
		}

		pprev = &p->next;
		p = p->next;
		index++;
	}
}
