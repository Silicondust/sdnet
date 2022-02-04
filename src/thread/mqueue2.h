/*
 * mqueue2.h
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef void (*mqueue2_item_handler_func_t)(void *item);

struct mqueue2_item_prefix_t {
	struct dlist_prefix_t dlist_prefix;
	mqueue2_item_handler_func_t item_handler;
	size_t byte_cost;
};

struct mqueue2_stats_t {
	size_t worst_queue_depth;
	uint64_t worst_queue_bytes;
};

struct mqueue2_t;

extern struct mqueue2_t *mqueue2_alloc(size_t max_queue_depth, uint64_t max_queue_bytes, struct thread_signal_t *signal);
extern size_t mqueue2_get_current_queue_depth(struct mqueue2_t *mqueue);
extern void mqueue2_get_and_reset_stats(struct mqueue2_t *mqueue, struct mqueue2_stats_t *stats);
extern bool mqueue2_enqueue_item(struct mqueue2_t *mqueue, void *item, mqueue2_item_handler_func_t item_handler, size_t byte_cost);
extern bool mqueue2_enqueue_copy(struct mqueue2_t *mqueue, void *item, size_t item_sizeof, mqueue2_item_handler_func_t item_handler, size_t byte_cost);
extern void mqueue2_dequeue_and_execute_item(struct mqueue2_t *mqueue);
extern void mqueue2_thread_execute(void *arg);
