/*
 * mqueue2.c
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("mqueue2");

struct mqueue2_t {
	struct dlist_t queue;
	struct spinlock queue_lock;
	struct thread_signal_t *signal;

	size_t max_queue_depth;
	size_t current_queue_depth;
	size_t worst_queue_depth;

	uint64_t max_queue_bytes;
	uint64_t current_queue_bytes;
	uint64_t worst_queue_bytes;
};

size_t mqueue2_get_current_queue_depth(struct mqueue2_t *mqueue)
{
	spinlock_lock(&mqueue->queue_lock);
	size_t current_queue_depth = mqueue->current_queue_depth;
	spinlock_unlock(&mqueue->queue_lock);
	return current_queue_depth;
}

void mqueue2_get_and_reset_stats(struct mqueue2_t *mqueue, struct mqueue2_stats_t *stats)
{
	spinlock_lock(&mqueue->queue_lock);

	stats->worst_queue_depth = mqueue->worst_queue_depth;
	stats->worst_queue_bytes = mqueue->worst_queue_bytes;

	mqueue->worst_queue_depth = mqueue->current_queue_depth;
	mqueue->worst_queue_bytes = mqueue->current_queue_bytes;

	spinlock_unlock(&mqueue->queue_lock);
}

void mqueue2_dequeue_and_execute_item(struct mqueue2_t *mqueue)
{
	if (!dlist_get_head(struct mqueue2_item_prefix_t, &mqueue->queue)) {
		return;
	}

	spinlock_lock(&mqueue->queue_lock);

	struct mqueue2_item_prefix_t *prefix = dlist_detach_head(struct mqueue2_item_prefix_t, &mqueue->queue);
	if (!prefix) {
		spinlock_unlock(&mqueue->queue_lock);
		return;
	}

	mqueue->current_queue_depth--;
	mqueue->current_queue_bytes -= prefix->byte_cost;

	spinlock_unlock(&mqueue->queue_lock);

	void *item = prefix;
	prefix->item_handler(item);

	if (dlist_get_head(struct mqueue2_item_prefix_t, &mqueue->queue)) {
		thread_signal_set(mqueue->signal);
	}
}

void mqueue2_thread_execute(void *arg)
{
	struct mqueue2_t *mqueue = (struct mqueue2_t *)arg;

	while (1) {
		thread_suspend_wait_for_signal(mqueue->signal);
		mqueue2_dequeue_and_execute_item(mqueue);
	}
}

bool mqueue2_enqueue_item(struct mqueue2_t *mqueue, void *item, mqueue2_item_handler_func_t item_handler, size_t byte_cost)
{
	spinlock_lock(&mqueue->queue_lock);

	if (mqueue->current_queue_depth >= mqueue->max_queue_depth) {
		spinlock_unlock(&mqueue->queue_lock);
		DEBUG_WARN("mqueue full");
		return false;
	}

	if (mqueue->current_queue_bytes + byte_cost > mqueue->max_queue_bytes) {
		spinlock_unlock(&mqueue->queue_lock);
		DEBUG_WARN("mqueue full");
		return false;
	}

	mqueue->current_queue_depth++;
	mqueue->current_queue_bytes += byte_cost;

	if (mqueue->current_queue_depth > mqueue->worst_queue_depth) {
		mqueue->worst_queue_depth = mqueue->current_queue_depth;
	}
	if (mqueue->current_queue_bytes > mqueue->worst_queue_bytes) {
		mqueue->worst_queue_bytes = mqueue->current_queue_bytes;
	}

	struct mqueue2_item_prefix_t *prefix = (struct mqueue2_item_prefix_t *)item;
	prefix->item_handler = item_handler;
	prefix->byte_cost = byte_cost;

	memset(prefix, 0, sizeof(struct dlist_prefix_t));
	dlist_attach_tail(struct mqueue2_item_prefix_t, &mqueue->queue, prefix);

	spinlock_unlock(&mqueue->queue_lock);
	thread_signal_set(mqueue->signal);
	return true;
}

bool mqueue2_enqueue_copy(struct mqueue2_t *mqueue, void *item, size_t item_sizeof, mqueue2_item_handler_func_t item_handler, size_t byte_cost)
{
	void *item_clone = heap_alloc(item_sizeof, PKG_OS, MEM_TYPE_OS_MQUEUE_ITEM);
	if (!item_clone) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	memcpy(item_clone, item, item_sizeof);

	if (!mqueue2_enqueue_item(mqueue, item_clone, item_handler, byte_cost)) {
		heap_free(item_clone);
		return false;
	}

	return true;
}

struct mqueue2_t *mqueue2_alloc(size_t max_queue_depth, uint64_t max_queue_bytes, struct thread_signal_t *signal)
{
	struct mqueue2_t *mqueue = (struct mqueue2_t *)heap_alloc_and_zero(sizeof(struct mqueue2_t), PKG_OS, MEM_TYPE_OS_MQUEUE);
	if (!mqueue) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	mqueue->signal = signal;
	mqueue->max_queue_depth = max_queue_depth;
	mqueue->max_queue_bytes = max_queue_bytes;
	spinlock_init(&mqueue->queue_lock, 0);

	return mqueue;
}
