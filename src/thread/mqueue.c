/*
 * mqueue.c
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

THIS_FILE("mqueue");

struct mqueue_item_t
{
	struct dlist_prefix_t dlist_prefix;
	mqueue_read_handler_func_t read_handler;
	size_t length;
};

struct mqueue_t
{
	struct dlist_t queue;
	struct spinlock queue_lock;
	struct thread_signal_t *signal;
	size_t max_queue_depth;
	size_t current_queue_depth;

	struct spinlock current_write_lock;
	struct mqueue_item_t *current_write_item;
	uint8_t *current_write_ptr;
	uint8_t *current_write_end;

	struct spinlock current_read_lock;
	struct mqueue_item_t *current_read_item;
	uint8_t *current_read_ptr;
	uint8_t *current_read_end;
};

mqueue_read_handler_func_t mqueue_read_request(struct mqueue_t *mqueue)
{
	spinlock_lock(&mqueue->queue_lock);
	struct mqueue_item_t *item = dlist_detach_head(struct mqueue_item_t, &mqueue->queue);
	spinlock_unlock(&mqueue->queue_lock);

	if (!item) {
		return NULL;
	}

	spinlock_lock(&mqueue->current_read_lock);
	DEBUG_ASSERT(!mqueue->current_read_item, "internal error");

	mqueue->current_read_item = item;
	mqueue->current_read_ptr = (uint8_t *)(item + 1);
	mqueue->current_read_end = mqueue->current_read_ptr + item->length;

	return item->read_handler;
}

static void mqueue_read(struct mqueue_t *mqueue, void *ptr, size_t length)
{
	DEBUG_ASSERT(mqueue->current_read_item, "mqueue_read called without active request");
	DEBUG_ASSERT(mqueue->current_read_ptr + length <= mqueue->current_read_end, "mqueue read beyond end of item");

	memcpy(ptr, mqueue->current_read_ptr, length);
	mqueue->current_read_ptr += length;
}

uint8_t mqueue_read_u8(struct mqueue_t *mqueue)
{
	uint8_t result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

uint16_t mqueue_read_u16(struct mqueue_t *mqueue)
{
	uint16_t result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

uint32_t mqueue_read_u32(struct mqueue_t *mqueue)
{
	uint32_t result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

uint64_t mqueue_read_u64(struct mqueue_t *mqueue)
{
	uint64_t result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

int mqueue_read_int(struct mqueue_t *mqueue)
{
	int result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

void *mqueue_read_handle(struct mqueue_t *mqueue)
{
	void *result;
	mqueue_read(mqueue, &result, sizeof(result));
	return result;
}

void mqueue_read_complete(struct mqueue_t *mqueue)
{
	DEBUG_ASSERT(mqueue->current_read_item, "mqueue_read_complete called without active request");
	DEBUG_ASSERT(mqueue->current_read_ptr == mqueue->current_read_end, "mqueue read length miss-match");

	heap_free(mqueue->current_read_item);
	mqueue->current_read_item = NULL;
	mqueue->current_read_ptr = NULL;
	mqueue->current_read_end = NULL;

	spinlock_unlock(&mqueue->current_read_lock);

	spinlock_lock(&mqueue->queue_lock);
	mqueue->current_queue_depth--;
	bool signal_needed = (mqueue->current_queue_depth > 0);
	spinlock_unlock(&mqueue->queue_lock);

	if (signal_needed) {
		thread_signal_set(mqueue->signal);
	}
}

bool mqueue_write_request(struct mqueue_t *mqueue, mqueue_read_handler_func_t read_handler, size_t length)
{
	struct mqueue_item_t *item = (struct mqueue_item_t *)heap_alloc_and_zero(sizeof(struct mqueue_item_t) + length, PKG_OS, MEM_TYPE_OS_MQUEUE_ITEM);
	if (!item) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	item->read_handler = read_handler;
	item->length = length;

	spinlock_lock(&mqueue->queue_lock);
	if (mqueue->current_queue_depth >= mqueue->max_queue_depth) {
		spinlock_unlock(&mqueue->queue_lock);
		DEBUG_WARN("mqueue full");
		heap_free(item);
		return false;
	}
	mqueue->current_queue_depth++;
	spinlock_unlock(&mqueue->queue_lock);

	spinlock_lock(&mqueue->current_write_lock);
	DEBUG_ASSERT(!mqueue->current_write_item, "internal error");

	mqueue->current_write_item = item;
	mqueue->current_write_ptr = (uint8_t *)(item + 1);
	mqueue->current_write_end = mqueue->current_write_ptr + length;

	return true;
}

void mqueue_write_request_blocking(struct mqueue_t *mqueue, mqueue_read_handler_func_t read_handler, size_t length)
{
	struct mqueue_item_t *item;
	while (1) {
		item = (struct mqueue_item_t *)heap_alloc_and_zero(sizeof(struct mqueue_item_t) + length, PKG_OS, MEM_TYPE_OS_MQUEUE_ITEM);
		if (!item) {
			thread_yield();
			continue;
		}
		break;
	}

	item->read_handler = read_handler;
	item->length = length;

	while (1) {
		spinlock_lock(&mqueue->queue_lock);
		if (mqueue->current_queue_depth >= mqueue->max_queue_depth) {
			spinlock_unlock(&mqueue->queue_lock);
			thread_yield();
			continue;
		}
		mqueue->current_queue_depth++;
		spinlock_unlock(&mqueue->queue_lock);
		break;
	}

	spinlock_lock(&mqueue->current_write_lock);
	DEBUG_ASSERT(!mqueue->current_write_item, "internal error");

	mqueue->current_write_item = item;
	mqueue->current_write_ptr = (uint8_t *)(item + 1);
	mqueue->current_write_end = mqueue->current_write_ptr + length;
}

static void mqueue_write(struct mqueue_t *mqueue, void *ptr, size_t length)
{
	DEBUG_ASSERT(mqueue->current_write_item, "mqueue_write called without active request");
	DEBUG_ASSERT(mqueue->current_write_ptr + length <= mqueue->current_write_end, "mqueue write beyond end of item");

	memcpy(mqueue->current_write_ptr, ptr, length);
	mqueue->current_write_ptr += length;
}

void mqueue_write_u8(struct mqueue_t *mqueue, uint8_t value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_u16(struct mqueue_t *mqueue, uint16_t value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_u32(struct mqueue_t *mqueue, uint32_t value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_u64(struct mqueue_t *mqueue, uint64_t value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_int(struct mqueue_t *mqueue, int value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_handle(struct mqueue_t *mqueue, void *value)
{
	mqueue_write(mqueue, &value, sizeof(value));
}

void mqueue_write_complete(struct mqueue_t *mqueue)
{
	DEBUG_ASSERT(mqueue->current_write_item, "mqueue_write_complete called without active request");
	DEBUG_ASSERT(mqueue->current_write_ptr == mqueue->current_write_end, "mqueue write length miss-match");

	struct mqueue_item_t *item = mqueue->current_write_item;
	mqueue->current_write_item = NULL;
	mqueue->current_write_ptr = NULL;
	mqueue->current_write_end = NULL;

	spinlock_unlock(&mqueue->current_write_lock);

	spinlock_lock(&mqueue->queue_lock);
	dlist_attach_tail(struct mqueue_item_t, &mqueue->queue, item);
	spinlock_unlock(&mqueue->queue_lock);

	thread_signal_set(mqueue->signal);
}

void mqueue_write_cancel(struct mqueue_t *mqueue)
{
	DEBUG_ASSERT(mqueue->current_write_item, "mqueue_write_cancel called without active request");

	struct mqueue_item_t *item = mqueue->current_write_item;
	mqueue->current_write_item = NULL;
	mqueue->current_write_ptr = NULL;
	mqueue->current_write_end = NULL;

	spinlock_unlock(&mqueue->current_write_lock);

	spinlock_lock(&mqueue->queue_lock);
	mqueue->current_queue_depth--;
	spinlock_unlock(&mqueue->queue_lock);

	heap_free(item);
}

struct mqueue_t *mqueue_alloc(size_t max_queue_depth, struct thread_signal_t *signal)
{
	struct mqueue_t *mqueue = (struct mqueue_t *)heap_alloc_and_zero(sizeof(struct mqueue_t), PKG_OS, MEM_TYPE_OS_MQUEUE);
	if (!mqueue) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	mqueue->signal = signal;
	mqueue->max_queue_depth = max_queue_depth;
	spinlock_init(&mqueue->queue_lock, 0);
	spinlock_init(&mqueue->current_write_lock, 0);
	spinlock_init(&mqueue->current_read_lock, 0);

	return mqueue;
}
