/*
 * ./src/default/heap.c
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

THIS_FILE("heap");

#define HEAP_BLOCK_MAGIC 0x09f5e1b6
#define HEAP_BLOCK_FOOTPRINT_DETECT 0xaf7fd913

struct heap_block_t
{
	struct dlist_prefix_t dlist_prefix;
	size_t size;
	uint32_t magic;
	uint8_t pkg;
	uint8_t type;
	bool leaktrack_ignore;
};

struct heap_manager_t
{
	struct dlist_t alloc_list;
	struct spinlock lock;
	size_t total_allocated;
};

static struct heap_manager_t heap_manager;

void *heap_alloc(size_t size, uint8_t pkg, uint8_t type)
{
	size = (size + 3) & ~3;
	size_t footprint_detect_size = (RUNTIME_DEBUG) ? 4 : 0;

	struct heap_block_t *heap_block = (struct heap_block_t *)malloc(sizeof(struct heap_block_t) + size + footprint_detect_size);
	if (!heap_block) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	memset(&heap_block->dlist_prefix, 0, sizeof(heap_block->dlist_prefix));
	heap_block->size = size;
	heap_block->magic = HEAP_BLOCK_MAGIC;
	heap_block->pkg = pkg;
	heap_block->type = type;

	void *block = heap_block + 1;

	if (RUNTIME_DEBUG) {
		void *ptr = (uint8_t *)block + heap_block->size;
		*(uint32_t *)ptr = HEAP_BLOCK_FOOTPRINT_DETECT;
	}

	spinlock_lock(&heap_manager.lock);
	dlist_attach_head(struct heap_block_t, &heap_manager.alloc_list, heap_block);
	heap_manager.total_allocated += size;
	spinlock_unlock(&heap_manager.lock);

	return block;
}

void *heap_alloc_and_zero(size_t size, uint8_t pkg, uint8_t type)
{
	size = (size + 3) & ~3;
	size_t footprint_detect_size = (RUNTIME_DEBUG) ? 4 : 0;

	struct heap_block_t *heap_block = (struct heap_block_t *)calloc(1, sizeof(struct heap_block_t) + size + footprint_detect_size);
	if (!heap_block) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	heap_block->size = size;
	heap_block->magic = HEAP_BLOCK_MAGIC;
	heap_block->pkg = pkg;
	heap_block->type = type;

	void *block = heap_block + 1;

	if (RUNTIME_DEBUG) {
		void *ptr = (uint8_t *)block + heap_block->size;
		*(uint32_t *)ptr = HEAP_BLOCK_FOOTPRINT_DETECT;
	}

	spinlock_lock(&heap_manager.lock);
	dlist_attach_head(struct heap_block_t, &heap_manager.alloc_list, heap_block);
	heap_manager.total_allocated += heap_block->size;
	spinlock_unlock(&heap_manager.lock);

	return block;
}

void *heap_realloc(void *block, size_t size, uint8_t pkg, uint8_t type)
{
	DEBUG_ASSERT(size > 0, "heap_realloc of 0 bytes");

	if (!block) {
		return heap_alloc(size, pkg, type);
	}

	/* Check exisitng block. */
	struct heap_block_t *old_heap_block = (struct heap_block_t *)block;
	old_heap_block--;

	if (old_heap_block->magic != HEAP_BLOCK_MAGIC) {
		DEBUG_ASSERT(0, "invalid magic");
		return NULL;
	}

	DEBUG_ASSERT(pkg == old_heap_block->pkg, "realloc with different pkg");
	DEBUG_ASSERT(type == old_heap_block->type, "realloc with different type");

	if (RUNTIME_DEBUG) {
		void *ptr = (uint8_t *)block + old_heap_block->size;
		DEBUG_ASSERT(*(uint32_t *)ptr == HEAP_BLOCK_FOOTPRINT_DETECT, "buffer overflow detected");
	}

	/* Remove from list tracking. */
	spinlock_lock(&heap_manager.lock);
	if (!dlist_detach_item(struct heap_block_t, &heap_manager.alloc_list, old_heap_block)) {
		DEBUG_ASSERT(0, "heap block not on alloc list");
	}
	heap_manager.total_allocated -= old_heap_block->size;
	spinlock_unlock(&heap_manager.lock);

	/* New block */
	size = (size + 3) & ~3;
	size_t footprint_detect_size = (RUNTIME_DEBUG) ? 4 : 0;

	struct heap_block_t *new_heap_block = (struct heap_block_t *)realloc(old_heap_block, sizeof(struct heap_block_t) + size + footprint_detect_size);
	if (!new_heap_block) {
		DEBUG_ERROR("out of memory");
		/* Old block still valid - add to tracking list again. */
		spinlock_lock(&heap_manager.lock);
		dlist_attach_head(struct heap_block_t, &heap_manager.alloc_list, old_heap_block);
		heap_manager.total_allocated += old_heap_block->size;
		spinlock_unlock(&heap_manager.lock);
		return NULL;
	}

	new_heap_block->size = size;
	block = new_heap_block + 1;

	if (RUNTIME_DEBUG) {
		void *ptr = (uint8_t *)block + new_heap_block->size;
		*(uint32_t *)ptr = HEAP_BLOCK_FOOTPRINT_DETECT;
	}

	spinlock_lock(&heap_manager.lock);
	dlist_attach_head(struct heap_block_t, &heap_manager.alloc_list, new_heap_block);
	heap_manager.total_allocated += new_heap_block->size;
	spinlock_unlock(&heap_manager.lock);

	return block;
}

char *heap_strdup(const char *str, uint8_t pkg, uint8_t type)
{
	size_t size = strlen(str);
	char *result = (char *)heap_alloc(size + 1, pkg, type);
	if (!result) {
		return NULL;
	}

	memcpy(result, str, size + 1);
	return result;
}

char *heap_netbuf_strdup(struct netbuf *nb, uint8_t pkg, uint8_t type)
{
	size_t size = netbuf_get_remaining(nb);
	char *result = (char *)heap_alloc(size + 1, pkg, type);
	if (!result) {
		return NULL;
	}

	if (size > 0) {
		netbuf_fwd_read(nb, result, size);
		netbuf_retreat_pos(nb, size);
	}

	result[size] = 0;
	return result;
}

bool heap_verify(void *block)
{
	if (!block) {
		DEBUG_ERROR("heap verify failed %p", block);
		return false;
	}

	struct heap_block_t *heap_block = (struct heap_block_t *)block;
	heap_block--;

	if (heap_block->magic != HEAP_BLOCK_MAGIC) {
		DEBUG_ERROR("heap verify failed %p", block);
		return false;
	}

	return true;
}

void heap_free(void *block)
{
	struct heap_block_t *heap_block = (struct heap_block_t *)block;
	heap_block--;

	if (heap_block->magic != HEAP_BLOCK_MAGIC) {
		DEBUG_ASSERT(0, "invalid magic or double free");
		return;
	}

	if (RUNTIME_DEBUG) {
		void *ptr = (uint8_t *)block + heap_block->size;
		DEBUG_ASSERT(*(uint32_t *)ptr == HEAP_BLOCK_FOOTPRINT_DETECT, "buffer overflow detected");
	}

	spinlock_lock(&heap_manager.lock);
	if (!dlist_detach_item(struct heap_block_t, &heap_manager.alloc_list, heap_block)) {
		DEBUG_ASSERT(0, "heap block not on alloc list");
	}
	heap_manager.total_allocated -= heap_block->size;
	spinlock_unlock(&heap_manager.lock);

	heap_block->magic = 0;
	free(heap_block);
}

void heap_leaktrack_set_ignore(void *block)
{
	struct heap_block_t *heap_block = (struct heap_block_t *)block;
	heap_block--;

	if (heap_block->magic != HEAP_BLOCK_MAGIC) {
		DEBUG_ASSERT(0, "invalid magic or double free");
		return;
	}

	spinlock_lock(&heap_manager.lock);
	heap_block->leaktrack_ignore = true;
	spinlock_unlock(&heap_manager.lock);
}

void heap_leaktrack_set_ignore_all(void)
{
	spinlock_lock(&heap_manager.lock);

	struct heap_block_t *heap_block = dlist_get_head(struct heap_block_t, &heap_manager.alloc_list);
	while (heap_block) {
		heap_block->leaktrack_ignore = true;
		heap_block = dlist_get_next(struct heap_block_t, heap_block);
	}

	spinlock_unlock(&heap_manager.lock);
}

static void heap_leaktrack_log_state_pkg(uint8_t pkg)
{
	uint16_t counts[256];
	memset(counts, 0, sizeof(counts));

	spinlock_lock(&heap_manager.lock);

	struct heap_block_t *heap_block = dlist_get_head(struct heap_block_t, &heap_manager.alloc_list);
	while (heap_block) {
		if (heap_block->leaktrack_ignore || (heap_block->pkg != pkg)) {
			heap_block = dlist_get_next(struct heap_block_t, heap_block);
			continue;
		}

		if (counts[heap_block->type] < 0xFFFF) {
			counts[heap_block->type]++;
		}

		heap_block = dlist_get_next(struct heap_block_t, heap_block);
	}

	spinlock_unlock(&heap_manager.lock);

	for (uint16_t type = 0; type < 256; type++) {
		uint16_t count = counts[type];
		if (count > 0) {
			log_trace("Memory", "pkg %u type %u count %u", pkg, type, count);
		}
	}
}

void heap_leaktrack_log_state(void)
{
	/*
	 * Check allocation counts by pkg.
	 */
	uint16_t counts[256];
	memset(counts, 0, sizeof(counts));

	spinlock_lock(&heap_manager.lock);

	struct heap_block_t *heap_block = dlist_get_head(struct heap_block_t, &heap_manager.alloc_list);
	while (heap_block) {
		if (heap_block->leaktrack_ignore) {
			heap_block = dlist_get_next(struct heap_block_t, heap_block);
			continue;
		}

		if (counts[heap_block->pkg] < 0xFFFF) {
			counts[heap_block->pkg]++;
		}

		heap_block = dlist_get_next(struct heap_block_t, heap_block);
	}

	spinlock_unlock(&heap_manager.lock);

	/*
	 * Output worst 4 packages.
	 */
	for (uint8_t i = 0; i < 4; i++) {
		uint8_t worst_pkg = 0;
		uint16_t worst_count = 0;

		for (uint16_t pkg = 0; pkg < 256; pkg++) {
			uint16_t count = counts[pkg];
			if (count > worst_count) {
				worst_pkg = (uint8_t)pkg;
				worst_count = count;
			}
		}

		if (worst_count == 0) {
			break;
		}

		heap_leaktrack_log_state_pkg(worst_pkg);
		counts[worst_pkg] = 0;
	}
}

size_t heap_manager_get_total_allocated(void)
{
	spinlock_lock(&heap_manager.lock);
	size_t result = heap_manager.total_allocated;
	spinlock_unlock(&heap_manager.lock);
	return result;
}

void heap_manager_init(void)
{
	spinlock_init(&heap_manager.lock, 0);
}
