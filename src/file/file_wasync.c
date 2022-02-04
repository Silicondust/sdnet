/*
 * file_wasync.c
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

THIS_FILE("file_wasync");

#if !defined(FILE_WASYNC_QUEUE_MAX_AGE)
#define FILE_WASYNC_QUEUE_MAX_AGE (10ULL * TICK_RATE)
#endif

#if !defined(FILE_WASYNC_MAX_APPEND_NETBUFS)
#define FILE_WASYNC_MAX_APPEND_NETBUFS 8U
#endif

#if !defined(FILE_WASYNC_MAX_APPEND_BYTES)
#define FILE_WASYNC_MAX_APPEND_BYTES (128U * 1024U)
#endif

struct file_wasync_operation_t {
	struct dlist_prefix_t dlist_prefix;
	struct file_wasync_t *file;
	uint64_t position;
	struct netbuf_queue nb_queue;
	size_t length;
	ticks_t enqueue_timestamp;

	file_wasync_callback_t callback;
	void *callback_arg;
	bool callback_mainline;
};

struct file_wasync_t {
	struct file_t *fp;
	volatile int refs;
	bool api_closed;
	bool error;

	uint64_t api_filesize;
	uint64_t api_position;
	uint64_t thread_position;

	struct file_wasync_operation_t *appendable_operation;
};

struct file_wasync_manager_t {
	struct dlist_t queue;
	struct spinlock queue_lock;
	struct thread_signal_t *signal;

	struct spinlock file_refs_lock;

	size_t current_queue_depth;
	size_t current_queue_netbufs;
	uint64_t current_queue_bytes;
	ticks_t current_timeout;

	struct spinlock stats_lock;
	struct file_wasync_manager_stats_t stats;
};

static struct file_wasync_manager_t file_wasync_manager;

static struct file_wasync_t *file_wasync_ref(struct file_wasync_t *file)
{
	spinlock_lock(&file_wasync_manager.file_refs_lock);
	file->refs++;
	spinlock_unlock(&file_wasync_manager.file_refs_lock);
	return file;
}

static int file_wasync_deref(struct file_wasync_t *file)
{
	spinlock_lock(&file_wasync_manager.file_refs_lock);
	int refs = --file->refs;
	spinlock_unlock(&file_wasync_manager.file_refs_lock);

	if (refs != 0) {
		return refs;
	}

	DEBUG_ASSERT(file->api_closed, "deref free without close");

	file_close(file->fp);
	heap_free(file);
	return 0;
}

void file_wasync_close(struct file_wasync_t *file)
{
	file->api_closed = true;
	file_wasync_deref(file);
}

uint64_t file_wasync_get_pos(struct file_wasync_t *file, uint64_t result_on_error)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return result_on_error;
	}

	return file->api_position;
}

bool file_wasync_seek_set(struct file_wasync_t *file, uint64_t offset)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	file->api_position = offset;
	return true;
}

bool file_wasync_seek_advance(struct file_wasync_t *file, uint64_t offset)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	uint64_t target_position = file->api_position + offset;
	if (target_position < file->api_position) {
		return false;
	}

	file->api_position = target_position;
	return true;
}

bool file_wasync_seek_retreat(struct file_wasync_t *file, uint64_t offset)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	uint64_t target_position = file->api_position - offset;
	if (target_position > file->api_position) {
		return false;
	}

	file->api_position = target_position;
	return true;
}

bool file_wasync_seek_end(struct file_wasync_t *file)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	file->api_position = file->api_filesize;
	return true;
}

static void file_wasync_mainline_callback(void)
{
	file_wasync_callback_t callback = (file_wasync_callback_t)mqueue_read_handle(system_app_queue);
	void *callback_arg = mqueue_read_handle(system_app_queue);
	uint64_t position = mqueue_read_u64(system_app_queue);
	mqueue_read_complete(system_app_queue);

	callback(callback_arg, position);
}

static void file_wasync_thread_write_stats(uint64_t actual, ticks_t duration)
{
	spinlock_lock(&file_wasync_manager.stats_lock);

	file_wasync_manager.stats.disk_write_bytes += actual;
	file_wasync_manager.stats.disk_write_time += duration;

	if (duration > file_wasync_manager.stats.disk_write_worst_time) {
		file_wasync_manager.stats.disk_write_worst_time = duration;
	}

	spinlock_unlock(&file_wasync_manager.stats_lock);
}

static void file_wasync_thread_write(struct file_wasync_t *file, uint64_t position, struct netbuf_queue *nb_queue, size_t length)
{
	if (file->error) {
		return;
	}

	if (timer_get_ticks() >= file_wasync_manager.current_timeout) {
		log_trace("Filesystem", "wasync excessive lag");
		file->error = true;
		return;
	}

	if (file->thread_position != position) {
		if (!file_seek_set(file->fp, position)) {
			log_trace("Filesystem", "wasync seek failed %llu->%llu", file->thread_position, position);
			file->error = true;
			return;
		}

		file->thread_position = position;
	}

	ticks_t start_time = timer_get_ticks();
	size_t actual = file_write_nb_queue(file->fp, nb_queue);
	ticks_t duration = timer_get_ticks() - start_time;

	file_wasync_thread_write_stats(actual, duration);

	if (actual != length) {
		log_trace("Filesystem", "wasync write failed (%u of %u at %llu)", (unsigned int)actual, (unsigned int)length, file->thread_position);
		file->error = true;
		return;
	}

	file->thread_position += length;
}

static void file_wasync_thread_execute(void *arg)
{
	while (1) {
		spinlock_lock(&file_wasync_manager.queue_lock);

		struct file_wasync_operation_t *operation = dlist_detach_head(struct file_wasync_operation_t, &file_wasync_manager.queue);
		if (!operation) {
			file_wasync_manager.current_timeout = TICKS_INFINITE;
			spinlock_unlock(&file_wasync_manager.queue_lock);
			thread_suspend_wait_for_signal(file_wasync_manager.signal);
			continue;
		}

		struct file_wasync_t *file = operation->file;
		if (file->appendable_operation == operation) {
			file->appendable_operation = NULL;
		}

		file_wasync_manager.current_queue_depth--;
		file_wasync_manager.current_queue_netbufs -= netbuf_queue_get_count(&operation->nb_queue);
		file_wasync_manager.current_queue_bytes -= operation->length;
		file_wasync_manager.current_timeout = operation->enqueue_timestamp + FILE_WASYNC_QUEUE_MAX_AGE;

		spinlock_unlock(&file_wasync_manager.queue_lock);

		if (operation->length > 0) {
			file_wasync_thread_write(file, operation->position, &operation->nb_queue, operation->length);
			netbuf_queue_detach_and_free_all(&operation->nb_queue);
		}

		if (operation->callback) {
			uint64_t position = (file->error) ? (uint64_t)-1 : operation->position + operation->length;
			if (operation->callback_mainline) {
				mqueue_write_request_blocking(system_app_queue, file_wasync_mainline_callback, MQUEUE_SIZEOF(void *) * 2 + MQUEUE_SIZEOF(uint64_t));
				mqueue_write_handle(system_app_queue, operation->callback);
				mqueue_write_handle(system_app_queue, operation->callback_arg);
				mqueue_write_u64(system_app_queue, position);
				mqueue_write_complete(system_app_queue);
			} else {
				operation->callback(operation->callback_arg, position);
			}
		}

		file_wasync_deref(operation->file);
		heap_free(operation);
	}
}

static bool file_wasync_api_write_internal_try_append(struct file_wasync_t *file, struct netbuf *nb, size_t length)
{
	struct file_wasync_operation_t *operation = file->appendable_operation;
	if (!operation) {
		return false;
	}

	if (file->api_position != operation->position + operation->length) {
		return false;
	}

	if (operation->length + length > FILE_WASYNC_MAX_APPEND_BYTES) {
		return false;
	}

	if (netbuf_queue_get_count(&operation->nb_queue) >= FILE_WASYNC_MAX_APPEND_NETBUFS) {
		return false;
	}

	netbuf_queue_attach_tail(&operation->nb_queue, nb);
	operation->length += length;

	file_wasync_manager.current_queue_netbufs++;
	file_wasync_manager.current_queue_bytes += length;

	return true;
}

static bool file_wasync_api_write_common_internal(struct file_wasync_t *file, struct netbuf *nb, size_t length)
{
	ticks_t current_time = timer_get_ticks();

	if (current_time >= file_wasync_manager.current_timeout) {
		log_trace("Filesystem", "wasync excessive lag");
		return false;
	}

	if (file_wasync_api_write_internal_try_append(file, nb, length)) {
		return true;
	}

	struct file_wasync_operation_t *operation = heap_alloc_and_zero(sizeof(struct file_wasync_operation_t), PKG_OS, MEM_TYPE_OS_FILE_WASYNC_OPERATION);
	if (!operation) {
		DEBUG_WARN("out of memory");
		return false;
	}

	operation->file = file_wasync_ref(file);
	operation->position = file->api_position;
	netbuf_queue_attach_tail(&operation->nb_queue, nb);
	operation->length = length;
	operation->enqueue_timestamp = current_time;

	file->appendable_operation = operation;
	dlist_attach_tail(struct file_wasync_operation_t, &file_wasync_manager.queue, operation);

	file_wasync_manager.current_queue_depth++;
	file_wasync_manager.current_queue_netbufs++;
	file_wasync_manager.current_queue_bytes += length;

	thread_signal_set(file_wasync_manager.signal);
	return true;
}

static bool file_wasync_api_write_common(struct file_wasync_t *file, struct netbuf *nb)
{
	size_t length = netbuf_get_extent(nb);

	spinlock_lock(&file_wasync_manager.queue_lock);

	if (!file_wasync_api_write_common_internal(file, nb, length)) {
		spinlock_unlock(&file_wasync_manager.queue_lock);
		return false;
	}

	if (file_wasync_manager.current_queue_depth > file_wasync_manager.stats.queue_worst_depth) {
		file_wasync_manager.stats.queue_worst_depth = file_wasync_manager.current_queue_depth;
	}
	if (file_wasync_manager.current_queue_netbufs > file_wasync_manager.stats.queue_worst_netbufs) {
		file_wasync_manager.stats.queue_worst_netbufs = file_wasync_manager.current_queue_netbufs;
	}
	if (file_wasync_manager.current_queue_bytes > file_wasync_manager.stats.queue_worst_bytes) {
		file_wasync_manager.stats.queue_worst_bytes = file_wasync_manager.current_queue_bytes;
	}

	spinlock_unlock(&file_wasync_manager.queue_lock);

	file->api_position += length;

	if (file->api_position > file->api_filesize) {
		file->api_filesize = file->api_position;
	}

	return true;
}

bool file_wasync_steal_and_write(struct file_wasync_t *file, struct netbuf *nb)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	struct netbuf *nb_clone = netbuf_alloc_and_steal(nb);
	if (!nb_clone) {
		DEBUG_WARN("out of memory");
		return false;
	}

	netbuf_set_pos_to_start(nb_clone);

	if (!file_wasync_api_write_common(file, nb_clone)) {
		netbuf_free(nb_clone);
		return false;
	}

	return true;
}

bool file_wasync_buffer_and_write(struct file_wasync_t *file, uint8_t *ptr, uint8_t *end)
{
	DEBUG_ASSERT(!file->api_closed, "api call after close");

	if (file->error) {
		return false;
	}

	size_t length = end - ptr;
	struct netbuf *nb = netbuf_alloc_with_fwd_space(length);
	if (!nb) {
		DEBUG_WARN("out of memory");
		return false;
	}

	netbuf_fwd_write(nb, ptr, length);
	netbuf_set_pos_to_start(nb);

	if (!file_wasync_api_write_common(file, nb)) {
		netbuf_free(nb);
		return false;
	}

	return true;
}

bool file_wasync_callback(struct file_wasync_t *file, file_wasync_callback_t callback, void *callback_arg, bool mainline)
{
	spinlock_lock(&file_wasync_manager.queue_lock);

	struct file_wasync_operation_t *operation = file->appendable_operation;
	file->appendable_operation = NULL;

	if (operation && (file->api_position == operation->position + operation->length)) {
		operation->callback = callback;
		operation->callback_arg = callback_arg;
		operation->callback_mainline = mainline;
		spinlock_unlock(&file_wasync_manager.queue_lock);
		return true;
	}

	operation = heap_alloc_and_zero(sizeof(struct file_wasync_operation_t), PKG_OS, MEM_TYPE_OS_FILE_WASYNC_OPERATION);
	if (!operation) {
		spinlock_unlock(&file_wasync_manager.queue_lock);
		DEBUG_WARN("out of memory");
		return false;
	}

	operation->file = file_wasync_ref(file);
	operation->position = file->api_position;
	operation->enqueue_timestamp = timer_get_ticks();
	operation->callback = callback;
	operation->callback_arg = callback_arg;
	operation->callback_mainline = mainline;

	dlist_attach_tail(struct file_wasync_operation_t, &file_wasync_manager.queue, operation);
	file_wasync_manager.current_queue_depth++;
	if (file_wasync_manager.current_queue_depth > file_wasync_manager.stats.queue_worst_depth) {
		file_wasync_manager.stats.queue_worst_depth = file_wasync_manager.current_queue_depth;
	}

	thread_signal_set(file_wasync_manager.signal);
	spinlock_unlock(&file_wasync_manager.queue_lock);
	return true;
}

static struct file_wasync_t *file_wasync_open_internal(struct file_t *fp)
{
	if (!file_seek_end(fp)) {
		return NULL;
	}

	uint64_t filesize = file_get_pos(fp, (uint64_t)-1);
	if (filesize == (uint64_t)-1) {
		return NULL;
	}

	struct file_wasync_t *file = (struct file_wasync_t *)heap_alloc_and_zero(sizeof(struct file_wasync_t), PKG_OS, MEM_TYPE_OS_FILE_WASYNC);
	if (!file) {
		return NULL;
	}

	file->fp = fp;
	file->refs = 1;
	file->api_filesize = filesize;
	file->thread_position = filesize;

	return file;
}

struct file_wasync_t *file_wasync_open_create(const char *path)
{
	struct file_t *fp = file_open_create(path);
	if (!fp) {
		return NULL;
	}

	struct file_wasync_t *file = file_wasync_open_internal(fp);
	if (!file) {
		file_close(fp);
		return NULL;
	}

	return file;
}

struct file_wasync_t *file_wasync_open_existing(const char *path)
{
	struct file_t *fp = file_open_existing(path);
	if (!fp) {
		return NULL;
	}

	struct file_wasync_t *file = file_wasync_open_internal(fp);
	if (!file) {
		file_close(fp);
		return NULL;
	}

	return file;
}

void file_wasync_manager_get_and_reset_stats(struct file_wasync_manager_stats_t *stats)
{
	spinlock_lock(&file_wasync_manager.stats_lock);
	stats->disk_write_bytes = file_wasync_manager.stats.disk_write_bytes;
	stats->disk_write_time = file_wasync_manager.stats.disk_write_time;
	stats->disk_write_worst_time = file_wasync_manager.stats.disk_write_worst_time;
	file_wasync_manager.stats.disk_write_bytes = 0;
	file_wasync_manager.stats.disk_write_time = 0;
	file_wasync_manager.stats.disk_write_worst_time = 0;
	spinlock_unlock(&file_wasync_manager.stats_lock);

	spinlock_lock(&file_wasync_manager.queue_lock);
	stats->queue_worst_depth = file_wasync_manager.stats.queue_worst_depth;
	stats->queue_worst_netbufs = file_wasync_manager.stats.queue_worst_netbufs;
	stats->queue_worst_bytes = file_wasync_manager.stats.queue_worst_bytes;
	stats->queue_current_depth = file_wasync_manager.current_queue_depth;
	stats->queue_current_netbufs = file_wasync_manager.current_queue_netbufs;
	stats->queue_current_bytes = file_wasync_manager.current_queue_bytes;
	file_wasync_manager.stats.queue_worst_depth = file_wasync_manager.current_queue_depth;
	file_wasync_manager.stats.queue_worst_netbufs = file_wasync_manager.current_queue_netbufs;
	file_wasync_manager.stats.queue_worst_bytes = file_wasync_manager.current_queue_bytes;
	spinlock_unlock(&file_wasync_manager.queue_lock);
}

void file_wasync_manager_start(void)
{
	thread_start(file_wasync_thread_execute, NULL);
}

void file_wasync_manager_init(void)
{
	file_wasync_manager.current_timeout = TICKS_INFINITE;
	file_wasync_manager.signal = thread_signal_alloc();

	spinlock_init(&file_wasync_manager.queue_lock, 0);
	spinlock_init(&file_wasync_manager.file_refs_lock, 0);
	spinlock_init(&file_wasync_manager.stats_lock, 0);
}
