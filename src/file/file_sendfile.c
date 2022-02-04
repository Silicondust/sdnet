/*
 * file_sendfile.c
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

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("file_sendfile");

#if !defined(FILE_SENDFILE_SEND_SIZE)
#define FILE_SENDFILE_SEND_SIZE (128U * 1024U)
#endif

struct file_sendfile_t {
	struct dlist_prefix_t dlist_prefix;
	struct file_t *file;
	struct tcp_connection *tcp_conn;
	uint64_t bytes_sent;
	uint64_t remaining;

	volatile ticks_t wait_for_more_until;
	volatile bool wait_for_more_pending;
	volatile bool stop_requested;

	file_sendfile_wait_for_more_callback_t wait_for_more_callback;
	file_sendfile_complete_callback_t complete_callback;
	void *callback_arg;
};

struct file_sendfile_manager_t {
	struct dlist_t queue;
	struct spinlock queue_lock;
	struct thread_signal_t *signal;
	ticks_t thread_retry_time;

	struct spinlock stats_lock;
	struct file_sendfile_manager_stats_t stats;
};

static struct file_sendfile_manager_t file_sendfile_manager;

static void file_sendfile_complete(void)
{
	struct file_sendfile_t *sendfile = (struct file_sendfile_t *)mqueue_read_handle(system_app_queue);
	uint8_t result = mqueue_read_u8(system_app_queue);
	mqueue_read_complete(system_app_queue);

	tcp_connection_deref(sendfile->tcp_conn);
	sendfile->tcp_conn = NULL;
	sendfile->file = NULL;

	if (sendfile->stop_requested) {
		result = FILE_SENDFILE_COMPLETE_RESULT_STOP_REQUESTED;
	}

	if (sendfile->complete_callback) {
		sendfile->complete_callback(sendfile->callback_arg, result, sendfile->bytes_sent);
	}

	heap_free(sendfile);
}

static void file_sendfile_wait_for_more(void)
{
	struct file_sendfile_t *sendfile = (struct file_sendfile_t *)mqueue_read_handle(system_app_queue);
	mqueue_read_complete(system_app_queue);

	if (sendfile->stop_requested) {
		return;
	}

	ticks_t delay = sendfile->wait_for_more_callback(sendfile->callback_arg);
	if (sendfile->stop_requested) {
		return;
	}

	ticks_t wait_for_more_until = (delay == TICKS_INFINITE) ? TICKS_INFINITE : timer_get_ticks() + delay;
	sendfile->wait_for_more_until = wait_for_more_until;
	sendfile->wait_for_more_pending = false;
}

static inline void file_sendfile_thread_set_retry_time(void)
{
	if (file_sendfile_manager.thread_retry_time != TICKS_INFINITE) {
		return;
	}
	
	file_sendfile_manager.thread_retry_time = timer_get_ticks() + 16;
}

static int8_t file_sendfile_thread_send(struct file_sendfile_t *sendfile)
{
	if (sendfile->stop_requested) {
		return FILE_SENDFILE_COMPLETE_RESULT_STOP_REQUESTED;
	}

	size_t sz = FILE_SENDFILE_SEND_SIZE;
	if ((uint64_t)sz > sendfile->remaining) {
		sz = (size_t)sendfile->remaining;
	}

	ticks_t start_time = timer_get_ticks();

	size_t actual;
	tcp_error_t ret = tcp_connection_send_file(sendfile->tcp_conn, sendfile->file, sz, &actual);
	if (ret == TCP_ERROR_SOCKET_BUSY) {
		file_sendfile_thread_set_retry_time();
		return FILE_SENDFILE_COMPLETE_RESULT_ACTIVE;
	}
	if (ret == TCP_ERROR_FILE) {
		if (sendfile->wait_for_more_callback) {
			if (!sendfile->wait_for_more_pending && (timer_get_ticks() >= sendfile->wait_for_more_until)) {
				sendfile->wait_for_more_pending = true;
				mqueue_write_request_blocking(system_app_queue, file_sendfile_wait_for_more, MQUEUE_SIZEOF(void *));
				mqueue_write_handle(system_app_queue, sendfile);
				mqueue_write_complete(system_app_queue);
			}

			file_sendfile_thread_set_retry_time();
			return FILE_SENDFILE_COMPLETE_RESULT_ACTIVE;
		}

		DEBUG_INFO("end of file");
		return FILE_SENDFILE_COMPLETE_RESULT_END_OF_FILE;
	}
	if (ret != TCP_OK) {
		DEBUG_INFO("tcp error");
		return FILE_SENDFILE_COMPLETE_RESULT_CONNECTION_CLOSED;
	}

	ticks_t duration = timer_get_ticks() - start_time;

	spinlock_lock(&file_sendfile_manager.stats_lock);
	file_sendfile_manager.stats.disk_read_bytes += actual;
	file_sendfile_manager.stats.disk_read_time += duration;
	if (duration > file_sendfile_manager.stats.disk_read_worst_time) {
		file_sendfile_manager.stats.disk_read_worst_time = duration;
	}
	spinlock_unlock(&file_sendfile_manager.stats_lock);

	sendfile->bytes_sent += actual;
	sendfile->remaining -= actual;
	if (sendfile->remaining == 0) {
		DEBUG_INFO("end of range requested");
		return FILE_SENDFILE_COMPLETE_RESULT_TRANSFER_LENGTH_REACHED;
	}

	if (actual < sz) {
		file_sendfile_thread_set_retry_time();
		return FILE_SENDFILE_COMPLETE_RESULT_ACTIVE;
	}

	thread_signal_set(file_sendfile_manager.signal); /* skip 16ms loop pause */
	return FILE_SENDFILE_COMPLETE_RESULT_ACTIVE;
}

static struct file_sendfile_t *file_sendfile_thread_get_first_sendfile(void)
{
	if (timer_get_ticks() >= file_sendfile_manager.thread_retry_time) {
		thread_signal_set(file_sendfile_manager.signal);
	}

	thread_suspend_wait_for_signal_or_ticks(file_sendfile_manager.signal, 16);
	file_sendfile_manager.thread_retry_time = TICKS_INFINITE;

	while (1) {
		spinlock_lock(&file_sendfile_manager.queue_lock);
		struct file_sendfile_t *sendfile = dlist_get_head(struct file_sendfile_t, &file_sendfile_manager.queue);
		spinlock_unlock(&file_sendfile_manager.queue_lock);

		if (sendfile) {
			return sendfile;
		}

		thread_suspend_wait_for_signal(file_sendfile_manager.signal);
	}
}

static struct file_sendfile_t *file_sendfile_thread_get_next_sendfile(struct file_sendfile_t *sendfile)
{
	spinlock_lock(&file_sendfile_manager.queue_lock);
	struct file_sendfile_t *next_sendfile = dlist_get_next(struct file_sendfile_t, sendfile);
	spinlock_unlock(&file_sendfile_manager.queue_lock);

	if (!next_sendfile) {
		return file_sendfile_thread_get_first_sendfile();
	}
	
	return next_sendfile;
}

static struct file_sendfile_t *file_sendfile_thread_close_sendfile_get_next(struct file_sendfile_t *sendfile, uint8_t result)
{
	spinlock_lock(&file_sendfile_manager.queue_lock);
	struct file_sendfile_t *next_sendfile = dlist_get_next(struct file_sendfile_t, sendfile);
	(void)dlist_detach_item(struct file_sendfile_t, &file_sendfile_manager.queue, sendfile);
	spinlock_unlock(&file_sendfile_manager.queue_lock);

	mqueue_write_request_blocking(system_app_queue, file_sendfile_complete, MQUEUE_SIZEOF(void *) + MQUEUE_SIZEOF(uint8_t));
	mqueue_write_handle(system_app_queue, sendfile);
	mqueue_write_u8(system_app_queue, result);
	mqueue_write_complete(system_app_queue);

	if (!next_sendfile) {
		return file_sendfile_thread_get_first_sendfile();
	}

	return next_sendfile;
}

static void file_sendfile_thread_execute(void *arg)
{
	struct file_sendfile_t *sendfile = file_sendfile_thread_get_first_sendfile();
	while (1) {
		uint8_t result = file_sendfile_thread_send(sendfile);
		if (result != FILE_SENDFILE_COMPLETE_RESULT_ACTIVE) {
			sendfile = file_sendfile_thread_close_sendfile_get_next(sendfile, result);
			continue;
		}

		sendfile = file_sendfile_thread_get_next_sendfile(sendfile);
	}
}

void file_sendfile_request_stop(struct file_sendfile_t *sendfile)
{
	sendfile->stop_requested = true;
	thread_signal_set(file_sendfile_manager.signal);
}

struct file_sendfile_t *file_sendfile_start(struct file_t *file, struct tcp_connection *tcp_conn, uint64_t transfer_length, file_sendfile_wait_for_more_callback_t wait_for_more_callback, file_sendfile_complete_callback_t complete_callback, void *callback_arg)
{
	struct file_sendfile_t *sendfile = (struct file_sendfile_t *)heap_alloc_and_zero(sizeof(struct file_sendfile_t), PKG_OS, MEM_TYPE_OS_FILE_SENDFILE);
	if (!sendfile) {
		return NULL;
	}

	sendfile->file = file;
	sendfile->tcp_conn = tcp_connection_ref(tcp_conn);
	sendfile->remaining = transfer_length;

	sendfile->wait_for_more_callback = wait_for_more_callback;
	sendfile->complete_callback = complete_callback;
	sendfile->callback_arg = callback_arg;

	spinlock_lock(&file_sendfile_manager.queue_lock);
	dlist_attach_tail(struct file_sendfile_t, &file_sendfile_manager.queue, sendfile);
	spinlock_unlock(&file_sendfile_manager.queue_lock);
	thread_signal_set(file_sendfile_manager.signal);

	return sendfile;
}

void file_sendfile_manager_get_and_reset_stats(struct file_sendfile_manager_stats_t *stats)
{
	spinlock_lock(&file_sendfile_manager.stats_lock);
	stats->disk_read_bytes = file_sendfile_manager.stats.disk_read_bytes;
	stats->disk_read_time = file_sendfile_manager.stats.disk_read_time;
	stats->disk_read_worst_time = file_sendfile_manager.stats.disk_read_worst_time;
	file_sendfile_manager.stats.disk_read_bytes = 0;
	file_sendfile_manager.stats.disk_read_time = 0;
	file_sendfile_manager.stats.disk_read_worst_time = 0;
	spinlock_unlock(&file_sendfile_manager.stats_lock);
}

void file_sendfile_manager_start(void)
{
	thread_start(file_sendfile_thread_execute, NULL);
}

void file_sendfile_manager_init(void)
{
	file_sendfile_manager.signal = thread_signal_alloc();
	spinlock_init(&file_sendfile_manager.queue_lock, 0);
	spinlock_init(&file_sendfile_manager.stats_lock, 0);
	file_sendfile_manager.thread_retry_time = TICKS_INFINITE;
}
