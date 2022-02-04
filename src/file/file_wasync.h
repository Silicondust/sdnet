/*
 * file_wasync.h
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct file_wasync_t;

typedef void (*file_wasync_callback_t)(void *arg, uint64_t position);

struct file_wasync_manager_stats_t {
	uint64_t disk_write_bytes;
	ticks_t disk_write_time;
	ticks_t disk_write_worst_time;

	uint64_t queue_current_bytes;
	size_t queue_current_netbufs;
	size_t queue_current_depth;

	uint64_t queue_worst_bytes;
	size_t queue_worst_netbufs;
	size_t queue_worst_depth;
};

/*
 * Use file_wasync_callback() to receive a callback when all write transactions up until this point have been written to disk.
 * Can also be used when there are no write transactions to get a callback from the wasync worker thread in order to do other file operations.
 * Note that the callback will occur even if file_wasync_close() has been called.
 */

extern struct file_wasync_t *file_wasync_open_create(const char *path);
extern struct file_wasync_t *file_wasync_open_existing(const char *path);
extern bool file_wasync_steal_and_write(struct file_wasync_t *file, struct netbuf *nb);
extern bool file_wasync_buffer_and_write(struct file_wasync_t *file, uint8_t *ptr, uint8_t *end);
extern bool file_wasync_callback(struct file_wasync_t *file, file_wasync_callback_t callback, void *callback_arg, bool mainline);
extern bool file_wasync_seek_set(struct file_wasync_t *file, uint64_t offset);
extern bool file_wasync_seek_advance(struct file_wasync_t *file, uint64_t offset);
extern bool file_wasync_seek_retreat(struct file_wasync_t *file, uint64_t offset);
extern bool file_wasync_seek_end(struct file_wasync_t *file);
extern uint64_t file_wasync_get_pos(struct file_wasync_t *file, uint64_t result_on_error);
extern void file_wasync_close(struct file_wasync_t *file);

extern void file_wasync_manager_init(void);
extern void file_wasync_manager_start(void);
extern void file_wasync_manager_get_and_reset_stats(struct file_wasync_manager_stats_t *stats);
