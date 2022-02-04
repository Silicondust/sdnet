/*
 * file_sendfile.h
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct file_sendfile_t;

#define FILE_SENDFILE_COMPLETE_RESULT_ACTIVE 0
#define FILE_SENDFILE_COMPLETE_RESULT_STOP_REQUESTED 1
#define FILE_SENDFILE_COMPLETE_RESULT_TRANSFER_LENGTH_REACHED 2
#define FILE_SENDFILE_COMPLETE_RESULT_END_OF_FILE 3
#define FILE_SENDFILE_COMPLETE_RESULT_CONNECTION_CLOSED 4

typedef ticks_t (*file_sendfile_wait_for_more_callback_t)(void *arg);
typedef void (*file_sendfile_complete_callback_t)(void *arg, uint8_t result, uint64_t bytes_sent);

struct file_sendfile_manager_stats_t {
	uint64_t disk_read_bytes;
	ticks_t disk_read_time;
	ticks_t disk_read_worst_time;
};

extern void file_sendfile_manager_init(void);
extern void file_sendfile_manager_start(void);
extern void file_sendfile_manager_get_and_reset_stats(struct file_sendfile_manager_stats_t *stats);

/*
 * The wait_for_more callback is optional.
 * If not specified the operation will complete when end-of-file is reached (or transfer length is reached).
 * If specified the operation will wait for more data when end-of-file is reached and invoke the callback.
 * Callback - return the time the thread should wait for before invoking the wait_more_data callback again.
 * To stop the trafser call file_sendfile_abort().
 * 
 * The file must not be closed while the operation is active.
 * The tcp connection is reference counted and may be closed while the operation is active.
 */
extern struct file_sendfile_t *file_sendfile_start(struct file_t *file, struct tcp_connection *tcp_conn, uint64_t transfer_length, file_sendfile_wait_for_more_callback_t wait_for_more_callback, file_sendfile_complete_callback_t complete_callback, void *callback_arg);
extern void file_sendfile_request_stop(struct file_sendfile_t *sendfile);
