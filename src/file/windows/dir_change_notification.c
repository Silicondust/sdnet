/*
 * ./src/file/windows/dir_change_notification.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("dir_change_notification");

struct dir_change_notification_worker_t;

struct dir_change_notification_t {
	struct slist_prefix_t slist_prefix;
	struct dir_change_notification_worker_t *worker;
	HANDLE change_notification_handle;

	dir_change_notification_callback_func_t change_callback;
	dir_change_notification_callback_func_t error_callback;
	void *callback_arg;
};

struct dir_change_notification_worker_t {
	struct slist_prefix_t slist_prefix;

	struct slist_t dcn_list;
	uint32_t dcn_list_count;
	bool dcn_list_modified;

	HANDLE wait_array[MAXIMUM_WAIT_OBJECTS];
	uint32_t wait_array_count;

	HANDLE thread_signal;
};

struct dir_change_notification_manager_t {
	struct slist_t worker_list;
};

static struct dir_change_notification_manager_t dir_change_notification_manager;

static void dir_change_notification_close(struct dir_change_notification_t *dcn)
{
	DEBUG_ASSERT(thread_is_main_thread(), "dir_change_notification_close called from unsupported thread");

	if (dcn->change_notification_handle == 0) {
		return;
	}

	struct dir_change_notification_worker_t *worker = dcn->worker;
	(void)slist_detach_item(struct dir_change_notification_t, &worker->dcn_list, dcn);
	worker->dcn_list_count--;
	worker->dcn_list_modified = true;

	FindCloseChangeNotification(dcn->change_notification_handle);
	dcn->change_notification_handle = 0;
}

static struct dir_change_notification_t *dir_change_notification_find_by_change_notification_handle(struct dir_change_notification_worker_t *worker, HANDLE change_notification_handle)
{
	struct dir_change_notification_t *dcn = slist_get_head(struct dir_change_notification_t, &worker->dcn_list);
	while (dcn) {
		if (dcn->change_notification_handle == change_notification_handle) {
			return dcn;
		}

		dcn = slist_get_next(struct dir_change_notification_t, dcn);
	}

	return NULL;
}

static void dir_change_notification_execute_event(struct dir_change_notification_worker_t *worker, HANDLE change_notification_handle)
{
	struct dir_change_notification_t *dcn = dir_change_notification_find_by_change_notification_handle(worker, change_notification_handle);
	if (!dcn) {
		return;
	}

	if (!FindNextChangeNotification(dcn->change_notification_handle)) {
		DEBUG_INFO("dir_change_notification_thread_execute: FindNextChangeNotification failed (0x%08X)", GetLastError());

		dir_change_notification_close(dcn);

		if (dcn->error_callback) {
			dcn->error_callback(dcn->callback_arg);
		}

		return;
	}

	DEBUG_INFO("dir_change_notification_execute_event: watched directory change notification");
	if (dcn->change_callback) {
		dcn->change_callback(dcn->callback_arg);
	}
}

static void dir_change_notification_update_wait_array(struct dir_change_notification_worker_t *worker)
{
	if (!worker->dcn_list_modified) {
		return;
	}

	HANDLE *ptr = worker->wait_array;
	worker->wait_array_count = 0;

	*ptr++ = worker->thread_signal;
	worker->wait_array_count++;

	struct dir_change_notification_t *dcn = slist_get_head(struct dir_change_notification_t, &worker->dcn_list);
	while (dcn) {
		*ptr++ = dcn->change_notification_handle;
		worker->wait_array_count++;
		dcn = slist_get_next(struct dir_change_notification_t, dcn);
	}

	worker->dcn_list_modified = false;
}

static void dir_change_notification_thread_execute(void *arg)
{
	struct dir_change_notification_worker_t *worker = (struct dir_change_notification_worker_t *)arg;

	thread_main_enter();
	dir_change_notification_update_wait_array(worker);
	thread_main_exit();

	while (1) {
		DWORD ret = WaitForMultipleObjects(worker->wait_array_count, worker->wait_array, false, INFINITE);
		if (ret == WAIT_FAILED) {
			DEBUG_INFO("dir_change_notification_thread_execute: WaitForMultipleObjects failed");
			return;
		}

		if ((ret < WAIT_OBJECT_0) || (ret >= WAIT_OBJECT_0 + worker->wait_array_count)) {
			continue;
		}

		HANDLE change_notification_handle = worker->wait_array[ret - WAIT_OBJECT_0];

		thread_main_enter();
		dir_change_notification_execute_event(worker, change_notification_handle);
		dir_change_notification_update_wait_array(worker);
		thread_main_exit();
	}
}

void dir_change_notification_free(struct dir_change_notification_t *dcn)
{
	dir_change_notification_close(dcn);
	heap_free(dcn);
}

static struct dir_change_notification_worker_t *dir_change_notification_create_worker(void)
{
	struct dir_change_notification_worker_t *worker = slist_get_head(struct dir_change_notification_worker_t, &dir_change_notification_manager.worker_list);
	while (worker) {
		if (worker->dcn_list_count + 1 < MAXIMUM_WAIT_OBJECTS) {
			return worker;
		}

		worker = slist_get_next(struct dir_change_notification_worker_t, worker);
	}

	worker = (struct dir_change_notification_worker_t *)heap_alloc_and_zero(sizeof(struct dir_change_notification_worker_t), PKG_OS, MEM_TYPE_OS_DIR_CHANGE_NOTIFICATION);
	if (!worker) {
		DEBUG_ERROR("out of memory");
		errno = 0;
		return NULL;
	}

	worker->thread_signal = CreateEvent(NULL, false, false, NULL);
	if (worker->thread_signal == 0) {
		DEBUG_ERROR("CreateEvent failed");
		heap_free(worker);
		errno = 0;
		return NULL;
	}

	slist_attach_head(struct dir_change_notification_worker_t, &dir_change_notification_manager.worker_list, worker);
	thread_start(dir_change_notification_thread_execute, worker);
	return worker;
}

struct dir_change_notification_t *dir_change_notification_register(const char *dirname, dir_change_notification_callback_func_t change_callback, dir_change_notification_callback_func_t error_callback, void *callback_arg)
{
	struct dir_change_notification_worker_t *worker = dir_change_notification_create_worker();
	if (!worker) {
		return NULL;
	}

	struct dir_change_notification_t *dcn = (struct dir_change_notification_t *)heap_alloc_and_zero(sizeof(struct dir_change_notification_t), PKG_OS, MEM_TYPE_OS_DIR_CHANGE_NOTIFICATION);
	if (!dcn) {
		DEBUG_ERROR("out of memory");
		errno = 0;
		return NULL;
	}

	uint16_t dirname_wstr[MAX_PATH];
	str_utf8_to_utf16(dirname_wstr, dirname_wstr + MAX_PATH, dirname);

	dcn->change_notification_handle = FindFirstChangeNotificationW((wchar_t *)dirname_wstr, false, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME);
	if (dcn->change_notification_handle == INVALID_HANDLE_VALUE) {
		int errno_preserve = (int)GetLastError();
		heap_free(dcn);
		errno = errno_preserve;
		return NULL;
	}

	dcn->worker = worker;
	dcn->change_callback = change_callback;
	dcn->error_callback = error_callback;
	dcn->callback_arg = callback_arg;

	slist_attach_head(struct dir_change_notification_t, &worker->dcn_list, dcn);
	worker->dcn_list_count++;
	worker->dcn_list_modified = true;
	SetEvent(worker->thread_signal);

	return dcn;
}
