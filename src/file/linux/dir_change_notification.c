/*
 * dir_change_notification.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/inotify.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("dir_change_notification");

struct dir_change_notification_t {
	struct slist_prefix_t slist_prefix;
	int watch_handle;

	dir_change_notification_callback_func_t change_callback;
	dir_change_notification_callback_func_t error_callback;
	void *callback_arg;
};

struct dir_change_notification_manager_t {
	struct slist_t dcn_list;
	int inotify_fd;
	bool thread_running;
};

static struct dir_change_notification_manager_t dir_change_notification_manager;

static void dir_change_notification_close(struct dir_change_notification_t *dcn)
{
	DEBUG_ASSERT(thread_is_main_thread(), "dir_change_notification_close called from unsupported thread");

	if (dcn->watch_handle == 0) {
		return;
	}

	(void)slist_detach_item(struct dir_change_notification_t, &dir_change_notification_manager.dcn_list, dcn);

	inotify_rm_watch(dir_change_notification_manager.inotify_fd, dcn->watch_handle);
	dcn->watch_handle = 0;
}

static struct dir_change_notification_t *dir_change_notification_find_by_watch_handle(int watch_handle)
{
	struct dir_change_notification_t *dcn = slist_get_head(struct dir_change_notification_t, &dir_change_notification_manager.dcn_list);
	while (dcn) {
		if (dcn->watch_handle == watch_handle) {
			return dcn;
		}

		dcn = slist_get_next(struct dir_change_notification_t, dcn);
	}

	return NULL;
}

static void dir_change_notification_execute_event(struct inotify_event *event)
{
	struct dir_change_notification_t *dcn = dir_change_notification_find_by_watch_handle(event->wd);
	if (!dcn) {
		return;
	}

	if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
		DEBUG_INFO("dir_change_notification_execute_event: watched directory deleted or moved");

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

static void dir_change_notification_thread_execute(void *arg)
{
	while (1) {
		struct pollfd poll_fd;
		poll_fd.fd = dir_change_notification_manager.inotify_fd;
		poll_fd.events = POLLIN;
		poll_fd.revents = 0;

		int count = poll(&poll_fd, 1, -1);
		if (count < 0) {
			DEBUG_ERROR("dir_change_notification_thread_execute: poll failed");
			return;
		}
		if (count == 0) {
			DEBUG_WARN("dir_change_notification_thread_execute: poll returned 0");
			continue;
		}

		uint8_t buffer[sizeof(struct inotify_event) + NAME_MAX + 1];
		int length = read(dir_change_notification_manager.inotify_fd, &buffer, sizeof(buffer));
		if (length < (int)sizeof(struct inotify_event)) {
			DEBUG_ERROR("dir_change_notification_thread_execute: read failed");
			return;
		}

		struct inotify_event *event = (struct inotify_event *)(void *)buffer;

		thread_main_enter();
		dir_change_notification_execute_event(event);
		thread_main_exit();
	}
}

void dir_change_notification_free(struct dir_change_notification_t *dcn)
{
	dir_change_notification_close(dcn);
	heap_free(dcn);
}

static bool dir_change_notification_init(void)
{
	if (dir_change_notification_manager.inotify_fd == 0) {
		int inotify_fd = inotify_init();
		if (inotify_fd <= 0) {
			int errno_preserve = errno;
			DEBUG_ERROR("inotify_init failed");
			errno = errno_preserve;
			return false;
		}

		dir_change_notification_manager.inotify_fd = inotify_fd;
	}

	return true;
}

struct dir_change_notification_t *dir_change_notification_register(const char *dirname, dir_change_notification_callback_func_t change_callback, dir_change_notification_callback_func_t error_callback, void *callback_arg)
{
	if (!dir_change_notification_init()) {
		return NULL;
	}

	struct dir_change_notification_t *dcn = (struct dir_change_notification_t *)heap_alloc_and_zero(sizeof(struct dir_change_notification_t), PKG_OS, MEM_TYPE_OS_DIR_CHANGE_NOTIFICATION);
	if (!dcn) {
		DEBUG_ERROR("out of memory");
		errno = 0;
		return NULL;
	}

	dcn->watch_handle = inotify_add_watch(dir_change_notification_manager.inotify_fd, dirname, IN_ONLYDIR | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF);
	if (dcn->watch_handle == -1) {
		int errno_preserve = errno;
		DEBUG_ERROR("inotify_add_watch failed");
		heap_free(dcn);
		errno = errno_preserve;
		return NULL;
	}

	dcn->change_callback = change_callback;
	dcn->error_callback = error_callback;
	dcn->callback_arg = callback_arg;

	slist_attach_head(struct dir_change_notification_t, &dir_change_notification_manager.dcn_list, dcn);

	if (!dir_change_notification_manager.thread_running) {
		dir_change_notification_manager.thread_running = true;
		thread_start(dir_change_notification_thread_execute, NULL);
	}

	return dcn;
}
