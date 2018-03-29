/*
 * ./src/file/bsd/dir_change_notification.c
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

#if !defined(O_EVTONLY)
#define O_EVTONLY O_RDONLY
#endif

struct dir_change_notification_t {
	struct slist_prefix_t slist_prefix;
	int dir_fd;

	dir_change_notification_callback_func_t change_callback;
	dir_change_notification_callback_func_t error_callback;
	void *callback_arg;
};

struct dir_change_notification_manager_t {
	struct slist_t dcn_list;
	int kqueue_fd;
	bool thread_running;
};

static struct dir_change_notification_manager_t dir_change_notification_manager;

static void dir_change_notification_close(struct dir_change_notification_t *dcn)
{
	DEBUG_ASSERT(thread_is_main_thread(), "dir_change_notification_close called from unsupported thread");

	if (dcn->dir_fd == 0) {
		return;
	}

	(void)slist_detach_item(struct dir_change_notification_t, &dir_change_notification_manager.dcn_list, dcn);

	struct kevent change;
	memset(&change, 0, sizeof(change));
	EV_SET(&change, dcn->dir_fd, EVFILT_VNODE, EV_DELETE, NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE, 0, NULL);
	if (kevent(dir_change_notification_manager.kqueue_fd, &change, 1, NULL, 0, NULL) < 0) {
		DEBUG_ERROR("kevent delete failed (%d)", errno);
	}

	close(dcn->dir_fd);
	dcn->dir_fd = 0;
}

static struct dir_change_notification_t *dir_change_notification_find_by_dir_fd(int dir_fd)
{
	struct dir_change_notification_t *dcn = slist_get_head(struct dir_change_notification_t, &dir_change_notification_manager.dcn_list);
	while (dcn) {
		if (dcn->dir_fd == dir_fd) {
			return dcn;
		}

		dcn = slist_get_next(struct dir_change_notification_t, dcn);
	}

	return NULL;
}

static void dir_change_notification_execute_event(struct kevent *event)
{
	struct dir_change_notification_t *dcn = dir_change_notification_find_by_dir_fd((int)event->ident);
	if (!dcn) {
		return;
	}

	if (event->filter != EVFILT_VNODE) {
		DEBUG_INFO("dir_change_notification_thread_execute: kevent not EVFILT_VNODE");
		return;
	}

	if (event->fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) {
		DEBUG_INFO("dir_change_notification_thread_execute: watched directory deleted or moved");

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
		struct kevent event;
		memset(&event, 0, sizeof(event));
		int ret = kevent(dir_change_notification_manager.kqueue_fd, NULL, 0, &event, 1, NULL);
		if (ret < 0) {
			DEBUG_INFO("dir_change_notification_thread_execute: kevent failed");
			return;
		}
		if (ret == 0) {
			DEBUG_WARN("dir_change_notification_thread_execute: kevent returned 0");
			continue;
		}

		thread_main_enter();
		dir_change_notification_execute_event(&event);
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
	if (dir_change_notification_manager.kqueue_fd == 0) {
		int kqueue_fd = kqueue();
		if (kqueue_fd <= 0) {
			int errno_preserve = errno;
			DEBUG_ERROR("kqueue failed");
			errno = errno_preserve;
			return false;
		}

		dir_change_notification_manager.kqueue_fd = kqueue_fd;
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
		return NULL;
	}

	dcn->dir_fd = open(dirname, O_DIRECTORY | O_EVTONLY);
	if (dcn->dir_fd == -1) {
		DEBUG_ERROR("failed to open %s", dirname);
		heap_free(dcn);
		return NULL;
	}
	
	struct kevent change;
	memset(&change, 0, sizeof(change));
	EV_SET(&change, dcn->dir_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE, NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE, 0, (void *)dirname);
	if (kevent(dir_change_notification_manager.kqueue_fd, &change, 1, NULL, 0, NULL) < 0) {
		DEBUG_ERROR("kevent add failed (%d)", errno);
		close(dcn->dir_fd);
		heap_free(dcn);
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
