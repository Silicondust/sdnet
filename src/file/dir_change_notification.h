/*
 * dir_change_notification.h
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct dir_change_notification_t;
typedef void(*dir_change_notification_callback_func_t)(void *arg);

extern void dir_change_notification_manager_init(void);
extern void dir_change_notification_manager_start(void);

/* dir_change_notification_register|free can be called from any thread */
extern struct dir_change_notification_t *dir_change_notification_register(const char *dirname, dir_change_notification_callback_func_t change_callback, dir_change_notification_callback_func_t error_callback, void *callback_arg, bool callback_main_thread);
extern void dir_change_notification_free(struct dir_change_notification_t *dcn);
