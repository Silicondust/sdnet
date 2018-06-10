/*
 * long_task.h
 *
 * Copyright © 2010 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef bool (*long_task_execute_func_t)(void *arg);
typedef void (*long_task_result_func_t)(void *arg);

extern bool long_task_enqueue(long_task_execute_func_t execute, long_task_result_func_t on_success, long_task_result_func_t on_error, void *arg);
extern bool long_task_inline(long_task_execute_func_t execute, long_task_result_func_t on_success, long_task_result_func_t on_error, void *arg);

extern void long_task_manager_init(void);
extern void long_task_manager_start(void);
