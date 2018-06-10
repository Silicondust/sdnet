/*
 * long_task.c
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

THIS_FILE("long_task");

struct long_task_manager_t
{
	struct mqueue_t *mqueue;
	struct thread_signal_t *signal;
};

static struct long_task_manager_t long_task_manager;

static void long_task_result(void)
{
	long_task_result_func_t on_result = (long_task_result_func_t)mqueue_read_handle(system_app_queue);
	void *arg = (void *)mqueue_read_handle(system_app_queue);
	mqueue_read_complete(system_app_queue);

	on_result(arg);
}

static void long_task_execute(void)
{
	long_task_execute_func_t execute = (long_task_execute_func_t)mqueue_read_handle(long_task_manager.mqueue);
	long_task_result_func_t on_success = (long_task_result_func_t)mqueue_read_handle(long_task_manager.mqueue);
	long_task_result_func_t on_error = (long_task_result_func_t)mqueue_read_handle(long_task_manager.mqueue);
	void *arg = (void *)mqueue_read_handle(long_task_manager.mqueue);
	mqueue_read_complete(long_task_manager.mqueue);

	DEBUG_TRACE("executing long task %p", execute);
	bool result = execute(arg);

	long_task_result_func_t on_result = (result) ? on_success : on_error;
	if (!on_result) {
		return;
	}

	while (!mqueue_write_request(system_app_queue, long_task_result, 2 * MQUEUE_SIZEOF(void *))) {
		thread_yield();
	}

	mqueue_write_handle(system_app_queue, on_result);
	mqueue_write_handle(system_app_queue, arg);
	mqueue_write_complete(system_app_queue);
}

static void long_task_thread_start(void *arg)
{
	while (1) {
		thread_suspend_wait_for_signal(long_task_manager.signal);

		mqueue_read_handler_func_t handler = mqueue_read_request(long_task_manager.mqueue);
		if (handler) {
			handler();
		}
	}
}

bool long_task_enqueue(long_task_execute_func_t execute, long_task_result_func_t on_success, long_task_result_func_t on_error, void *arg)
{
	DEBUG_ASSERT(thread_is_main_thread(), "long_task_enqueue called from unsupported thread");
	DEBUG_TRACE("long_task_enqueue %p", execute);

	if (!mqueue_write_request(long_task_manager.mqueue, long_task_execute, 4 * MQUEUE_SIZEOF(void *))) {
		DEBUG_WARN("queue full");
		return false;
	}

	mqueue_write_handle(long_task_manager.mqueue, execute);
	mqueue_write_handle(long_task_manager.mqueue, on_success);
	mqueue_write_handle(long_task_manager.mqueue, on_error);
	mqueue_write_handle(long_task_manager.mqueue, arg);
	mqueue_write_complete(long_task_manager.mqueue);

	return true;
}

bool long_task_inline(long_task_execute_func_t execute, long_task_result_func_t on_success, long_task_result_func_t on_error, void *arg)
{
	bool result = execute(arg);

	long_task_result_func_t on_result = (result) ? on_success : on_error;
	if (on_result) {
		on_result(arg);
	}

	return true;
}

void long_task_manager_start(void)
{
	thread_start(long_task_thread_start, NULL);
}

void long_task_manager_init(void)
{
	long_task_manager.signal = thread_signal_alloc();
	long_task_manager.mqueue = mqueue_alloc(32, long_task_manager.signal);
}
