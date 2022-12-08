/*
 * thread.c
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

THIS_FILE("thread");

#define THREAD_MAIN_THREAD_STATE_NONE 0
#define THREAD_MAIN_THREAD_STATE_WAITING 1
#define THREAD_MAIN_THREAD_STATE_ACTIVE 2

struct thread_context_t {
	struct slist_prefix_t slist_prefix;
	struct thread_public_context_t public_context;
	pthread_t thread_id;
	thread_execute_func_t execute_func;
	void *execute_arg;
	volatile uint8_t main_thread_state;
};

struct thread_manager_t {
	struct slist_t thread_list;
	struct spinlock thread_main_lock;
	pthread_key_t context_key;
	struct thread_context_t initial_context;
	bool started;

	volatile uint32_t watchdog_counter;
};

static struct thread_manager_t thread_manager;

static struct thread_context_t *thread_get_context_internal(void)
{
	return (struct thread_context_t *)pthread_getspecific(thread_manager.context_key);
}

struct thread_public_context_t *thread_get_public_context(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	return &thread_context->public_context;
}

bool thread_is_main_thread(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	return (thread_context->main_thread_state == THREAD_MAIN_THREAD_STATE_ACTIVE);
}

void thread_main_execute(thread_execute_func_t execute_func, void *execute_arg)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	if (thread_context->main_thread_state == THREAD_MAIN_THREAD_STATE_ACTIVE) {
		execute_func(execute_arg);
		return;
	}

	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_WAITING;
	spinlock_lock(&thread_manager.thread_main_lock);
	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_ACTIVE;
	thread_manager.watchdog_counter++;

	execute_func(execute_arg);

	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_NONE;
	spinlock_unlock(&thread_manager.thread_main_lock);
}

void thread_main_enter(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_WAITING;
	spinlock_lock(&thread_manager.thread_main_lock);
	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_ACTIVE;
	thread_manager.watchdog_counter++;
}

void thread_main_exit(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	thread_context->main_thread_state = THREAD_MAIN_THREAD_STATE_NONE;
	spinlock_unlock(&thread_manager.thread_main_lock);
}

static void *thread_execute(void *arg)
{
	struct thread_context_t *thread_context = (struct thread_context_t *)arg;

	thread_public_context_init(&thread_context->public_context);
	pthread_setspecific(thread_manager.context_key, thread_context);

#if defined(DEBUG) && defined(PR_SET_NAME)
	char name[16];
	snprintf(name, sizeof(name), "t_%p", thread_context->execute_func);
	prctl(PR_SET_NAME, name);
#endif

	thread_context->execute_func(thread_context->execute_arg);
	return NULL;
}

void thread_start(thread_execute_func_t execute_func, void *execute_arg)
{
	DEBUG_ASSERT(thread_manager.started, "attempt to start thread before start");

	struct thread_context_t *thread_context = (struct thread_context_t *)heap_alloc_and_zero(sizeof(struct thread_context_t), PKG_OS, MEM_TYPE_OS_THREAD);
	if (!thread_context) {
		DEBUG_ASSERT(0, "out of memory");
		return;
	}

	thread_context->execute_func = execute_func;
	thread_context->execute_arg = execute_arg;
	slist_attach_head(struct thread_context_t, &thread_manager.thread_list, thread_context);

	/* Launch thread */
	pthread_create(&thread_context->thread_id, NULL, thread_execute, thread_context);
}

void thread_external_thread_init(void)
{
	struct thread_context_t *thread_context = (struct thread_context_t *)heap_alloc_and_zero(sizeof(struct thread_context_t), PKG_OS, MEM_TYPE_OS_THREAD);
	if (!thread_context) {
		DEBUG_ASSERT(0, "out of memory");
		return;
	}

	thread_public_context_init(&thread_context->public_context);
	pthread_setspecific(thread_manager.context_key, thread_context);
}

#if defined(THREAD_MANAGER_WATCHDOG)
static void *thread_manager_watchdog_thread(void *arg)
{
	uint32_t previous_watchdog_counter = thread_manager.watchdog_counter;

	while (1) {
		sleep(10);

		uint32_t latest_watchdog_couner = thread_manager.watchdog_counter;
		if (latest_watchdog_couner == previous_watchdog_counter) {
			break;
		}

		previous_watchdog_counter = latest_watchdog_couner;
	}

	DEBUG_ERROR("watchdog detected stall");
	pthread_t thread_id = pthread_self();

#if defined(DEBUG) || defined(THREAD_MAIN_TRACKING)
	struct thread_context_t *thread_context = slist_get_head(struct thread_context_t, &thread_manager.thread_list);
	while (thread_context) {
		if (thread_context->main_thread_state == THREAD_MAIN_THREAD_STATE_ACTIVE) {
			thread_id = thread_context->thread_id;
			break;
		}
		thread_context = slist_get_next(struct thread_context_t, thread_context);
	}
#endif

	pthread_kill(thread_id, SIGALRM);
	return NULL;
}
#endif

void thread_manager_start(void)
{
	thread_manager.started = true;

#if defined(THREAD_MANAGER_WATCHDOG)
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, thread_manager_watchdog_thread, NULL);
#endif
}

void thread_manager_init(void)
{
	spinlock_init(&thread_manager.thread_main_lock, 65535);
	pthread_key_create(&thread_manager.context_key, NULL);

	struct thread_context_t *thread_context = &thread_manager.initial_context;
	thread_context->thread_id = pthread_self();
	thread_public_context_init(&thread_context->public_context);
	pthread_setspecific(thread_manager.context_key, thread_context);
	slist_attach_head(struct thread_context_t, &thread_manager.thread_list, thread_context);

	thread_main_enter();
}
