/*
 * oneshot.c
 *
 * Copyright © 2007-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("oneshot");

/*
 * Threading: Main thread operation only.
 */

struct oneshot_manager_t {
	struct oneshot *attached_list;
	struct thread_signal_t *signal;
};

static struct oneshot_manager_t oneshot_manager;

void oneshot_init(struct oneshot *os)
{
	memset(os, 0, sizeof(struct oneshot));
}

void oneshot_attach(struct oneshot *os, ticks_t ticks, oneshot_callback_t callback, void *callback_arg)
{
	DEBUG_ASSERT(thread_is_main_thread(), "oneshot_attach called from unsupported thread");
	DEBUG_ASSERT(os->callback_time == 0, "oneshot already attached");

	os->callback_time = timer_get_ticks() + ticks;
	os->callback = callback;
	os->callback_arg = callback_arg;

	struct oneshot **pprev = &oneshot_manager.attached_list;
	struct oneshot *p = oneshot_manager.attached_list;
	while (p) {
		if (p->callback_time > os->callback_time) {
			break;
		}

		pprev = &p->next;
		p = p->next;
	}

	os->next = p;
	*pprev = os;

	if (oneshot_manager.attached_list == os) {
		thread_signal_set(oneshot_manager.signal);
	}
}

void oneshot_attach_with_jitter(struct oneshot *os, ticks_t ticks, uint32_t jitter, oneshot_callback_t callback, void *callback_arg)
{
	oneshot_attach(os, ticks - (jitter / 2) + (random_get32() % jitter), callback, callback_arg);
}

bool oneshot_detach(struct oneshot *os)
{
	DEBUG_ASSERT(thread_is_main_thread(), "oneshot_detach called from unsupported thread");

	if (os->callback_time == 0) {
		return false;
	}

	struct oneshot **pprev = &oneshot_manager.attached_list;
	struct oneshot *p = oneshot_manager.attached_list;
	while (1) {
		if (p == os) {
			break;
		}

		if (!p || (p->callback_time > os->callback_time)) {
			DEBUG_ASSERT(0, "oneshot has non zero time and is not on list");
			return false;
		}

		pprev = &p->next;
		p = p->next;
	}

	*pprev = p->next;
	os->next = NULL;
	os->callback_time = 0;

	return true;
}

bool oneshot_is_attached(struct oneshot *os)
{
	DEBUG_ASSERT(thread_is_main_thread(), "oneshot_is_attached called from unsupported thread");
	return (os->callback_time != 0);
}

ticks_t oneshot_get_ticks_remaining(struct oneshot *os)
{
	DEBUG_ASSERT(thread_is_main_thread(), "oneshot_is_attached called from unsupported thread");
	if (os->callback_time == 0) {
		return TICKS_INFINITE;
	}

	ticks_t current_time = timer_get_ticks();
	if (current_time > os->callback_time) {
		return 0;
	}

	return os->callback_time - current_time;
}

static ticks_t oneshot_timer_notification(void)
{
	struct oneshot *os = oneshot_manager.attached_list;
	if (!os) {
		return TICKS_INFINITE;
	}

	if (os->callback_time > timer_get_ticks()) {
		return os->callback_time;
	}

	oneshot_manager.attached_list = os->next;
	os->next = NULL;
	os->callback_time = 0;

	if (os->callback) {
		os->callback(os->callback_arg);
	}

	struct oneshot *next_os = oneshot_manager.attached_list;
	if (!next_os) {
		return TICKS_INFINITE;
	}

	return next_os->callback_time;
}

static void oneshot_timer_thread_execute(void *arg)
{
	while (1) {
		thread_main_enter();
		ticks_t next_notification_time = oneshot_timer_notification();
		thread_main_exit();

		thread_suspend_wait_for_signal_or_timestamp(oneshot_manager.signal, next_notification_time);
	}
}

void oneshot_manager_start(void)
{
	thread_start(oneshot_timer_thread_execute, NULL);
}

void oneshot_manager_init(void)
{
	oneshot_manager.signal = thread_signal_alloc();
}
