/*
 * signal.c
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

THIS_FILE("signal");

#define THREAD_SIGNAL_MAX_WAIT_TICKS 0x00000000FFFFFFFEULL

struct thread_signal_t {
	HANDLE event_handle;
};

void thread_suspend_wait_for_signal(struct thread_signal_t *signal)
{
	thread_yield();

	WaitForSingleObject(signal->event_handle, INFINITE);
}

void thread_suspend_wait_for_signal_or_ticks(struct thread_signal_t *signal, ticks_t ticks)
{
	thread_yield();

	if (ticks == TICKS_INFINITE) {
		WaitForSingleObject(signal->event_handle, INFINITE);
		return;
	}

	if (ticks > THREAD_SIGNAL_MAX_WAIT_TICKS) {
		ticks = THREAD_SIGNAL_MAX_WAIT_TICKS;
	}

	WaitForSingleObject(signal->event_handle, (DWORD)ticks);
}

void thread_suspend_wait_for_signal_or_timestamp(struct thread_signal_t *signal, ticks_t timestamp)
{
	thread_yield();

	if (timestamp == TICKS_INFINITE) {
		WaitForSingleObject(signal->event_handle, INFINITE);
		return;
	}

	ticks_t current_time = timer_get_ticks();
	if (current_time >= timestamp) {
		WaitForSingleObject(signal->event_handle, 0);
		return;
	}

	ticks_t ticks = timestamp - current_time;
	if (ticks > THREAD_SIGNAL_MAX_WAIT_TICKS) {
		ticks = THREAD_SIGNAL_MAX_WAIT_TICKS;
	}

	WaitForSingleObject(signal->event_handle, (DWORD)ticks);
}

void thread_signal_set(struct thread_signal_t *signal)
{
	SetEvent(signal->event_handle);
}

struct thread_signal_t *thread_signal_alloc(void)
{
	struct thread_signal_t *signal = (struct thread_signal_t *)heap_alloc_and_zero(sizeof(struct thread_signal_t), PKG_OS, MEM_TYPE_OS_THREAD_SIGNAL);
	if (!signal) {
		DEBUG_ASSERT(0, "out of memory");
		return NULL;
	}

	signal->event_handle = CreateEvent(NULL, false, false, NULL);
	DEBUG_ASSERT(signal->event_handle, "CreateEvent failed");

	return signal;
}
