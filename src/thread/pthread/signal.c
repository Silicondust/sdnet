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

struct thread_signal_t
{
	volatile bool signaled;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

void thread_suspend_wait_for_signal(struct thread_signal_t *signal)
{
	thread_yield();

	pthread_mutex_lock(&signal->mutex);

	if (!signal->signaled) {
		pthread_cond_wait(&signal->cond, &signal->mutex);
	}

	signal->signaled = false;
	pthread_mutex_unlock(&signal->mutex);
}

void thread_suspend_wait_for_signal_or_timeout(struct thread_signal_t *signal, ticks_t timeout_time)
{
	thread_yield();

	pthread_mutex_lock(&signal->mutex);

	if (!signal->signaled) {
		ticks_t current_time = timer_get_ticks();
		if (current_time < timeout_time) {
			thread_pthread_cond_timedwait(&signal->cond, &signal->mutex, timeout_time - current_time);
		}
	}

	signal->signaled = false;
	pthread_mutex_unlock(&signal->mutex);
}

void thread_signal_set(struct thread_signal_t *signal)
{
	pthread_mutex_lock(&signal->mutex);

	signal->signaled = true;
	pthread_cond_signal(&signal->cond);

	pthread_mutex_unlock(&signal->mutex);
}

struct thread_signal_t *thread_signal_alloc(void)
{
	struct thread_signal_t *signal = (struct thread_signal_t *)heap_alloc_and_zero(sizeof(struct thread_signal_t), PKG_OS, MEM_TYPE_OS_THREAD_SIGNAL);
	if (!signal) {
		DEBUG_ASSERT(0, "out of memory");
		return NULL;
	}

	pthread_mutex_init(&signal->mutex, NULL);
	pthread_cond_init(&signal->cond, NULL);

	return signal;
}
