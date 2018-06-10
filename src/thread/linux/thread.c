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

void thread_public_context_init(struct thread_public_context_t *context)
{
	context->random_fp = fopen("/dev/urandom", "rb");
	DEBUG_ASSERT(context->random_fp, "failed to open /dev/urandom");
}

void thread_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, ticks_t timeout_duration)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	int64_t tv_nsec = (int64_t)ts.tv_nsec + (timeout_duration * 1000000);
	ts.tv_nsec = (long)(tv_nsec % 1000000000);
	ts.tv_sec += (time_t)(tv_nsec / 1000000000);

	pthread_cond_timedwait(cond, mutex, &ts);
}
