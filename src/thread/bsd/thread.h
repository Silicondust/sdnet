/*
 * ./src/thread/bsd/thread.h
 *
 * Copyright © 2012-2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct thread_public_context_t {
	uint32_t dummy;
};

extern inline void thread_yield(void)
{
	sched_yield();
}

/* Internal APIs */
extern void thread_public_context_init(struct thread_public_context_t *context);
extern void thread_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, ticks_t timeout_duration);
