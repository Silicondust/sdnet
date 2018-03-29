/*
 * ./src/thread/pthread/spinlock.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define SPINLOCK_ORDER(pkg, pkg_order) 0
typedef uint16_t spinlock_order_t;

#if defined(DEBUG) && 0

struct spinlock {
	pthread_mutex_t mutex;
	spinlock_order_t order;
	uint32_t start_time;
};

static inline void spinlock_init(struct spinlock *lock, spinlock_order_t order)
{
	pthread_mutex_init(&lock->mutex, NULL);
	lock->order = order;
}

static inline void spinlock_lock(struct spinlock *lock)
{
	pthread_mutex_lock(&lock->mutex);
	lock->start_time = timer_get_fast_ticks();
}

#define spinlock_unlock(lock) \
{ \
	uint32_t duration = timer_get_fast_ticks() - (lock)->start_time; \
	pthread_mutex_unlock(&(lock)->mutex); \
	if (duration >= FAST_TICK_RATE_MS) { \
		DEBUG_INFO("lock held for %uus", duration / FAST_TICK_RATE_US); \
	} \
}

#else

struct spinlock {
	pthread_mutex_t mutex;
};

static inline void spinlock_init(struct spinlock *lock, spinlock_order_t order)
{
	pthread_mutex_init(&lock->mutex, NULL);
}

static inline void spinlock_lock(struct spinlock *lock)
{
	pthread_mutex_lock(&lock->mutex);
}

static inline void spinlock_unlock(struct spinlock *lock)
{
	pthread_mutex_unlock(&lock->mutex);
}

#endif
