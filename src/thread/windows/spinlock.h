/*
 * spinlock.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define SPINLOCK_ORDER(pkg, pkg_order) 0

struct spinlock {
	HANDLE mutex;
};

typedef uint16_t spinlock_order_t;

static inline void spinlock_init(struct spinlock *lock, spinlock_order_t order)
{
	lock->mutex = CreateMutex(NULL, false, NULL);
}

static inline void spinlock_lock(struct spinlock *lock)
{
	WaitForSingleObject(lock->mutex, INFINITE);
}

static inline void spinlock_unlock(struct spinlock *lock)
{
	ReleaseMutex(lock->mutex);
}
