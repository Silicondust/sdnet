/*
 * timer.c
 *
 * Copyright © 2008-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("timer");

ticks_t timer_get_ticks(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	return ((ticks_t)tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
}

uint32_t timer_get_fast_ticks(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	return (tp.tv_sec * 1000000000) + tp.tv_nsec;
}

/*
 * Some platforms usleep/nanosleep/clock_nanosleep blocks for 9.2-9.9ms minimum so can't be used
 */
#if defined(TIMER_SLEEP_BUSY_WAIT)
void timer_sleep_fast(uint32_t fast_tick_count)
{
	uint32_t stop_time = timer_get_fast_ticks() + fast_tick_count;
	timer_sleep_fast_until(stop_time);
}

void timer_sleep_fast_until(uint32_t stop_time)
{
	while (1) {
		thread_yield();
		int32_t remaining = (int32_t)(stop_time - timer_get_fast_ticks());
		if (remaining <= 0) {
			return;
		}
	}
}
#else
void timer_sleep_fast(uint32_t fast_tick_count)
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = fast_tick_count;
	nanosleep(&ts, NULL);
}

void timer_sleep_fast_until(uint32_t stop_time)
{
	int32_t fast_tick_count = (int32_t)(stop_time - timer_get_fast_ticks());
	if (fast_tick_count <= 0) {
		return;
	}

	timer_sleep_fast((uint32_t)fast_tick_count);
}
#endif

void timer_sleep(ticks_t tick_count)
{
	struct timespec ts;
	ts.tv_sec = tick_count / TICK_RATE;
	ts.tv_nsec = (tick_count % TICK_RATE) * 1000000UL;
	nanosleep(&ts, NULL);
}

void timer_sleep_until(ticks_t stop_time)
{
	int64_t tick_count = (int64_t)(stop_time - timer_get_ticks());
	if (tick_count <= 0) {
		return;
	}

	timer_sleep((ticks_t)tick_count);
}
