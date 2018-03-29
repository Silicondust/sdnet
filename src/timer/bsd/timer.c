/*
 * ./src/timer/bsd/timer.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
