/*
 * ./src/timer/windows/timer.c
 *
 * Copyright © 2008-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

static uint64_t timer_fast_tick_rate;

ticks_t timer_get_ticks(void)
{
	return GetTickCount64();
}

uint32_t timer_get_fast_ticks(void)
{
	LARGE_INTEGER fast_ticks;
	QueryPerformanceCounter(&fast_ticks);
	return (uint32_t)((uint64_t)fast_ticks.QuadPart * 1000000 / timer_fast_tick_rate);
}

void timer_sleep_fast(uint32_t fast_tick_count)
{
	uint32_t stop_time = timer_get_fast_ticks() + fast_tick_count;
	timer_sleep_fast_until(stop_time);
}

void timer_sleep_fast_until(uint32_t stop_time)
{
	thread_yield();

	while (1) {
		int32_t remaining = (int32_t)(stop_time - timer_get_fast_ticks());
		if (remaining <= 0) {
			return;
		}

		uint32_t remaining_ms = ((uint32_t)remaining + FAST_TICK_RATE_MS - 1) / FAST_TICK_RATE_MS;
		Sleep((DWORD)remaining_ms);
	}
}

void timer_sleep(ticks_t tick_count)
{
	ticks_t stop_time = timer_get_ticks() + tick_count;
	timer_sleep_until(stop_time);
}

void timer_sleep_until(ticks_t stop_time)
{
	thread_yield();

	while (1) {
		int64_t remaining = (int64_t)(stop_time - timer_get_ticks());
		if (remaining <= 0) {
			return;
		}

		Sleep((DWORD)remaining);
	}
}

void timer_init(void)
{
	LARGE_INTEGER fast_ticks = {0, 0};
	QueryPerformanceFrequency(&fast_ticks);
	timer_fast_tick_rate = (uint64_t)fast_ticks.QuadPart;
	DEBUG_INFO("timer_fast_tick_rate = %llu", timer_fast_tick_rate);
}
