/*
 * ./src/timer/timer.h
 *
 * Copyright © 2008-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define TICK_RATE 1000
#define TICK_RATE_MINUTE (TICK_RATE * 60)
#define TICK_RATE_HOUR (TICK_RATE_MINUTE * 60)
#define TICK_RATE_DAY (TICK_RATE_HOUR * 24)
#define TICKS_INFINITE 0xFFFFFFFFFFFFFFFFULL

extern ticks_t timer_get_ticks(void);
extern void timer_sleep(ticks_t tick_count);
extern void timer_sleep_until(ticks_t stop_time);

extern uint32_t timer_get_fast_ticks(void);
extern void timer_sleep_fast(uint32_t fast_tick_count);
extern void timer_sleep_fast_until(uint32_t stop_time);
