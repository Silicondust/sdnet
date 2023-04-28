/*
 * unix_time.c
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

THIS_FILE("unix_time");

struct unix_time_manager_t {
	time64_t ticks_sec_to_gmt_time;
	time64_t last_set;
	unix_time_source_t source;
};

static struct unix_time_manager_t unix_time_manager;

time64_t unix_time(void)
{
	if (unix_time_manager.ticks_sec_to_gmt_time == 0) {
		return (time64_t)time(NULL);
	}

	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	time64_t local_ref = (time64_t)tp.tv_sec;

	return local_ref + unix_time_manager.ticks_sec_to_gmt_time;
}

time64_t unix_time_last_set(void)
{
	return unix_time_manager.last_set;
}

time64_t unix_time_get_offset_from_native(void)
{
	return unix_time() - (time64_t)time(NULL);
}

void unix_time_get_timespec(struct timespec64 *tp)
{
	struct timespec native_tp;
	clock_gettime(CLOCK_SELECTION, &native_tp);
	tp->tv_sec = (time64_t)native_tp.tv_sec + unix_time_manager.ticks_sec_to_gmt_time;
	tp->tv_nsec = native_tp.tv_nsec;
}

void unix_time_set(time64_t new_time, unix_time_source_t source)
{
	if (source < UNIX_TIME_MIN_SOURCE) {
		return;
	}
	if ((new_time < UNIX_TIME_MIN_VALID) || (new_time > UNIX_TIME_MAX_VALID)) {
		return;
	}

	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	time64_t local_ref = (time64_t)tp.tv_sec;
	time64_t existing_time = local_ref + unix_time_manager.ticks_sec_to_gmt_time;

	if ((source < unix_time_manager.source) && (unix_time_manager.last_set + UNIX_TIME_SOURCE_EXPIRE > existing_time)) {
		return;
	}

	unix_time_manager.ticks_sec_to_gmt_time = new_time - local_ref;
	unix_time_manager.last_set = new_time;
	unix_time_manager.source = source;
}

char *unix_time_to_str(time64_t time_v, char *buf)
{
	struct tm tm_v;
	unix_time_to_tm(time_v, &tm_v);

	asctime_r(&tm_v, buf);
	*strchr(buf, '\n') = 0;
	return buf;
}

void unix_time_to_tm(time64_t time_v, struct tm *tm_v)
{
	time_t time_v_native = (time_t)time_v;
	gmtime_r(&time_v_native, tm_v);
}

time64_t unix_tm_to_time(struct tm *tm_v)
{
	return (time64_t)timegm(tm_v);
}
