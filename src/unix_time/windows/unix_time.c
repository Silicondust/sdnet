/*
 * unix_time.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
		return _time64(NULL);
	}

	time64_t local_ref = GetTickCount64() / 1000;
	return local_ref + unix_time_manager.ticks_sec_to_gmt_time;
}

time64_t unix_time_last_set(void)
{
	return unix_time_manager.last_set;
}

time64_t unix_time_get_offset_from_native(void)
{
	return unix_time() - _time64(NULL);
}

/* WARNING: unix_time_get_timespec does not use correction value */
void unix_time_get_timespec(struct timespec64 *tp)
{
	struct _timespec64 native_tp;
	_timespec64_get(&native_tp, TIME_UTC);
	tp->tv_sec = native_tp.tv_sec;
	tp->tv_nsec = native_tp.tv_nsec;
}

void unix_time_set(time64_t new_time, unix_time_source_t source)
{
	if ((new_time < UNIX_TIME_MIN_VALID) || (new_time > UNIX_TIME_MAX_VALID)) {
		return;
	}

	time64_t local_ref = GetTickCount64() / 1000;
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
	_gmtime64_s(&tm_v, &time_v);

	asctime_s(buf, 26, &tm_v);
	*strchr(buf, '\n') = 0;
	return buf;
}

void unix_time_to_tm(time64_t time_v, struct tm *tm_v)
{
	_gmtime64_s(tm_v, &time_v);
}

time64_t unix_tm_to_time(struct tm *tm_v)
{
	return _mkgmtime64(tm_v);
}
