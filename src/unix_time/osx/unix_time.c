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

static time64_t unix_time_ticks_sec_to_gmt_time = 0;

time64_t unix_time(void)
{
	if (unix_time_ticks_sec_to_gmt_time == 0) {
		return (time64_t)time(NULL);
	}

	struct thread_public_context_t *context = thread_get_public_context();

	struct mach_timespec t;
	clock_get_time(context->system_clock_serv, &t);
	return (time64_t)t.tv_sec + unix_time_ticks_sec_to_gmt_time;
}

time64_t unix_time_get_offset_from_native(void)
{
	return unix_time() - (time64_t)time(NULL);
}

void unix_time_set(time64_t new_time)
{
	struct thread_public_context_t *context = thread_get_public_context();

	struct mach_timespec t;
	clock_get_time(context->system_clock_serv, &t);
	unix_time_ticks_sec_to_gmt_time = new_time - (time64_t)t.tv_sec;
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
