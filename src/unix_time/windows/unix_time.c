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
		return _time64(NULL);
	}

	return (GetTickCount64() / 1000) + unix_time_ticks_sec_to_gmt_time;
}

time64_t unix_time_get_offset_from_native(void)
{
	return unix_time() - _time64(NULL);
}

void unix_time_set(time64_t new_time)
{
	unix_time_ticks_sec_to_gmt_time = new_time - (GetTickCount64() / 1000);
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
