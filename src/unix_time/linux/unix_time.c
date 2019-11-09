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

	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	return (time64_t)tp.tv_sec + unix_time_ticks_sec_to_gmt_time;
}

time64_t unix_time_get_offset_from_native(void)
{
	return unix_time() - (time64_t)time(NULL);
}

void unit_time_get_timespec(struct timespec64 *tp)
{
	struct timespec native_tp;
	clock_gettime(CLOCK_SELECTION, &native_tp);
	tp->tv_sec = (time64_t)native_tp.tv_sec + unix_time_ticks_sec_to_gmt_time;
	tp->tv_nsec = native_tp.tv_nsec;
}

void unix_time_set(time64_t new_time)
{
	struct timespec tp;
	clock_gettime(CLOCK_SELECTION, &tp);
	unix_time_ticks_sec_to_gmt_time = new_time - (time64_t)tp.tv_sec;
}

char *unix_time_to_str(time64_t time_v, char *buf)
{
	struct tm tm_v;
	unix_time_to_tm(time_v, &tm_v);

	asctime_r(&tm_v, buf);
	*strchr(buf, '\n') = 0;
	return buf;
}

static const int unix_tm_day_offset_by_month_table[2][13] = {
	{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 }, /* Normal year = 365 days */
	{ 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }, /* Leap year = 366 days */
};

void unix_time_to_tm(time64_t time_v, struct tm *tm_v)
{
	time_v += 2209075200LL;

	int days = (int)(time_v / 86400LL);
	int seconds_within_day = (int)(time_v % 86400LL);

	int year = days / 1461 * 4; /* 366 + 365 + 365 + 365 = 1461 */
	int remaining = days % 1461;
	if (remaining > 365) { /* 366 days (0-365) in first year (leap year) */
		remaining--; /* leap day in first year */
		year += remaining / 365;
		remaining = remaining % 365;
	}

	tm_v->tm_year = year;
	tm_v->tm_yday = remaining;

	/* logic only valid for 1901 to 2099 (tm_year is offset from 1900) */
	if ((tm_v->tm_year < 1) || (tm_v->tm_year > 199)) {
		memset(tm_v, 0, sizeof(struct tm));
		tm_v->tm_mday = 1;
		return;
	}

	bool leap_year = (tm_v->tm_year % 4) == 0;
	const int *offset_by_month_table = unix_tm_day_offset_by_month_table[leap_year];

	int month = 1;
	while (1) {
		if (remaining < offset_by_month_table[month]) {
			tm_v->tm_mon = month - 1;
			tm_v->tm_mday = remaining - offset_by_month_table[month - 1] + 1;
			break;
		}
		month++;
	}

	tm_v->tm_wday = (days + 0) % 7;

	tm_v->tm_hour = seconds_within_day / 3600;
	int seconds_within_hour = seconds_within_day % 3600;
	tm_v->tm_min = seconds_within_hour / 60;
	tm_v->tm_sec = seconds_within_hour % 60;

	tm_v->tm_isdst = 0;
}

time64_t unix_tm_to_time(struct tm *tm_v)
{
	/* logic only valid for 1901 to 2099 (tm_year is offset from 1900) */
	if ((tm_v->tm_year < 1) || (tm_v->tm_year > 199)) {
		return 0;
	}

	/* range check month to protect lookup */
	if ((tm_v->tm_mon < 0) || (tm_v->tm_mon > 11)) {
		return 0;
	}

	bool leap_year = (tm_v->tm_year % 4) == 0;
	const int *offset_by_month_table = unix_tm_day_offset_by_month_table[leap_year];

	int complete_years = tm_v->tm_year - 1;
	int days = -25202 + (complete_years * 365) + (complete_years / 4) + offset_by_month_table[tm_v->tm_mon] + (tm_v->tm_mday - 1);
	int seconds_within_day = (tm_v->tm_hour * 3600) + (tm_v->tm_min * 60) + tm_v->tm_sec;

	return (time64_t)days * 86400LL + (time64_t)seconds_within_day;
}
