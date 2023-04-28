/*
 * unix_time.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* min time valid = 2022/01/01 00:00:00 */
/* max time valid = 2099/12/31 23:59:59 */
#define UNIX_TIME_MIN_VALID 1640995200LL
#define UNIX_TIME_MAX_VALID 4102444799LL
#define UNIX_TIME_SOURCE_EXPIRE (24 * 60 * 60)

#if !defined(UNIX_TIME_MIN_SOURCE)
#define UNIX_TIME_MIN_SOURCE UNIX_TIME_SOURCE_HTTP
#endif

/* higher number = higher priority */
typedef enum {
	UNIX_TIME_SOURCE_NONE = 0,
	UNIX_TIME_SOURCE_OTA = 1,
	UNIX_TIME_SOURCE_HTTP = 2,
	UNIX_TIME_SOURCE_NTP = 3,
	UNIX_TIME_SOURCE_CABLECARD_OOB = 4, /* must be highest priority for cablecard applications */
} unix_time_source_t;

typedef int64_t time64_t;

struct timespec64 {
	time64_t tv_sec;
	uint32_t tv_nsec;
};

#define TIME64_MAX_VALUE 0x7FFFFFFFFFFFFFFFLL

extern time64_t unix_time(void);
extern time64_t unix_time_last_set(void);
extern time64_t unix_time_get_offset_from_native(void);
extern void unix_time_get_timespec(struct timespec64 *tp);
extern void unix_time_set(time64_t new_time, unix_time_source_t source);
extern char *unix_time_to_str(time64_t time_v, char *buf);
extern void unix_time_to_tm(time64_t time_v, struct tm *tm_v);
extern time64_t unix_tm_to_time(struct tm *tm_v);
