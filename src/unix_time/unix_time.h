/*
 * unix_time.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef int64_t time64_t;

#define TIME64_MAX_VALUE 0x7FFFFFFFFFFFFFFFLL

extern time64_t unix_time(void);
extern time64_t unix_time_get_offset_from_native(void);
extern void unix_time_set(time64_t new_time);
extern char *unix_time_to_str(time64_t time_v, char *buf);
extern void unix_time_to_tm(time64_t time_v, struct tm *tm_v);
extern time64_t unix_tm_to_time(struct tm *tm_v);
