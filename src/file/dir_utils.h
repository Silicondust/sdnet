/*
 * dir_utils.h
 *
 * Copyright © 2014-2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool dir_exists(const char *name);
extern bool dir_mkdir(const char *name);
extern bool dir_rmdir(const char *name);
extern bool dir_chdir(const char *name);
extern void dir_get_totalspace_freespace(const char *path, uint64_t *ptotalspace, uint64_t *pfreespace);
extern uint64_t dir_get_totalspace(const char *path);
extern uint64_t dir_get_freespace(const char *path);
extern bool dir_get_fs_type(char *str, char *end, const char *path);

static inline uint64_t convert_bytes_to_gb(uint64_t bytes)
{
	return (bytes + 500000000ULL) / 1000000000ULL;
}
