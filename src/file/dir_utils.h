/*
 * ./src/file/dir_utils.h
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool dir_exists(const char *name);
extern bool dir_mkdir(const char *name);
extern bool dir_rmdir(const char *name);
extern bool dir_chdir(const char *name);
extern uint64_t dir_get_freespace(const char *path);
extern bool dir_get_fs_type(char *str, char *end, const char *path);
