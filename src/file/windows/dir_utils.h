/*
 * ./src/file/windows/dir_utils.h
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DT_UNKNOWN 0
#define DT_DIR 1
#define DT_REG 2

struct dirent {
	unsigned char d_type;
	char d_name[256]; /* filename */
};

struct dir_t;
typedef struct dir_t DIR;

extern DIR *opendir(const char *name);
extern int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
extern void rewinddir(DIR *dirp);
extern int closedir(DIR *dirp);
