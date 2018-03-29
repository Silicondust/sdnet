/*
 * ./src/file/bsd/dir_utils.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/param.h>
#include <sys/mount.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("dir_utils");

bool dir_exists(const char *name)
{
	struct stat stats;
	if (stat(name, &stats) != 0) {
		return false;
	}

	return S_ISDIR(stats.st_mode);
}

bool dir_mkdir(const char *name)
{
	if (dir_exists(name)) {
		return true;
	}

	if (mkdir(name, S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
		DEBUG_ERROR("dir_mkdir: mkdir %s failed - %s", name, strerror(errno));
		return false;
	}

	return true;
}

bool dir_rmdir(const char *name)
{
	if (rmdir(name) != 0) {
		DEBUG_ERROR("dir_rmdir: rmdir %s failed - %s", name, strerror(errno));
		return false;
	}

	return true;
}

bool dir_chdir(const char *name)
{
	if (chdir(name) != 0) {
		DEBUG_ERROR("dir_chdir: chdir %s failed - %s", name, strerror(errno));
		return false;
	}

	return true;
}

uint64_t dir_get_freespace(const char *path)
{
	struct statfs stats;
	if (statfs(path, &stats) < 0) {
		DEBUG_ERROR("statfs returned error %d", errno);
		return 0;
	}

	return (uint64_t)stats.f_bavail * (uint64_t)stats.f_bsize;
}

bool dir_get_fs_type(char *str, char *end, const char *path)
{
	struct statfs stats;
	if (statfs(path, &stats) < 0) {
		DEBUG_ERROR("statfs returned error %d", errno);
		sprintf_custom(str, end, "error");
		return false;
	}

	sprintf_custom(str, end, "%s", stats.f_fstypename);
	return true;
}
