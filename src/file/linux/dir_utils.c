/*
 * ./src/file/linux/dir_utils.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/statfs.h>
#include <sys/syscall.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("dir_utils");

/* Work around broken uclibc statfs64 implementation on 32-bit platforms */
#if defined(__UCLIBC__) && !defined(__x86_64)
int statfs64(const char *path, struct statfs64 *buf)
{
	return syscall(SYS_statfs64, path, sizeof(*buf), buf);
}
#endif

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
	struct statfs64 stats;
	if (statfs64(path, &stats) < 0) {
		DEBUG_ERROR("statfs64 returned error %d", errno);
		return 0;
	}

	return (uint64_t)stats.f_bavail * (uint64_t)stats.f_bsize;
}

struct dir_get_fs_type_lookup_t {
	uint32_t f_type;
	char name[8];
};

static struct dir_get_fs_type_lookup_t dir_get_fs_type_lookup[] =
{
	{0x00004d44, "msdos"},
	{0x00006969, "nfs"},
	{0x0000ef53, "ext"},
	{0x01021994, "tmpfs"},
	{0x3153464a, "jfs"},
	{0x52654973, "reiserfs"},
	{0x5346544e, "ntfs"},
	{0x58465342, "xfs"},
	{0x65735546, "fuse"},
	{0x9123683e, "btrfs"},
	{0xff534d42, "cifs"},
	{0x00000000, ""}
};

bool dir_get_fs_type(char *str, char *end, const char *path)
{
	struct statfs64 stats;
	if (statfs64(path, &stats) < 0) {
		DEBUG_ERROR("statfs64 returned error %d", errno);
		sprintf_custom(str, end, "error");
		return false;
	}

	struct dir_get_fs_type_lookup_t *entry = dir_get_fs_type_lookup;
	while (entry->f_type) {
		if (entry->f_type == stats.f_type) {
			sprintf_custom(str, end, entry->name);
			return true;
		}

		entry++;
	}

	sprintf_custom(str, end, "0x%08x", stats.f_type);
	return true;
}
