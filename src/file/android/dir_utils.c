/*
 * dir_utils.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("dir_utils_fixup");

static void dir_get_fs_type_fixup(char *str, char *end, const char *path)
{
	FILE *fp = fopen("/proc/self/mountinfo", "r");
	if (!fp) {
		DEBUG_WARN("unable to open mountinfo: %d", errno);
		return;
	}

	size_t longest_mount_point_len = 1; /* set to 1 to skip matching '/' */
	char mount_source[128];
	mount_source[0] = 0;

	while (1) {
		char mount_line[512];
		if (!fgets(mount_line, sizeof(mount_line), fp)) {
			break;
		}

		char *saveptr = NULL;
		strtok_r(mount_line, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);

		char *mount_point = strtok_r(NULL, " ", &saveptr);
		if (!mount_point) {
			continue;
		}

		size_t mount_point_len = strlen(mount_point);
		if (mount_point_len <= longest_mount_point_len) {
			continue;
		}
		if (strncmp(mount_point, path, mount_point_len) != 0) {
			continue;
		}
		if (path[mount_point_len] != '/') {
			continue;
		}

		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		
		char *mounted_fs_type = strtok_r(NULL, " ", &saveptr);
		if (!mounted_fs_type) {
			continue;
		}
		if (strcmp(mounted_fs_type, str) != 0) {
			continue;
		}

		char *mount_source_local = strtok_r(NULL, " ", &saveptr);
		if (!mount_source_local) {
			continue;
		}

		longest_mount_point_len = mount_point_len;
		sprintf_custom(mount_source, mount_source + sizeof(mount_source), "%s", mount_source_local);
	}

	if (mount_source[0] == 0) {
		DEBUG_WARN("mount source not found");
		fclose(fp);
		return;
	}

	/* Remove /media from the end (if present) - required for Nvidia Shield with hdd configured as internal storage. */
	size_t mount_source_len = strlen(mount_source);
	if (mount_source_len > 6) {
		if (strcmp(mount_source + mount_source_len - 6, "/media") == 0) {
			mount_source[mount_source_len - 6] = 0;
		}
	}

	fseek(fp, 0, SEEK_SET);

	while (1) {
		char mount_line[512];
		if (!fgets(mount_line, sizeof(mount_line), fp)) {
			break;
		}

		char *saveptr = NULL;
		strtok_r(mount_line, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);

		char *mount_point = strtok_r(NULL, " ", &saveptr);
		if (!mount_point) {
			continue;
		}
		if (strcmp(mount_point, mount_source) != 0) {
			continue;
		}

		/* Found */
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);
		strtok_r(NULL, " ", &saveptr);

		char *mounted_fs_type = strtok_r(NULL, " ", &saveptr);
		if (!mounted_fs_type) {
			break;
		}
		if (strcmp(mounted_fs_type, str) == 0) {
			break;
		}

		sprintf_custom(strchr(str, 0), end, ":%s", mounted_fs_type);
		break;
	}

	fclose(fp);
}

bool dir_get_fs_type(char *str, char *end, const char *path)
{
	if (!dir_get_fs_type_statfs64(str, end, path)) {
		return false;
	}

	if (strcmp(str, "sdcardfs") == 0) {
		dir_get_fs_type_fixup(str, end, path);
		return true;
	}

	if (strcmp(str, "fuse") == 0) {
		dir_get_fs_type_fixup(str, end, path);
		return true;
	}

	return true;
}
