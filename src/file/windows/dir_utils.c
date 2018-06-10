/*
 * dir_utils.c
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

THIS_FILE("dir_utils");

struct dir_t {
	HANDLE find_handle;
	struct dirent result;
	uint16_t search_pattern_wstr[0];
};

DIR *opendir(const char *name)
{
	size_t name_len = strlen(name);
	size_t search_pattern_len = name_len + 2;

	DIR *dirp = (DIR *)heap_alloc_and_zero(sizeof(DIR) + (search_pattern_len * 2), PKG_OS, MEM_TYPE_OS_FS_DIR);
	if (!dirp) {
		return NULL;
	}

	dirp->find_handle = INVALID_HANDLE_VALUE;
	str_utf8_to_utf16(dirp->search_pattern_wstr, dirp->search_pattern_wstr + search_pattern_len, name);

	wchar_t *ptr = wcschr((wchar_t *)dirp->search_pattern_wstr, 0) - 1;
	if (*ptr++ != '\\') {
		*ptr++ = '\\';
	}

	*ptr++ = '*';
	*ptr++ = 0;

	return dirp;
}

static unsigned char readdir_file_attributes_to_type(DWORD file_attributes)
{
	if (file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		return DT_DIR;
	}

	return DT_REG;
}

struct dirent *readdir(DIR *dirp)
{
	WIN32_FIND_DATAW find_file_data;

	if (dirp->find_handle == INVALID_HANDLE_VALUE) {
		dirp->find_handle = FindFirstFileW((wchar_t *)dirp->search_pattern_wstr, &find_file_data);
		if (dirp->find_handle == INVALID_HANDLE_VALUE) {
			return NULL;
		}

		struct dirent *result = &dirp->result;
		result->d_type = readdir_file_attributes_to_type(find_file_data.dwFileAttributes);
		str_utf16_to_utf8(result->d_name, result->d_name + sizeof(result->d_name), (uint16_t *)find_file_data.cFileName);
		return result;
	}

	if (!FindNextFileW(dirp->find_handle, &find_file_data)) {
		return NULL;
	}

	struct dirent *result = &dirp->result;
	result->d_type = readdir_file_attributes_to_type(find_file_data.dwFileAttributes);
	str_utf16_to_utf8(result->d_name, result->d_name + sizeof(result->d_name), (uint16_t *)find_file_data.cFileName);
	return result;
}

void rewinddir(DIR *dirp)
{
	if (dirp->find_handle == INVALID_HANDLE_VALUE) {
		return;
	}

	FindClose(dirp->find_handle);
	dirp->find_handle = INVALID_HANDLE_VALUE;
}

int closedir(DIR *dirp)
{
	if (dirp->find_handle != INVALID_HANDLE_VALUE) {
		FindClose(dirp->find_handle);
	}

	heap_free(dirp);
	return 0;
}

bool dir_exists(const char *name)
{
	uint16_t name_wchar[MAX_PATH];
	str_utf8_to_utf16(name_wchar, name_wchar + MAX_PATH, name);

	DWORD attributes = GetFileAttributesW((wchar_t *)name_wchar);
	if ((attributes == INVALID_FILE_ATTRIBUTES) || ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
		return false;
	}

	return true;
}

bool dir_mkdir(const char *name)
{
	uint16_t name_wchar[MAX_PATH];
	str_utf8_to_utf16(name_wchar, name_wchar + MAX_PATH, name);

	DWORD attributes = GetFileAttributesW((wchar_t *)name_wchar);
	if ((attributes != INVALID_FILE_ATTRIBUTES) && ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)) {
		return true;
	}

	return (bool)CreateDirectoryW((wchar_t *)name_wchar, NULL);
}

bool dir_rmdir(const char *name)
{
	uint16_t name_wchar[MAX_PATH];
	str_utf8_to_utf16(name_wchar, name_wchar + MAX_PATH, name);

	return (bool)RemoveDirectoryW((wchar_t *)name_wchar);
}

bool dir_chdir(const char *name)
{
	uint16_t name_wchar[MAX_PATH];
	str_utf8_to_utf16(name_wchar, name_wchar + MAX_PATH, name);

	return (bool)SetCurrentDirectoryW((wchar_t *)name_wchar);
}

uint64_t dir_get_freespace(const char *path)
{
	uint16_t path_wchar[MAX_PATH];
	str_utf8_to_utf16(path_wchar, path_wchar + MAX_PATH, path);

	ULARGE_INTEGER free_bytes_available;
	if (!GetDiskFreeSpaceExW((wchar_t *)path_wchar, &free_bytes_available, NULL, NULL)) {
		DEBUG_ERROR("GetDiskFreeSpaceExW returned error %d", GetLastError());
		return 0;
	}

	return (uint64_t)free_bytes_available.QuadPart;
}

bool dir_get_fs_type(char *str, char *end, const char *path)
{
	uint16_t path_wchar[MAX_PATH];
	str_utf8_to_utf16(path_wchar, path_wchar + MAX_PATH, path);

	uint16_t volume_wchar[MAX_PATH];
	if (!GetVolumePathNameW(path_wchar, volume_wchar, MAX_PATH)) {
		errno = GetLastError();
		DEBUG_ERROR("GetVolumePathNameW failed (%08x)", errno);
		sprintf_custom(str, end, "error");
		return false;
	}

	if (GetDriveTypeW(path_wchar) == DRIVE_REMOTE) {
		sprintf_custom(str, end, "cifs");
		return true;
	}

	uint16_t fs_type_wchar[32];
	if (!GetVolumeInformationW((wchar_t *)volume_wchar, NULL, 0, NULL, NULL, NULL, fs_type_wchar, 32)) {
		errno = GetLastError();
		DEBUG_ERROR("GetVolumeInformationW failed (%08x)", errno);
		sprintf_custom(str, end, "error");
		return false;
	}

	str_utf16_to_utf8(str, end, fs_type_wchar);

	char *ptr = str;
	while (*ptr) {
		if ((*ptr >= 'A') && (*ptr <= 'Z')) {
			*ptr += 'a' - 'A';
		}
		ptr++;
	}

	return true;
}
