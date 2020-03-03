/*
 * file_utils.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("file_utils");

struct file_t {
	HANDLE fp;
};

static struct file_t *file_open_internal(const char *path, DWORD access, DWORD creation)
{
	uint16_t path_wstr[MAX_PATH];
	str_utf8_to_utf16(path_wstr, path_wstr + MAX_PATH, path);

	HANDLE fp = CreateFileW(path_wstr, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fp == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	struct file_t *file = (struct file_t *)heap_alloc_and_zero(sizeof(struct file_t), PKG_OS, MEM_TYPE_OS_FILE);
	if (!file) {
		CloseHandle(fp);
		return NULL;
	}

	file->fp = fp;
	return file;
}

struct file_t *file_open_read(const char *path)
{
	return file_open_internal(path, GENERIC_READ, OPEN_EXISTING);
}

struct file_t *file_open_create(const char *path)
{
	return file_open_internal(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS);
}

struct file_t *file_open_existing(const char *path)
{
	return file_open_internal(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
}

size_t file_read(struct file_t *file, void *buffer, size_t length)
{
	DWORD actual = 0;
	(void)ReadFile(file->fp, buffer, (DWORD)length, &actual, NULL);
	return actual;
}

size_t file_write(struct file_t *file, void *buffer, size_t length)
{
	DWORD actual = 0;
	WriteFile(file->fp, buffer, (DWORD)length, &actual, NULL);
	return (size_t)actual;
}

bool file_seek_set(struct file_t *file, uint64_t offset)
{
	LARGE_INTEGER loffset;
	loffset.QuadPart = (LONGLONG)offset;
	return SetFilePointerEx(file->fp, loffset, NULL, FILE_BEGIN);
}

bool file_seek_advance(struct file_t *file, uint64_t offset)
{
	LARGE_INTEGER loffset;
	loffset.QuadPart = (LONGLONG)offset;
	return SetFilePointerEx(file->fp, loffset, NULL, FILE_CURRENT);
}

bool file_seek_retreat(struct file_t *file, uint64_t offset)
{
	LARGE_INTEGER loffset;
	loffset.QuadPart = -(LONGLONG)offset;
	return SetFilePointerEx(file->fp, loffset, NULL, FILE_CURRENT);
}

bool file_seek_end(struct file_t *file)
{
	LARGE_INTEGER loffset;
	loffset.QuadPart = 0LL;
	return SetFilePointerEx(file->fp, loffset, NULL, FILE_END);
}

uint64_t file_get_pos(struct file_t *file, uint64_t result_on_error)
{
	LARGE_INTEGER loffset, lresult;
	loffset.QuadPart = 0LL;
	lresult.QuadPart = 0LL;

	if (!SetFilePointerEx(file->fp, loffset, &lresult, FILE_CURRENT)) {
		return result_on_error;
	}

	return (uint64_t)lresult.QuadPart;
}

void file_close(struct file_t *file)
{
	CloseHandle(file->fp);
	heap_free(file);
}

FILE *fopen_utf8(const char *path, const char *mode)
{
	uint16_t path_wstr[MAX_PATH];
	str_utf8_to_utf16(path_wstr, path_wstr + MAX_PATH, path);

	uint16_t mode_wstr[16];
	str_utf8_to_utf16(mode_wstr, mode_wstr + 16, mode);

	return _wfopen((wchar_t *)path_wstr, (wchar_t *)mode_wstr);
}

bool file_delete(const char *path, bool result_on_not_found)
{
	uint16_t path_wstr[MAX_PATH];
	str_utf8_to_utf16(path_wstr, path_wstr + MAX_PATH, path);

	if (!DeleteFileW((wchar_t *)path_wstr)) {
		DWORD err = GetLastError();
		if ((err == ERROR_FILE_NOT_FOUND) || (err == ERROR_PATH_NOT_FOUND)) {
			return result_on_not_found;
		}

		DEBUG_INFO("delete %s failed (0x%x)", path, err);
		return false;
	}

	return true;
}

bool file_move(const char *new_path, const char *old_path)
{
	uint16_t old_path_wstr[MAX_PATH];
	str_utf8_to_utf16(old_path_wstr, old_path_wstr + MAX_PATH, old_path);

	uint16_t new_path_wstr[MAX_PATH];
	str_utf8_to_utf16(new_path_wstr, new_path_wstr + MAX_PATH, new_path);

	return MoveFileExW((wchar_t *)old_path_wstr, (wchar_t *)new_path_wstr, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
}
