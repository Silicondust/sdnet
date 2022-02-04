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

#if !defined(FILE_WRITE_NB_QUEUE_BUFFER_SIZE)
#define FILE_WRITE_NB_QUEUE_BUFFER_SIZE (128U * 1024U)
#endif

struct file_t {
	HANDLE fp;
	HANDLE mmap_handle;
	void *mmap_base;
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

uint8_t *file_mmap(struct file_t *file, size_t *psize)
{
	DEBUG_ASSERT(!file->mmap_handle, "already mmap'd");

	size_t file_size = (size_t)file_get_size(file, 0);
	if (file_size == 0) {
		return NULL;
	}

	HANDLE mmap_handle = CreateFileMappingW(file->fp, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!mmap_handle) { /* NULL on error, not INVALID_HANDLE */
		return NULL;
	}

	file->mmap_base = MapViewOfFile(mmap_handle, FILE_MAP_READ, 0, 0, file_size);
	if (!file->mmap_base) {
		CloseHandle(mmap_handle);
		return NULL;
	}

	*psize = file_size;
	file->mmap_handle = mmap_handle;
	return (uint8_t *)file->mmap_base;
}

void file_munmap(struct file_t *file)
{
	if (!file->mmap_handle) {
		return;
	}

	UnmapViewOfFile(file->mmap_base);
	file->mmap_base = NULL;

	CloseHandle(file->mmap_handle);
	file->mmap_handle = NULL;
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

size_t file_write_nb(struct file_t *file, struct netbuf *nb)
{
	uint8_t *ptr = netbuf_get_ptr(nb);
	size_t length = netbuf_get_remaining(nb);

	DWORD actual = 0;
	WriteFile(file->fp, ptr, (DWORD)length, &actual, NULL);
	return (size_t)actual;
}

size_t file_write_nb_queue(struct file_t *file, struct netbuf_queue *nb_queue)
{
	struct netbuf *nb = netbuf_queue_get_head(nb_queue);
	if (!nb->next) {
		return file_write_nb(file, nb);
	}

	uint8_t *buffer = (uint8_t *)malloc(FILE_WRITE_NB_QUEUE_BUFFER_SIZE);
	if (!buffer) {
		return 0;
	}

	uint8_t *buffer_ptr = buffer;
	uint8_t *buffer_end = buffer + FILE_WRITE_NB_QUEUE_BUFFER_SIZE;
	size_t result = 0;

	while (nb) {
		uint8_t *nb_ptr = netbuf_get_ptr(nb);
		size_t nb_length = netbuf_get_remaining(nb);
		size_t buffer_space = buffer_end - buffer_ptr;

		if (buffer_space > nb_length) {
			memcpy(buffer_ptr, nb_ptr, nb_length);
			buffer_ptr += nb_length;
			nb = nb->next;
			continue;
		}

		memcpy(buffer_ptr, nb_ptr, buffer_space);
		netbuf_advance_pos(nb, buffer_space);
		buffer_ptr += buffer_space;

		DWORD length = (DWORD)(buffer_ptr - buffer);
		DWORD actual = 0;
		WriteFile(file->fp, buffer, length, &actual, NULL);
		result += actual;

		if (actual != length) {
			free(buffer);
			return result;
		}

		buffer_ptr = buffer;
	}

	if (buffer_ptr > buffer) {
		DWORD length = (DWORD)(buffer_ptr - buffer);
		DWORD actual = 0;
		WriteFile(file->fp, buffer, length, &actual, NULL);
		result += actual;
	}

	free(buffer);
	return result;
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

uint64_t file_get_size(struct file_t *file, uint64_t result_on_error)
{
	LARGE_INTEGER lresult;
	if (!GetFileSizeEx(file->fp, &lresult)) {
		return result_on_error;
	}

	return (uint64_t)lresult.QuadPart;
}

void file_close(struct file_t *file)
{
	if (file->mmap_base) {
		UnmapViewOfFile(file->mmap_base);
		CloseHandle(file->mmap_handle);
	}

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

void file_sync_all(void)
{
}
