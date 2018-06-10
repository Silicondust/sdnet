/*
 * file_utils.c
 *
 * Copyright © 2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

#define FILE_CREATE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define FILE_MOVE_BLOCK_SIZE (1024 * 1024)

struct file_t {
	int fp;
};

static struct file_t *file_open_internal(const char *path, int flags)
{
	int fp = open(path, flags | O_NOFOLLOW, FILE_CREATE_MODE);
	if (fp < 0) {
		return NULL;
	}

	struct file_t *file = (struct file_t *)heap_alloc_and_zero(sizeof(struct file_t), PKG_OS, MEM_TYPE_OS_FILE);
	if (!file) {
		close(fp);
		return NULL;
	}

	file->fp = fp;
	return file;
}

struct file_t *file_open_read(const char *path)
{
	return file_open_internal(path, O_RDONLY);
}

struct file_t *file_open_create(const char *path)
{
	return file_open_internal(path, O_RDWR | O_CREAT);
}

struct file_t *file_open_existing(const char *path)
{
	return file_open_internal(path, O_RDWR);
}

size_t file_read(struct file_t *file, void *buffer, size_t length)
{
	ssize_t actual = read(file->fp, buffer, length);
	if (actual < 0) {
		return 0;
	}

	return actual;
}

size_t file_write(struct file_t *file, void *buffer, size_t length)
{
	ssize_t actual = write(file->fp, buffer, length);
	if (actual < 0) {
		return 0;
	}

	return actual;
}

bool file_seek_set(struct file_t *file, uint64_t offset)
{
	return (lseek(file->fp, (off_t)offset, SEEK_SET) >= 0);
}

bool file_seek_advance(struct file_t *file, uint64_t offset)
{
	return (lseek(file->fp, (off_t)offset, SEEK_CUR) >= 0);
}

bool file_seek_retreat(struct file_t *file, uint64_t offset)
{
	return (lseek(file->fp, -(off_t)offset, SEEK_CUR) >= 0);
}

bool file_seek_end(struct file_t *file)
{
	return (lseek(file->fp, 0, SEEK_END) >= 0);
}

uint64_t file_get_pos(struct file_t *file, uint64_t result_on_error)
{
	off_t result = lseek(file->fp, 0, SEEK_CUR);
	if (result < 0) {
		return result_on_error;
	}

	return (uint64_t)result;
}

void file_close(struct file_t *file)
{
	close(file->fp);
	heap_free(file);
}

FILE *fopen_utf8(const char *path, const char *mode)
{
	return fopen(path, mode);
}

bool file_delete(const char *path, bool result_on_not_found)
{
	if (unlink(path) < 0) {
		if (errno == ENOENT) {
			return result_on_not_found;
		}

		return false;
	}

	return true;
}

static bool file_move_internal(int new_fp, int old_fp, void *buffer)
{
	while (1) {
		ssize_t read_actual = read(old_fp, buffer, FILE_MOVE_BLOCK_SIZE);
		if (read_actual < 0) {
			return false;
		}

		if (read_actual == 0) {
			return true;
		}

		ssize_t write_actual = write(new_fp, buffer, read_actual);
		if (write_actual != read_actual) {
			return false;
		}

		if (read_actual < FILE_MOVE_BLOCK_SIZE) {
			return true;
		}
	}
}

bool file_move(const char *new_path, const char *old_path)
{
	if (rename(old_path, new_path) == 0) {
		return true;
	}

	if (errno != EXDEV) {
		return false;
	}

	void *buffer = malloc(FILE_MOVE_BLOCK_SIZE);
	if (!buffer) {
		return false;
	}

	/* open for RW as a test to know we can delete the file */
	int old_fp = open(old_path, O_RDWR | O_NOFOLLOW, FILE_CREATE_MODE);
	if (old_fp < 0) {
		free(buffer);
		return false;
	}

	int new_fp = open(new_path, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW, FILE_CREATE_MODE);
	if (new_fp < 0) {
		close(old_fp);
		free(buffer);
		return false;
	}

	if (!file_move_internal(new_fp, old_fp, buffer)) {
		close(new_fp);
		close(old_fp);
		free(buffer);
		unlink(new_path);
		return false;
	}

	close(new_fp);
	close(old_fp);
	free(buffer);
	unlink(old_path);
	return true;
}
