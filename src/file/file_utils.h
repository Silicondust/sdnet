/*
 * ./src/file/file_utils.h
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern FILE *fopen_utf8(const char *path, const char *mode);

struct file_t;

extern struct file_t *file_open_read(const char *path);
extern struct file_t *file_open_create(const char *path);
extern struct file_t *file_open_existing(const char *path);
extern size_t file_read(struct file_t *file, void *buffer, size_t length);
extern size_t file_write(struct file_t *file, void *buffer, size_t length);
extern bool file_seek_set(struct file_t *file, uint64_t offset);
extern bool file_seek_advance(struct file_t *file, uint64_t offset);
extern bool file_seek_retreat(struct file_t *file, uint64_t offset);
extern bool file_seek_end(struct file_t *file);
extern uint64_t file_get_pos(struct file_t *file, uint64_t result_on_error);
extern void file_close(struct file_t *file);

extern bool file_delete(const char *path, bool result_on_not_found);
extern bool file_move(const char *new_path, const char *old_path);
