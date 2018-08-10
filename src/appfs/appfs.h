/*
 * appfs.h
 *
 * Copyright © 2012-2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Appfs is a mechanism to put files inside the executable that can be retreived and used by the app.
 *
 * Files are stored in a tar container which is linked into the executable as binary data. The appfs
 * apis process the embedded tar data to locate and return the requested file data.
 *
 * The tar archive must be creared with the "--format ustar" option and the "-b 1" option.
 *
 * Performance: the current implementation does not index the tar file - each time a file is requested
 * (open or mmap) the tar data is walked until the requested file is found or the end is reached.
 */

struct appfs_file_t;

extern void *appfs_file_mmap(const char *filename, const char *root, size_t *psize);

extern struct appfs_file_t *appfs_file_open(const char *filename, const char *root);
extern void appfs_file_close(struct appfs_file_t *stream);
extern size_t appfs_file_size(struct appfs_file_t *stream);
extern size_t appfs_file_get_remaining(struct appfs_file_t *stream);
extern size_t appfs_file_getpos(struct appfs_file_t *stream);
extern void appfs_file_setpos(struct appfs_file_t *stream, size_t position);
extern void appfs_file_seek(struct appfs_file_t *stream, ssize_t offset);
extern void appfs_file_read(struct appfs_file_t *stream, void *ptr, size_t count);
extern void appfs_file_read_netbuf(struct appfs_file_t *stream, struct netbuf *nb, size_t count);
extern uint8_t appfs_file_read_u8(struct appfs_file_t *stream);
extern uint16_t appfs_file_read_u16(struct appfs_file_t *stream);
extern uint32_t appfs_file_read_u32(struct appfs_file_t *stream);
extern uint64_t appfs_file_read_u64(struct appfs_file_t *stream);

extern void appfs_init(void);
extern void appfs_tar_init(void *start, void *end);
extern void appfs_tar_init_encrypted(void *start, void *end, aes_128_iv_t *iv, aes_128_key_t *key);
