/*
 * appfs_tar.c
 *
 * Copyright © 2012-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("appfs_tar");

struct appfs_file_t {
	uint8_t *data;
	uint8_t *end;
	uint8_t *pos;
};

struct appfs_tar_header_t {
	char file_name[100];
	char file_mode[8];
	char uid[8];
	char gid[8];
	char file_size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char t_linkname[100];
	char reserved[255];
};

struct appfs_tar_manager_t {
	uint8_t *data_start;
	uint8_t *data_end;
};

struct appfs_tar_manager_t appfs_tar_manager;

static inline bool appfs_file_open_filename_compare(const uint32_t *record_filename, const uint32_t *desired_filename)
{
	while (1) {
		uint32_t c = *desired_filename++;
		if (*record_filename++ != c) {
			return false;
		}
		if (c == 0) {
			return true;
		}
	}
}

struct appfs_file_t *appfs_file_open(const char *filename, const char *root)
{
	DEBUG_ASSERT(appfs_tar_manager.data_start, "no filesystem data");

	/* Skip leading slash. */
	char c = *root;
	if (c != 0) {
		root++;
	} else {
		c = *filename++;
	}
	if (c != '/') {
		DEBUG_ERROR("invalid filename");
		return NULL;
	}

	uint32_t desired_filename[100/4]; /* Max filename length in TAR header = 100 bytes. */
	memset(desired_filename, 0, sizeof(desired_filename));
	int ret = snprintf((char *)desired_filename, sizeof(desired_filename), "%s%s", root, filename);
	if (ret >= (int)sizeof(desired_filename)) {
		DEBUG_ERROR("invalid filename");
		return NULL;
	}

	uint8_t *ptr = appfs_tar_manager.data_start;
	uint8_t *end = appfs_tar_manager.data_end;

	while (1) {
		if (ptr >= end) {
			return NULL;
		}

		struct appfs_tar_header_t *header = (struct appfs_tar_header_t *)ptr;
		size_t file_size = strtoul(header->file_size, NULL, 8);

		if (appfs_file_open_filename_compare((uint32_t *)(addr_t)header->file_name, desired_filename)) {
			DEBUG_INFO("file %s = %u bytes", header->file_name, file_size);
			ptr += 512;
			end = ptr + file_size;
			break;
		}

		size_t blocks = (512 + file_size + 511) / 512;
		ptr += blocks * 512;
	}

	struct appfs_file_t *fi = (struct appfs_file_t *)heap_alloc_and_zero(sizeof(struct appfs_file_t), PKG_OS, MEM_TYPE_OS_FILE);
	if (!fi) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	fi->data = ptr;
	fi->pos = ptr;
	fi->end = end;
	return fi;
}

void appfs_file_close(struct appfs_file_t *fi)
{
	heap_free(fi);
}

size_t appfs_file_size(struct appfs_file_t *fi)
{
	return (size_t)(fi->end - fi->data);
}

size_t appfs_file_get_remaining(struct appfs_file_t *fi)
{
	return (size_t)(fi->end - fi->pos);
}

size_t appfs_file_getpos(struct appfs_file_t *fi)
{
	return (size_t)(fi->pos - fi->data);
}

void appfs_file_setpos(struct appfs_file_t *fi, size_t position)
{
	DEBUG_ASSERT(fi->data + position <= fi->end, "setpos beyond end of file");

	fi->pos = fi->data + position;
}

void appfs_file_seek(struct appfs_file_t *fi, ssize_t offset)
{
	DEBUG_ASSERT(fi->pos + offset >= fi->data, "-seek beyond start of file");
	DEBUG_ASSERT(fi->pos + offset <= fi->end, "seek beyond end of file");

	fi->pos += offset;
}

void appfs_file_read(struct appfs_file_t *fi, void *ptr, size_t count)
{
	DEBUG_ASSERT(fi->pos + count <= fi->end, "read beyond end of file");

	memcpy(ptr, fi->pos, count);
	fi->pos += count;
}

void appfs_file_read_netbuf(struct appfs_file_t *fi, struct netbuf *nb, size_t count)
{
	DEBUG_ASSERT(fi->pos + count <= fi->end, "read beyond end of file");

	netbuf_fwd_write(nb, fi->pos, count);
	fi->pos += count;
}

uint8_t appfs_file_read_u8(struct appfs_file_t *fi)
{
	DEBUG_ASSERT(fi->pos + 1 <= fi->end, "read beyond end of file");

	return *fi->pos++;
}

uint16_t appfs_file_read_u16(struct appfs_file_t *fi)
{
	DEBUG_ASSERT(fi->pos + 2 <= fi->end, "read beyond end of file");

	uint16_t v;
	v  = (uint16_t)(*fi->pos++) << 8;
	v |= (uint16_t)(*fi->pos++) << 0;
	return v;
}

uint32_t appfs_file_read_u32(struct appfs_file_t *fi)
{
	DEBUG_ASSERT(fi->pos + 4 <= fi->end, "read beyond end of file");

	uint32_t v;
	v  = (uint32_t)(*fi->pos++) << 24;
	v |= (uint32_t)(*fi->pos++) << 16;
	v |= (uint32_t)(*fi->pos++) << 8;
	v |= (uint32_t)(*fi->pos++) << 0;
	return v;
}

uint64_t appfs_file_read_u64(struct appfs_file_t *fi)
{
	DEBUG_ASSERT(fi->pos + 8 <= fi->end, "read beyond end of file");

	uint64_t v;
	v  = (uint64_t)(*fi->pos++) << 56;
	v |= (uint64_t)(*fi->pos++) << 48;
	v |= (uint64_t)(*fi->pos++) << 40;
	v |= (uint64_t)(*fi->pos++) << 32;
	v |= (uint64_t)(*fi->pos++) << 24;
	v |= (uint64_t)(*fi->pos++) << 16;
	v |= (uint64_t)(*fi->pos++) << 8;
	v |= (uint64_t)(*fi->pos++) << 0;
	return v;
}

void *appfs_file_mmap(const char *filename, const char *root, size_t *psize)
{
	struct appfs_file_t *fi = appfs_file_open(filename, root);
	if (!fi) {
		return NULL;
	}

	*psize = fi->end - fi->data;
	void *result = fi->data;

	appfs_file_close(fi);
	return result;
}

void appfs_tar_init(void *start, void *end)
{
	appfs_tar_manager.data_start = (uint8_t *)start;
	appfs_tar_manager.data_end = (uint8_t *)end;
	DEBUG_ASSERT(((addr_t)appfs_tar_manager.data_start & 0x3) == 0, "appfs not aligned");
}
