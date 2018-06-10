/*
 * netbuf.c
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("netbuf");

#define NETBUF_PAGE_SIZE 256

struct netbuf_manager_t
{
	struct spinlock lock;
	size_t total_allocated;
};

static struct netbuf_manager_t netbuf_manager;

static inline void netbuf_manager_record_alloc(size_t size)
{
	spinlock_lock(&netbuf_manager.lock);
	netbuf_manager.total_allocated += size;
	spinlock_unlock(&netbuf_manager.lock);
}

static inline void netbuf_manager_record_free(size_t size)
{
	spinlock_lock(&netbuf_manager.lock);
	netbuf_manager.total_allocated -= size;
	spinlock_unlock(&netbuf_manager.lock);
}

static size_t netbuf_pages_needed(size_t length)
{
	return (length + NETBUF_PAGE_SIZE - 1) / NETBUF_PAGE_SIZE;
}

static size_t netbuf_alloc_size(size_t length)
{
	return (1 + netbuf_pages_needed(length) + 1) * NETBUF_PAGE_SIZE;
}

struct netbuf *netbuf_alloc(void)
{
	struct netbuf *nb = (struct netbuf *)heap_alloc_and_zero(sizeof(struct netbuf), PKG_OS, MEM_TYPE_OS_NETBUF);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	return nb;
}

struct netbuf *netbuf_alloc_with_fwd_space(size_t size)
{
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		return NULL;
	}

	if (!netbuf_fwd_make_space(nb, size)) {
		netbuf_free(nb);
		return NULL;
	}

	return nb;
}

struct netbuf *netbuf_alloc_with_rev_space(size_t size)
{
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		return NULL;
	}

	if (!netbuf_rev_make_space(nb, size)) {
		netbuf_free(nb);
		return NULL;
	}

	return nb;
}

struct netbuf *netbuf_alloc_and_steal(struct netbuf *orig)
{
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		return NULL;
	}

	nb->buffer = orig->buffer;
	nb->limit = orig->limit;
	nb->start = orig->start;
	nb->end = orig->end;
	nb->pos = orig->pos;

	orig->buffer = NULL;
	orig->limit = NULL;
	orig->start = NULL;
	orig->end = NULL;
	orig->pos = NULL;

	return nb;
}

struct netbuf *netbuf_clone(struct netbuf *orig)
{
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		return NULL;
	}

	size_t orig_len = orig->end - orig->start;
	size_t orig_pos = orig->pos - orig->start;
	size_t alloc_size = netbuf_alloc_size(orig_len);

	DEBUG_TRACE("netbuf_clone malloc and copy");
	nb->buffer = (uint8_t *)malloc(alloc_size);
	if (!nb->buffer) {
		DEBUG_ERROR("out of memory");
		netbuf_free(nb);
		return NULL;
	}

	netbuf_manager_record_alloc(alloc_size);
	nb->limit = nb->buffer + alloc_size;
	nb->start = nb->buffer + NETBUF_PAGE_SIZE;
	nb->pos = nb->start + orig_pos;
	nb->end = nb->start + orig_len;

	memcpy(nb->start, orig->start, orig_len);
	return nb;
}

void netbuf_free(struct netbuf *nb)
{
	if (nb->buffer) {
		netbuf_manager_record_free(nb->limit - nb->buffer);
		free(nb->buffer);
	}

	heap_free(nb);
}

void netbuf_reset(struct netbuf *nb)
{
	if (nb->buffer) {
		netbuf_manager_record_free(nb->limit - nb->buffer);
		free(nb->buffer);
	}

	memset(nb, 0, sizeof(struct netbuf));
}

bool netbuf_fwd_check_space(struct netbuf *nb, size_t size)
{
	return (nb->pos + size <= nb->end);
}

uint8_t netbuf_fwd_read_u8(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 1 <= nb->end, "read beyond end of netbuf");

	return *nb->pos++;
}

uint16_t netbuf_fwd_read_u16(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 2 <= nb->end, "read beyond end of netbuf");

	uint16_t v;
	v  = (uint16_t)*nb->pos++ << 8;
	v |= (uint16_t)*nb->pos++ << 0;
	return v;
}

uint32_t netbuf_fwd_read_u24(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 3 <= nb->end, "read beyond end of netbuf");

	uint32_t v;
	v  = (uint32_t)*nb->pos++ << 16;
	v |= (uint32_t)*nb->pos++ << 8;
	v |= (uint32_t)*nb->pos++ << 0;
	return v;
}

uint32_t netbuf_fwd_read_u32(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 4 <= nb->end, "read beyond end of netbuf");

	uint32_t v;
	v  = (uint32_t)*nb->pos++ << 24;
	v |= (uint32_t)*nb->pos++ << 16;
	v |= (uint32_t)*nb->pos++ << 8;
	v |= (uint32_t)*nb->pos++ << 0;
	return v;
}

uint64_t netbuf_fwd_read_u64(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 8 <= nb->end, "read beyond end of netbuf");

	uint64_t v;
	v  = (uint64_t)*nb->pos++ << 56;
	v |= (uint64_t)*nb->pos++ << 48;
	v |= (uint64_t)*nb->pos++ << 40;
	v |= (uint64_t)*nb->pos++ << 32;
	v |= (uint64_t)*nb->pos++ << 24;
	v |= (uint64_t)*nb->pos++ << 16;
	v |= (uint64_t)*nb->pos++ << 8;
	v |= (uint64_t)*nb->pos++ << 0;
	return v;
}

uint16_t netbuf_fwd_read_le_u16(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 2 <= nb->end, "read beyond end of netbuf");

	uint16_t v;
	v  = (uint16_t)*nb->pos++ << 0;
	v |= (uint16_t)*nb->pos++ << 8;
	return v;
}

uint32_t netbuf_fwd_read_le_u32(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 4 <= nb->end, "read beyond end of netbuf");

	uint32_t v;
	v  = (uint32_t)*nb->pos++ << 0;
	v |= (uint32_t)*nb->pos++ << 8;
	v |= (uint32_t)*nb->pos++ << 16;
	v |= (uint32_t)*nb->pos++ << 24;
	return v;
}

uint64_t netbuf_fwd_read_le_u64(struct netbuf *nb)
{
	DEBUG_ASSERT(nb->pos + 8 <= nb->end, "read beyond end of netbuf");

	uint64_t v;
	v  = (uint64_t)*nb->pos++ << 0;
	v |= (uint64_t)*nb->pos++ << 8;
	v |= (uint64_t)*nb->pos++ << 16;
	v |= (uint64_t)*nb->pos++ << 24;
	v |= (uint64_t)*nb->pos++ << 32;
	v |= (uint64_t)*nb->pos++ << 40;
	v |= (uint64_t)*nb->pos++ << 48;
	v |= (uint64_t)*nb->pos++ << 56;
	return v;
}

void netbuf_fwd_read(struct netbuf *nb, void *buffer, size_t size)
{
	DEBUG_ASSERT(size > 0, "read of 0 bytes");
	DEBUG_ASSERT(nb->pos + size <= nb->end, "read beyond end of netbuf");

	memcpy(buffer, nb->pos, size);
	nb->pos += size;
}

long netbuf_fwd_strtol(struct netbuf *nb, addr_t *endptr, int base)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	char *end = NULL;
	long result = strtol((char *)nb->pos, &end, base);

	if (endptr) {
		*endptr = (addr_t)end;
	}

	return result;
}

unsigned long netbuf_fwd_strtoul(struct netbuf *nb, addr_t *endptr, int base)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	char *end = NULL;
	unsigned long result = strtoul((char *)nb->pos, &end, base);

	if (endptr) {
		*endptr = (addr_t)end;
	}

	return result;
}

long long netbuf_fwd_strtoll(struct netbuf *nb, addr_t *endptr, int base)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	char *end = NULL;
	long long result = strtoll((char *)nb->pos, &end, base);

	if (endptr) {
		*endptr = (addr_t)end;
	}

	return result;
}

unsigned long long netbuf_fwd_strtoull(struct netbuf *nb, addr_t *endptr, int base)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	char *end = NULL;
	unsigned long long result = strtoull((char *)nb->pos, &end, base);

	if (endptr) {
		*endptr = (addr_t)end;
	}

	return result;
}

addr_t netbuf_fwd_strchr(struct netbuf *nb, char c)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return (addr_t)strchr((char *)nb->pos, c);
}

addr_t netbuf_fwd_strstr(struct netbuf *nb, const char *s)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return (addr_t)strstr((char *)nb->pos, s);
}

addr_t netbuf_fwd_strcasestr(struct netbuf *nb, const char *s)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return (addr_t)strcasestr((char *)nb->pos, s);
}

int netbuf_fwd_memcmp(struct netbuf *nb, const void *s, size_t count)
{
	return memcmp((char *)nb->pos, s, count);
}

int netbuf_fwd_strcmp(struct netbuf *nb, const char *s)
{	
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return strcmp((char *)nb->pos, s);
}

int netbuf_fwd_strncmp(struct netbuf *nb, const char *s, size_t count)
{
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return strncmp((char *)nb->pos, s, count);
}

int netbuf_fwd_strcasecmp(struct netbuf *nb, const char *s)
{	
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return strcasecmp((char *)nb->pos, s);
}

int netbuf_fwd_strncasecmp(struct netbuf *nb, const char *s, size_t count)
{	
	DEBUG_ASSERT(nb->end + 1 <= nb->limit, "no space for netbuf string termination (%p %p)", nb->end, nb->limit);
	*nb->end = 0;

	return strncasecmp((char *)nb->pos, s, count);
}

bool netbuf_fwd_make_space(struct netbuf *nb, size_t size)
{
	if (!nb->buffer) {
		size_t alloc_size = netbuf_alloc_size(size);

		nb->buffer = (uint8_t *)malloc(alloc_size);
		if (!nb->buffer) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_manager_record_alloc(alloc_size);
		nb->limit = nb->buffer + alloc_size;
		nb->start = nb->buffer + NETBUF_PAGE_SIZE;
		nb->end = nb->start + size;
		nb->pos = nb->start;
		return true;
	}

	if (nb->pos + size + 1 > nb->limit) {
		uint8_t *orig_buffer = nb->buffer;
		uint8_t *orig_start = nb->start;
		size_t orig_len = nb->end - nb->start;
		size_t start_to_pos_len = nb->pos - nb->start;
		size_t alloc_size = netbuf_alloc_size(start_to_pos_len + size);

		DEBUG_TRACE("netbuf_fwd_make_space malloc and copy");
		uint8_t *new_buffer = (uint8_t *)malloc(alloc_size);
		if (!new_buffer) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_manager_record_alloc(alloc_size - (nb->limit - nb->buffer));
		nb->buffer = new_buffer;
		nb->limit = nb->buffer + alloc_size;
		nb->start = nb->buffer + NETBUF_PAGE_SIZE;
		nb->end = nb->start + (start_to_pos_len + size);
		nb->pos = nb->start + start_to_pos_len;

		memcpy(nb->start, orig_start, orig_len);
		free(orig_buffer);
		return true;
	}

	if (nb->pos + size > nb->end) {
		nb->end = nb->pos + size;
	}

	return true;
}

void netbuf_fwd_write_u8(struct netbuf *nb, uint8_t v)
{
	DEBUG_ASSERT(nb->pos + 1 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = v;
}

void netbuf_fwd_write_u16(struct netbuf *nb, uint16_t v)
{
	DEBUG_ASSERT(nb->pos + 2 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 0);
}

void netbuf_fwd_write_u24(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos + 3 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 16);
	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 0);
}

void netbuf_fwd_write_u32(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos + 4 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 24);
	*nb->pos++ = (uint8_t)(v >> 16);
	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 0);
}

void netbuf_fwd_write_u64(struct netbuf *nb, uint64_t v)
{
	DEBUG_ASSERT(nb->pos + 8 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 56);
	*nb->pos++ = (uint8_t)(v >> 48);
	*nb->pos++ = (uint8_t)(v >> 40);
	*nb->pos++ = (uint8_t)(v >> 32);
	*nb->pos++ = (uint8_t)(v >> 24);
	*nb->pos++ = (uint8_t)(v >> 16);
	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 0);
}

void netbuf_fwd_write_le_u16(struct netbuf *nb, uint16_t v)
{
	DEBUG_ASSERT(nb->pos + 2 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 0);
	*nb->pos++ = (uint8_t)(v >> 8);
}

void netbuf_fwd_write_le_u32(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos + 4 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 0);
	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 16);
	*nb->pos++ = (uint8_t)(v >> 24);
}

void netbuf_fwd_write_le_u64(struct netbuf *nb, uint64_t v)
{
	DEBUG_ASSERT(nb->pos + 8 <= nb->end, "write beyond end of netbuf");

	*nb->pos++ = (uint8_t)(v >> 0);
	*nb->pos++ = (uint8_t)(v >> 8);
	*nb->pos++ = (uint8_t)(v >> 16);
	*nb->pos++ = (uint8_t)(v >> 24);
	*nb->pos++ = (uint8_t)(v >> 32);
	*nb->pos++ = (uint8_t)(v >> 40);
	*nb->pos++ = (uint8_t)(v >> 48);
	*nb->pos++ = (uint8_t)(v >> 56);
}

void netbuf_fwd_write(struct netbuf *nb, const void *buffer, size_t size)
{
	DEBUG_ASSERT(size > 0, "write of 0 bytes");
	DEBUG_ASSERT(nb->pos + size <= nb->end, "write beyond end of netbuf");

	memcpy(nb->pos, buffer, size);
	nb->pos += size;
}

void netbuf_fwd_fill_u8(struct netbuf *nb, size_t size, uint8_t value)
{
	memset(nb->pos, value, size);
	nb->pos += size;
}

void netbuf_fwd_copy(struct netbuf *nb, struct netbuf *orig, size_t size)
{
	DEBUG_ASSERT(size > 0, "write of 0 bytes");
	DEBUG_ASSERT(nb->pos + size <= nb->end, "write beyond end of netbuf");

	memcpy(nb->pos, orig->pos, size);
	orig->pos += size;
	nb->pos += size;
}

bool netbuf_rev_make_space(struct netbuf *nb, size_t size)
{
	if (!nb->buffer) {
		size_t alloc_size = netbuf_alloc_size(size);

		nb->buffer = (uint8_t *)malloc(alloc_size);
		if (!nb->buffer) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_manager_record_alloc(alloc_size);
		nb->limit = nb->buffer + alloc_size;
		nb->end = nb->limit - NETBUF_PAGE_SIZE;
		nb->start = nb->end - size;
		nb->pos = nb->end;
		return true;
	}

	if (nb->pos - size < nb->buffer) {
		uint8_t *orig_buffer = nb->buffer;
		uint8_t *orig_start = nb->start;
		size_t orig_len = nb->end - nb->start;
		size_t pos_to_end_len = nb->end - nb->pos;
		size_t alloc_size = netbuf_alloc_size(size + pos_to_end_len);

		DEBUG_TRACE("netbuf_rev_make_space malloc and copy");
		uint8_t *new_buffer = (uint8_t *)malloc(alloc_size);
		if (!new_buffer) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_manager_record_alloc(alloc_size - (nb->limit - nb->buffer));
		nb->buffer = new_buffer;
		nb->limit = nb->buffer + alloc_size;
		nb->end = nb->limit - NETBUF_PAGE_SIZE;
		nb->start = nb->end - (size + pos_to_end_len);
		nb->pos = nb->end - pos_to_end_len;

		memcpy(nb->end - orig_len, orig_start, orig_len);
		free(orig_buffer);
		return true;
	}

	if (nb->pos - size < nb->start) {
		nb->start = nb->pos - size;
	}

	return true;
}

void netbuf_rev_write_u8(struct netbuf *nb, uint8_t v)
{
	DEBUG_ASSERT(nb->pos - 1 >= nb->start, "write before start of netbuf");

	*--nb->pos = v;
}

void netbuf_rev_write_u16(struct netbuf *nb, uint16_t v)
{
	DEBUG_ASSERT(nb->pos - 2 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 0);
	*--nb->pos = (uint8_t)(v >> 8);
}

void netbuf_rev_write_u24(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos - 3 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 0);
	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 16);
}

void netbuf_rev_write_u32(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos - 4 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 0);
	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 16);
	*--nb->pos = (uint8_t)(v >> 24);
}

void netbuf_rev_write_u64(struct netbuf *nb, uint64_t v)
{
	DEBUG_ASSERT(nb->pos - 8 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 0);
	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 16);
	*--nb->pos = (uint8_t)(v >> 24);
	*--nb->pos = (uint8_t)(v >> 32);
	*--nb->pos = (uint8_t)(v >> 40);
	*--nb->pos = (uint8_t)(v >> 48);
	*--nb->pos = (uint8_t)(v >> 56);
}

void netbuf_rev_write_le_u16(struct netbuf *nb, uint16_t v)
{
	DEBUG_ASSERT(nb->pos - 2 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 0);
}

void netbuf_rev_write_le_u32(struct netbuf *nb, uint32_t v)
{
	DEBUG_ASSERT(nb->pos - 4 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 24);
	*--nb->pos = (uint8_t)(v >> 16);
	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 0);
}

void netbuf_rev_write_le_u64(struct netbuf *nb, uint64_t v)
{
	DEBUG_ASSERT(nb->pos - 8 >= nb->start, "write before start of netbuf");

	*--nb->pos = (uint8_t)(v >> 56);
	*--nb->pos = (uint8_t)(v >> 48);
	*--nb->pos = (uint8_t)(v >> 40);
	*--nb->pos = (uint8_t)(v >> 32);
	*--nb->pos = (uint8_t)(v >> 24);
	*--nb->pos = (uint8_t)(v >> 16);
	*--nb->pos = (uint8_t)(v >> 8);
	*--nb->pos = (uint8_t)(v >> 0);
}

void netbuf_rev_write(struct netbuf *nb, const void *buffer, size_t size)
{
	DEBUG_ASSERT(size > 0, "write of 0 bytes");
	DEBUG_ASSERT(nb->pos - size >= nb->start, "write before start of netbuf");

	nb->pos -= size;
	memcpy(nb->pos, buffer, size);
}

void netbuf_rev_fill_u8(struct netbuf *nb, size_t size, uint8_t value)
{
	nb->pos -= size;
	memset(nb->pos, value, size);
}

void netbuf_rev_copy(struct netbuf *nb, struct netbuf *orig, size_t size)
{
	DEBUG_ASSERT(size > 0, "write of 0 bytes");
	DEBUG_ASSERT(nb->pos - size >= nb->start, "write before start of netbuf");

	nb->pos -= size;
	memcpy(nb->pos, orig->pos, size);
	orig->pos += size;
}

size_t netbuf_get_preceding(struct netbuf *nb)
{
	return nb->pos - nb->start;
}

size_t netbuf_get_remaining(struct netbuf *nb)
{
	return nb->end - nb->pos;
}

size_t netbuf_get_extent(struct netbuf *nb)
{
	return nb->end - nb->start;
}

addr_t netbuf_get_pos(struct netbuf *nb)
{
	return (addr_t)nb->pos;
}

void netbuf_set_pos(struct netbuf *nb, addr_t pos)
{
	DEBUG_ASSERT(pos >= (addr_t)nb->start, "pos before start of netbuf");
	DEBUG_ASSERT(pos <= (addr_t)nb->end, "pos beyond end of netbuf");
	nb->pos = (uint8_t *)pos;
}

void netbuf_set_pos_to_start(struct netbuf *nb)
{
	nb->pos = nb->start;
}

void netbuf_set_pos_to_end(struct netbuf *nb)
{
	nb->pos = nb->end;
}

void netbuf_advance_pos(struct netbuf *nb, size_t offs)
{
	DEBUG_ASSERT(nb->pos + offs <= nb->end, "pos beyond end of netbuf");
	nb->pos += offs;
}

void netbuf_retreat_pos(struct netbuf *nb, size_t offs)
{
	DEBUG_ASSERT(nb->pos - offs >= nb->start, "pos before start of netbuf");
	nb->pos -= offs;
}

addr_t netbuf_get_start(struct netbuf *nb)
{
	return (addr_t)nb->start;
}

void netbuf_set_start(struct netbuf *nb, addr_t pos)
{
	DEBUG_ASSERT(pos >= (addr_t)nb->buffer, "start before buffer of netbuf");
	DEBUG_ASSERT(pos <= (addr_t)nb->pos, "start beyond pos of netbuf");
	nb->start = (uint8_t *)pos;
}

void netbuf_set_start_to_pos(struct netbuf *nb)
{
	nb->start = nb->pos;
}

addr_t netbuf_get_end(struct netbuf *nb)
{
	return (addr_t)nb->end;
}

void netbuf_set_end(struct netbuf *nb, addr_t pos)
{
	DEBUG_ASSERT(pos >= (addr_t)nb->pos, "end before pos of netbuf");
	DEBUG_ASSERT(pos + 1 <= (addr_t)nb->limit, "end beyond limit of netbuf");
	nb->end = (uint8_t *)pos;
}

void netbuf_set_end_to_pos(struct netbuf *nb)
{
	nb->end = nb->pos;
}

void netbuf_retreat_end(struct netbuf *nb, size_t offs)
{
	DEBUG_ASSERT(nb->end - offs >= nb->pos, "end before pos of netbuf");
	nb->end -= offs;
}

uint8_t *netbuf_get_ptr(struct netbuf *nb)
{
	return nb->pos;
}

uint32_t netbuf_crc32(struct netbuf *nb)
{
	static const uint32_t netbuf_crc32_lookup_low[16] = {
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91
	};

	static const uint32_t netbuf_crc32_lookup_high[16] = {
		0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
		0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
	};

	uint8_t *ptr = nb->start;
	uint32_t crc = 0xFFFFFFFF;
	while (ptr < nb->end) {
		uint8_t x = (uint8_t)crc ^ *ptr++;
		crc >>= 8;
		crc ^= netbuf_crc32_lookup_low[x & 0x0F];
		crc ^= netbuf_crc32_lookup_high[x >> 4];
	}

	crc ^= 0xFFFFFFFF;
	return byteswap_u32(crc);
}

size_t netbuf_queue_get_count(struct netbuf_queue *queue)
{
	return queue->count;
}

struct netbuf *netbuf_queue_get_head(struct netbuf_queue *queue)
{
	return queue->head;
}

void netbuf_queue_attach_head(struct netbuf_queue *queue, struct netbuf *nb)
{
	if (!queue->head) {
		DEBUG_ASSERT(queue->count == 0, "queue count error");
		queue->tail = nb;
	} else {
		DEBUG_ASSERT(queue->count > 0, "queue count error");
	}

	nb->next = queue->head;
	queue->head = nb;
	queue->count++;
}

void netbuf_queue_attach_tail(struct netbuf_queue *queue, struct netbuf *nb)
{
	if (!queue->tail) {
		DEBUG_ASSERT(queue->count == 0, "queue count error");
		queue->head = nb;
	} else {
		DEBUG_ASSERT(queue->count > 0, "queue count error");
		queue->tail->next = nb;
	}

	queue->tail = nb;
	queue->count++;
	nb->next = NULL;
}

bool netbuf_queue_attach_tail_limit(struct netbuf_queue *queue, struct netbuf *nb, size_t max_count)
{
	if (queue->count >= max_count) {
		return false;
	}

	netbuf_queue_attach_tail(queue, nb);
	return true;
}

struct netbuf *netbuf_queue_detach_head(struct netbuf_queue *queue)
{
	struct netbuf *nb = queue->head;
	if (!nb) {
		return NULL;
	}

	queue->count--;
	queue->head = nb->next;
	nb->next = NULL;

	if (!queue->head) {
		DEBUG_ASSERT(queue->count == 0, "queue count error");
		queue->tail = NULL;
	} else {
		DEBUG_ASSERT(queue->count > 0, "queue count error");
	}

	return nb;
}

size_t netbuf_manager_get_total_allocated(void)
{
	spinlock_lock(&netbuf_manager.lock);
	size_t result = netbuf_manager.total_allocated;
	spinlock_unlock(&netbuf_manager.lock);
	return result;
}

void netbuf_manager_init(void)
{
	spinlock_init(&netbuf_manager.lock, 0);
}
