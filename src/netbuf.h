/*
 * netbuf.h
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define NETBUF_MAX_LENGTH (128 * 1024)

#define NETBUF_FLAG_SILICONDUST_ARP_QUEUE_DISABLE 0
#define NETBUF_FLAG_SILICONDUST_QOS_MPEGTS 0

struct netbuf;
struct netbuf_queue;

extern struct netbuf *netbuf_alloc(void);
extern struct netbuf *netbuf_alloc_with_fwd_space(size_t size);
extern struct netbuf *netbuf_alloc_with_rev_space(size_t size);
extern struct netbuf *netbuf_alloc_and_steal(struct netbuf *orig);
extern struct netbuf *netbuf_clone(struct netbuf *orig);
extern void netbuf_free(struct netbuf *nb);

extern void netbuf_reset(struct netbuf *nb);

extern bool netbuf_exact_content_match(struct netbuf *nb1, struct netbuf *nb2);

extern bool netbuf_fwd_check_space(struct netbuf *nb, size_t size);
extern uint8_t netbuf_fwd_read_u8(struct netbuf *nb);
extern uint16_t netbuf_fwd_read_u16(struct netbuf *nb);
extern uint32_t netbuf_fwd_read_u24(struct netbuf *nb);
extern uint32_t netbuf_fwd_read_u32(struct netbuf *nb);
extern uint64_t netbuf_fwd_read_u64(struct netbuf *nb);
extern uint16_t netbuf_fwd_read_le_u16(struct netbuf *nb);
extern uint32_t netbuf_fwd_read_le_u32(struct netbuf *nb);
extern uint64_t netbuf_fwd_read_le_u64(struct netbuf *nb);
extern void netbuf_fwd_read(struct netbuf *nb, void *buffer, size_t size);
extern long netbuf_fwd_strtol(struct netbuf *nb, addr_t *endptr, int base);
extern long long netbuf_fwd_strtoll(struct netbuf *nb, addr_t *endptr, int base);
extern unsigned long netbuf_fwd_strtoul(struct netbuf *nb, addr_t *endptr, int base);
extern unsigned long long netbuf_fwd_strtoull(struct netbuf *nb, addr_t *endptr, int base);
extern addr_t netbuf_fwd_strchr(struct netbuf *nb, char c);
extern addr_t netbuf_fwd_strstr(struct netbuf *nb, const char *s);
extern addr_t netbuf_fwd_strcasestr(struct netbuf *nb, const char *s);
extern int netbuf_fwd_memcmp(struct netbuf *nb, const void *s, size_t count); 
extern int netbuf_fwd_strcmp(struct netbuf *nb, const char *s);
extern int netbuf_fwd_strncmp(struct netbuf *nb, const char *s, size_t count);
extern int netbuf_fwd_strcasecmp(struct netbuf *nb, const char *s);
extern int netbuf_fwd_strncasecmp(struct netbuf *nb, const char *s, size_t count);

extern bool netbuf_fwd_make_space(struct netbuf *nb, size_t size);
extern void netbuf_fwd_write_u8(struct netbuf *nb, uint8_t v);
extern void netbuf_fwd_write_u16(struct netbuf *nb, uint16_t v);
extern void netbuf_fwd_write_u24(struct netbuf *nb, uint32_t v);
extern void netbuf_fwd_write_u32(struct netbuf *nb, uint32_t v);
extern void netbuf_fwd_write_u64(struct netbuf *nb, uint64_t v);
extern void netbuf_fwd_write_le_u16(struct netbuf *nb, uint16_t v);
extern void netbuf_fwd_write_le_u32(struct netbuf *nb, uint32_t v);
extern void netbuf_fwd_write_le_u64(struct netbuf *nb, uint64_t v);
extern void netbuf_fwd_write(struct netbuf *nb, const void *buffer, size_t size);
extern void netbuf_fwd_fill_u8(struct netbuf *nb, size_t size, uint8_t value);
extern void netbuf_fwd_copy(struct netbuf *nb, struct netbuf *orig, size_t size);

extern bool netbuf_rev_make_space(struct netbuf *nb, size_t size);
extern void netbuf_rev_write_u8(struct netbuf *nb, uint8_t v);
extern void netbuf_rev_write_u16(struct netbuf *nb, uint16_t v);
extern void netbuf_rev_write_u24(struct netbuf *nb, uint32_t v);
extern void netbuf_rev_write_u32(struct netbuf *nb, uint32_t v);
extern void netbuf_rev_write_u64(struct netbuf *nb, uint64_t v);
extern void netbuf_rev_write_le_u16(struct netbuf *nb, uint16_t v);
extern void netbuf_rev_write_le_u32(struct netbuf *nb, uint32_t v);
extern void netbuf_rev_write_le_u64(struct netbuf *nb, uint64_t v);
extern void netbuf_rev_write(struct netbuf *nb, const void *buffer, size_t size);
extern void netbuf_rev_fill_u8(struct netbuf *nb, size_t size, uint8_t value);
extern void netbuf_rev_copy(struct netbuf *nb, struct netbuf *orig, size_t size);

extern size_t netbuf_get_preceding(struct netbuf *nb);
extern size_t netbuf_get_remaining(struct netbuf *nb);
extern size_t netbuf_get_extent(struct netbuf *nb);

extern addr_t netbuf_get_pos(struct netbuf *nb);
extern void netbuf_set_pos(struct netbuf *nb, addr_t pos);
extern void netbuf_set_pos_to_start(struct netbuf *nb);
extern void netbuf_set_pos_to_end(struct netbuf *nb);
extern void netbuf_advance_pos(struct netbuf *nb, size_t offs);
extern void netbuf_retreat_pos(struct netbuf *nb, size_t offs);

extern addr_t netbuf_get_start(struct netbuf *nb);
extern void netbuf_set_start(struct netbuf *nb, addr_t pos);
extern void netbuf_set_start_to_pos(struct netbuf *nb);

extern addr_t netbuf_get_end(struct netbuf *nb);
extern void netbuf_set_end(struct netbuf *nb, addr_t pos);
extern void netbuf_set_end_to_pos(struct netbuf *nb);
extern void netbuf_retreat_end(struct netbuf *nb, size_t offs);

extern uint32_t netbuf_crc32(struct netbuf *nb);

extern size_t netbuf_queue_get_count(struct netbuf_queue *queue);
extern struct netbuf *netbuf_queue_get_head(struct netbuf_queue *queue);
extern void netbuf_queue_attach_head(struct netbuf_queue *queue, struct netbuf *nb);
extern void netbuf_queue_attach_tail(struct netbuf_queue *queue, struct netbuf *nb);
extern bool netbuf_queue_attach_tail_limit(struct netbuf_queue *queue, struct netbuf *nb, size_t max_count);
extern struct netbuf *netbuf_queue_detach_head(struct netbuf_queue *queue);
extern void netbuf_queue_detach_and_free_all(struct netbuf_queue *queue);
