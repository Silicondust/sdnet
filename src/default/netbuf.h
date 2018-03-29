/*
 * ./src/default/netbuf.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct netbuf {
	struct netbuf *next;
	uint8_t *buffer;
	uint8_t *limit;
	uint8_t *start;
	uint8_t *end;
	uint8_t *pos;
	uint32_t flags;
	uint32_t ext;
};

struct netbuf_queue {
	struct netbuf *head;
	struct netbuf *tail;
	size_t count;
};

extern uint8_t *netbuf_get_ptr(struct netbuf *nb);

extern void netbuf_manager_init(void);
extern size_t netbuf_manager_get_total_allocated(void);
