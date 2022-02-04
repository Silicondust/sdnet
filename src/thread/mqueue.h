/*
 * mqueue.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define MQUEUE_SIZEOF(x) sizeof(x)

struct mqueue_t;

typedef void (*mqueue_read_handler_func_t)(void);

extern struct mqueue_t *mqueue_alloc(size_t max_queue_depth, struct thread_signal_t *signal);

extern mqueue_read_handler_func_t mqueue_read_request(struct mqueue_t *mqueue);
extern uint8_t mqueue_read_u8(struct mqueue_t *mqueue);
extern uint16_t mqueue_read_u16(struct mqueue_t *mqueue);
extern uint32_t mqueue_read_u32(struct mqueue_t *mqueue);
extern uint64_t mqueue_read_u64(struct mqueue_t *mqueue);
extern int mqueue_read_int(struct mqueue_t *mqueue);
extern void *mqueue_read_handle(struct mqueue_t *mqueue);
extern void mqueue_read_complete(struct mqueue_t *mqueue);

extern bool mqueue_write_request(struct mqueue_t *mqueue, mqueue_read_handler_func_t read_handler, size_t length);
extern void mqueue_write_request_blocking(struct mqueue_t *mqueue, mqueue_read_handler_func_t read_handler, size_t length);
extern void mqueue_write_u8(struct mqueue_t *mqueue, uint8_t value);
extern void mqueue_write_u16(struct mqueue_t *mqueue, uint16_t value);
extern void mqueue_write_u32(struct mqueue_t *mqueue, uint32_t value);
extern void mqueue_write_u64(struct mqueue_t *mqueue, uint64_t value);
extern void mqueue_write_int(struct mqueue_t *mqueue, int value);
extern void mqueue_write_handle(struct mqueue_t *mqueue, void *value);
extern void mqueue_write_complete(struct mqueue_t *mqueue);
extern void mqueue_write_cancel(struct mqueue_t *mqueue);
