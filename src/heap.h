/*
 * ./src/heap.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void *heap_alloc(size_t size, uint8_t pkg, uint8_t type);
extern void *heap_alloc_and_zero(size_t size, uint8_t pkg, uint8_t type);
extern void *heap_realloc(void *block, size_t size, uint8_t pkg, uint8_t type);
extern char *heap_strdup(const char *str, uint8_t pkg, uint8_t type);
extern char *heap_netbuf_strdup(struct netbuf *nb, uint8_t pkg, uint8_t type);
extern bool heap_verify(void *block);
extern void heap_free(void *block);

extern void heap_leaktrack_set_ignore(void *block);
extern void heap_leaktrack_set_ignore_all(void);
extern void heap_leaktrack_log_state(void);

extern void heap_manager_init(void);
extern size_t heap_manager_get_total_allocated(void);
