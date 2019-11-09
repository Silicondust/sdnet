/*
 * gunzip.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct gunzip_t;

#define GUNZIP_STATUS_DATA 0
#define GUNZIP_STATUS_COMPLETE 1
#define GUNZIP_STATUS_ERROR 2

typedef bool (*gunzip_output_callback_func_t)(void *arg, uint8_t status, uint8_t *ptr, uint8_t *end);

extern struct gunzip_t *gunzip_alloc(void);
extern void gunzip_register_callbacks(struct gunzip_t *gunzip, gunzip_output_callback_func_t output_callback, void *callback_arg);
extern void gunzip_free(struct gunzip_t *gunzip);
extern void gunzip_reset(struct gunzip_t *gunzip);
extern bool gunzip_input_data(struct gunzip_t *gunzip, uint8_t *ptr, uint8_t *end);
extern bool gunzip_input_eof(struct gunzip_t *gunzip);
