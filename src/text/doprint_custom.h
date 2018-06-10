/*
 * doprint_custom.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DOPRINT_CUSTOM_MODE_NORMAL 0
#define DOPRINT_CUSTOM_MODE_JSON 1
#define DOPRINT_CUSTOM_MODE_XML 2
#define DOPRINT_CUSTOM_MODE_URL 3

typedef bool (*doprint_custom_write_func_t)(void *arg, const char *str, size_t len);

extern bool doprint_custom(doprint_custom_write_func_t write_func, void *write_arg, uint8_t mode, const char *fmt, va_list ap);
