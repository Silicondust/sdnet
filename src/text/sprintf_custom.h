/*
 * ./src/text/sprintf_custom.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool sprintf_custom(char *buffer, char *end, const char *fmt, ...);
extern bool vsprintf_custom(char *buffer, char *end, const char *fmt, va_list ap);

extern bool sprintf_custom_url(char *buffer, char *end, const char *fmt, ...);
extern bool vsprintf_custom_url(char *buffer, char *end, const char *fmt, va_list ap);

extern bool sprintf_hex_array(char *buffer, char *end, void *data, size_t data_length);
