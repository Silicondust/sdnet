/*
 * ./src/text/sscanf_custom.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool vsscanf_custom(const char *str, const char *fmt, va_list ap);
extern bool sscanf_custom(const char *str, const char *fmt, ...);

extern bool vsscanf_custom_with_advance(const char **pstr, const char *fmt, va_list ap);
extern bool sscanf_custom_with_advance(const char **pstr, const char *fmt, ...);
