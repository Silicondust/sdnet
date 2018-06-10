/*
 * netbuf_sscanf.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool netbuf_vsprintf(struct netbuf *nb, const char *fmt, va_list ap);
extern bool netbuf_sprintf(struct netbuf *nb, const char *fmt, ...);
extern bool netbuf_vsprintf_json(struct netbuf *nb, const char *fmt, va_list ap);
extern bool netbuf_sprintf_json(struct netbuf *nb, const char *fmt, ...);
extern bool netbuf_vsprintf_xml(struct netbuf *nb, const char *fmt, va_list ap);
extern bool netbuf_sprintf_xml(struct netbuf *nb, const char *fmt, ...);

extern bool netbuf_vsscanf(struct netbuf *nb, const char *fmt, va_list ap);
extern bool netbuf_sscanf(struct netbuf *nb, const char *fmt, ...);
extern time64_t netbuf_sscanf_http_date(struct netbuf *nb);
extern bool netbuf_sscanf_next_option(struct netbuf *nb);
