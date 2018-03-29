/*
 * ./src/text/netbuf_sprintf.c
 *
 * Copyright © 2011-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("netbuf_printf");

static bool netbuf_vsprintf_write(void *arg, const char *str, size_t len)
{
	struct netbuf *nb = (struct netbuf *)arg;

	if (!netbuf_fwd_make_space(nb, len)) {
		return false;
	}

	netbuf_fwd_write(nb, (void *)str, len);
	return true;
}

bool netbuf_vsprintf(struct netbuf *nb, const char *fmt, va_list ap)
{
	return doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);
}

bool netbuf_sprintf(struct netbuf *nb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool ret = doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_NORMAL, fmt, ap);
	va_end(ap);
	return ret;
}

bool netbuf_vsprintf_json(struct netbuf *nb, const char *fmt, va_list ap)
{
	return doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_JSON, fmt, ap);
}

bool netbuf_sprintf_json(struct netbuf *nb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool ret = doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_JSON, fmt, ap);
	va_end(ap);
	return ret;
}

bool netbuf_vsprintf_xml(struct netbuf *nb, const char *fmt, va_list ap)
{
	return doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_XML, fmt, ap);
}

bool netbuf_sprintf_xml(struct netbuf *nb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool ret = doprint_custom(netbuf_vsprintf_write, nb, DOPRINT_CUSTOM_MODE_XML, fmt, ap);
	va_end(ap);
	return ret;
}
