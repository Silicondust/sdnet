/*
 * ./src/webserver/webserver_content_type.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("webserver_content_type");

struct webserver_content_type_t {
	const char *ext;
	const char *content_type;
};

static struct webserver_content_type_t webserver_content_type_table[] =
{
	{"html",  "text/html; charset=\"utf-8\""},
	{"css",   "text/css; charset=\"utf-8\""},
	{"js",    "text/javascript; charset=\"utf-8\""},
	{"json",  "application/json; charset=\"utf-8\""},
	{"xhtml", "application/ce-html+xml; charset=\"utf-8\""},
	{"xml",   "text/xml; charset=\"utf-8\""},
	{"xsl",   "text/xml; charset=\"utf-8\""},
	{"ico",   "image/vnd.microsoft.icon"},
	{"png",   "image/png"},
	{"jpg",   "image/jpeg"},
	{NULL,    "text/plain"}
};

const char *webserver_content_type_detect_from_ext(const char *uri)
{
	const char *ext = strrchr(uri, '.');
	if (!ext) {
		ext = uri;
	} else {
		ext++;
	}

	struct webserver_content_type_t *entry = webserver_content_type_table;
	while (1) {
		if (!entry->ext) {
			return entry->content_type;
		}
		if (strcmp(ext, entry->ext) == 0) {
			return entry->content_type;
		}
		entry++;
	}
}

const char *webserver_content_type_detect_from_ext_netbuf(struct netbuf *uri_nb)
{
	size_t len = netbuf_get_extent(uri_nb);
	if (len > 7) {
		len = 7;
	}

	char uri_tail[8];
	netbuf_set_pos(uri_nb, netbuf_get_end(uri_nb) - len);
	netbuf_fwd_read(uri_nb, uri_tail, len);
	uri_tail[len] = 0;

	return webserver_content_type_detect_from_ext(uri_tail);
}
