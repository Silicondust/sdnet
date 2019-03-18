/*
 * url.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	URL_PROTOCOL_UNKNOWN = 0,
	URL_PROTOCOL_HTTP,
	URL_PROTOCOL_HTTPS,
	URL_PROTOCOL_RTSP,
} url_protocol_t;

#define URL_FLAGS_PORT_SPECIFIED (1 << 0)

struct url_t {
	url_protocol_t protocol;
	ipv4_addr_t ip_addr;
	uint16_t ip_port;
	uint16_t flags;
	char dns_name[64];
	char uri[512];
};

extern bool url_to_str(struct url_t *url, char *buffer, char *end);

extern bool url_parse_str(struct url_t *output, const char *str);
extern bool url_parse_str_with_base(struct url_t *output, struct url_t *base, const char *str);

extern bool url_parse_nb(struct url_t *output, struct netbuf *nb);
extern bool url_parse_nb_with_base(struct url_t *output, struct url_t *base, struct netbuf *nb);

extern bool url_append_parameter(struct url_t *url, const char *name, const char *value);

extern void url_wipe(struct url_t *output);
extern bool url_compare(struct url_t *a, struct url_t *b);
