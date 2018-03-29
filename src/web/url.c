/*
 * ./src/web/url.c
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

THIS_FILE("url");

static void url_wipe(struct url_t *output)
{
	output->protocol = URL_PROTOCOL_UNKNOWN;
	output->ip_addr = 0;
	output->ip_port = 0;
	output->flags = 0;
	output->dns_name[0] = 0;
	output->uri[0] = 0;
}

static void url_parse_protocol_decode(struct url_t *output, char *protocol)
{
	if (strcasecmp(protocol, "http") == 0) {
		output->protocol = URL_PROTOCOL_HTTP;
		output->ip_port = 80;
		return;
	}

	if (strcasecmp(protocol, "https") == 0) {
		output->protocol = URL_PROTOCOL_HTTPS;
		output->ip_port = 443;
		return;
	}

	if (strcasecmp(protocol, "rtsp") == 0) {
		output->protocol = URL_PROTOCOL_RTSP;
		output->ip_port = 554;
		return;
	}

	DEBUG_WARN("unknown protocol %s", protocol);
	output->protocol = URL_PROTOCOL_UNKNOWN;
	output->ip_port = 0;
}

static bool url_parse_ip_addr(struct url_t *output, struct url_t *base)
{
	if (output->dns_name[0] == 0) {
		DEBUG_WARN("no ip/name found");
		return false;
	}

	if (sscanf_custom(output->dns_name, "%v", &output->ip_addr)) {
		if (output->ip_addr == 0) {
			DEBUG_WARN("zero ip addr");
			return false;
		}
		return true;
	}

	if (strcmp(output->dns_name, base->dns_name) == 0) {
		output->ip_addr = base->ip_addr;
		return true;
	}

	output->ip_addr = 0;
	return true;
}

static bool url_parse_str_protocol(struct url_t *output, const char **pstr)
{
	const char *str = *pstr;
	const char *slash_pos = strchr(str, '/');
	if (!slash_pos || (slash_pos == str)) {
		return false; /* no protocol specified */
	}

	if (strncmp(slash_pos - 1, "://", 3) != 0) {
		return false; /* no protocol specified */
	}

	char protocol[12];
	if (!sscanf_custom_with_advance(pstr, "%s://", protocol, sizeof(protocol))) {
		protocol[0] = 0; /* malformed - treat as unknown protocol specified */
	}

	url_parse_protocol_decode(output, protocol);
	return true;
}

static bool url_parse_str_port(struct url_t *output, const char **pstr)
{
	uint32_t ip_port;
	if (!sscanf_custom_with_advance(pstr, "%u", &ip_port)) {
		DEBUG_WARN("no port found");
		return false;
	}

	output->flags |= URL_FLAGS_PORT_SPECIFIED;
	output->ip_port = (uint16_t)ip_port;
	if (output->ip_port == 0) {
		DEBUG_WARN("zero port");
		return false;
	}

	const char *str = *pstr;
	if (*str == 0) {
		return true;
	}

	if (*str != '/') {
		DEBUG_WARN("garbage after port number");
		return false;
	}

	return true;
}

static bool url_parse_str_protocol_name_port(struct url_t *output, struct url_t *base, const char **pstr)
{
	/*
	 * Protocol.
	 */
	if (!url_parse_str_protocol(output, pstr)) {
		output->protocol = base->protocol;
		output->ip_addr = base->ip_addr;
		output->ip_port = base->ip_port;
		output->flags = base->flags;
		strcpy(output->dns_name, base->dns_name);
		return true;
	}

	if (output->protocol == URL_PROTOCOL_UNKNOWN) {
		return false;
	}
	
	/*
	 * DNS name.
	 */
	const char *str = *pstr;
	char *dns_name_ptr = output->dns_name;
	char *dns_name_end = output->dns_name + sizeof(output->dns_name) - 1;
	bool port_present = false;

	while (1) {
		char c = *str++;
		if (c == 0) {
			break;
		}

		if (c == '/') {
			str--;
			break;
		}
		if (c == ':') {
			port_present = true;
			break;
		}

		if (dns_name_ptr >= dns_name_end) {
			DEBUG_WARN("ip/name too long");
			return false;
		}

		*dns_name_ptr++ = c;
	}

	*dns_name_ptr = 0;
	*pstr = str;

	if (!url_parse_ip_addr(output, base)) {
		return false;
	}

	/*
	 * Port number.
	 */
	if (!port_present) {
		return true;
	}

	if (!url_parse_str_port(output, pstr)) {
		return false;
	}

	return true;
}

static bool url_parse_str_uri(struct url_t *output, struct url_t *base, const char *str)
{
	if (*str == 0) {
		strcpy(output->uri, "/");
		return true;
	}

	if (*str == '/') {
		sprintf_custom(output->uri, output->uri + sizeof(output->uri), "%s", str);
		return true;
	}

	char *base_uri_end = strrchr(base->uri, '/');
	if (!base_uri_end) {
		DEBUG_WARN("relative uri without base: %s", str);
		return false;
	}

	base_uri_end++;
	size_t base_length = base_uri_end - base->uri;
	memcpy(output->uri, base->uri, base_length);

	sprintf_custom(output->uri + base_length, output->uri + sizeof(output->uri), "%s", str);
	return true;
}

bool url_parse_str_with_base(struct url_t *output, struct url_t *base, const char *str)
{
	if (!url_parse_str_protocol_name_port(output, base, &str)) {
		url_wipe(output);
		return false;
	}

	if (!url_parse_str_uri(output, base, str))	{
		url_wipe(output);
		return false;
	}

	return true;
}

bool url_parse_str(struct url_t *output, const char *str)
{
	struct url_t base;
	url_wipe(&base);
	return url_parse_str_with_base(output, &base, str);
}

static bool url_parse_nb_protocol(struct url_t *output, struct netbuf *nb)
{
	addr_t start_pos = netbuf_get_pos(nb);
	addr_t slash_pos = netbuf_fwd_strchr(nb, '/');
	if (!slash_pos || (slash_pos == start_pos)) {
		return false; /* no protocol specified */
	}

	netbuf_set_pos(nb, slash_pos - 1);
	if (netbuf_fwd_strncmp(nb, "://", 3) != 0) {
		netbuf_set_pos(nb, start_pos);
		return false; /* no protocol specified */
	}

	char protocol[12];
	netbuf_set_pos(nb, start_pos);
	if (!netbuf_sscanf(nb, "%s://", protocol, sizeof(protocol))) {
		protocol[0] = 0; /* malformed - treat as unknown protocol specified */
	}

	url_parse_protocol_decode(output, protocol);
	return true;
}

static bool url_parse_nb_port(struct url_t *output, struct netbuf *nb)
{
	uint32_t ip_port;
	if (!netbuf_sscanf(nb, "%u", &ip_port)) {
		DEBUG_WARN("no port found");
		return false;
	}

	output->flags |= URL_FLAGS_PORT_SPECIFIED;
	output->ip_port = (uint16_t)ip_port;
	if (output->ip_port == 0) {
		DEBUG_WARN("zero port");
		return false;
	}

	if (!netbuf_fwd_check_space(nb, 1)) {
		return true;
	}

	if (netbuf_fwd_read_u8(nb) != '/') {
		DEBUG_WARN("garbage after port number");
		return false;
	}

	netbuf_retreat_pos(nb, 1);
	return true;
}

static bool url_parse_nb_protocol_name_port(struct url_t *output, struct url_t *base, struct netbuf *nb)
{
	/*
	 * Protocol.
	 */
	if (!url_parse_nb_protocol(output, nb)) {
		output->protocol = base->protocol;
		output->ip_addr = base->ip_addr;
		output->ip_port = base->ip_port;
		output->flags = base->flags;
		strcpy(output->dns_name, base->dns_name);
		return true;
	}

	if (output->protocol == URL_PROTOCOL_UNKNOWN) {
		return false;
	}
	
	/*
	 * DNS name.
	 */
	char *dns_name_ptr = output->dns_name;
	char *dns_name_end = output->dns_name + sizeof(output->dns_name) - 1;
	bool port_present = false;

	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			break;
		}

		uint8_t c = netbuf_fwd_read_u8(nb);
		if (c == '/') {
			netbuf_retreat_pos(nb, 1);
			break;
		}
		if (c == ':') {
			port_present = true;
			break;
		}

		if (dns_name_ptr >= dns_name_end) {
			DEBUG_WARN("ip/name too long");
			return false;
		}

		*dns_name_ptr++ = c;
	}

	*dns_name_ptr = 0;

	if (!url_parse_ip_addr(output, base)) {
		return false;
	}

	/*
	 * Port number.
	 */
	if (!port_present) {
		return true;
	}

	if (!url_parse_nb_port(output, nb)) {
		return false;
	}

	return true;
}

static void url_parse_nb_uri_fast_copy(char *ptr, char *end, struct netbuf *nb)
{
	size_t length = netbuf_get_remaining(nb);
	size_t space = end - ptr - 1;
	if (length > space) {
		length = space;
	}

	if (length > 0) {
		netbuf_fwd_read(nb, ptr, length);
	}

	ptr[length] = 0;
}

static bool url_parse_nb_uri(struct url_t *output, struct url_t *base, struct netbuf *nb)
{
	if (!netbuf_fwd_check_space(nb, 1)) {
		strcpy(output->uri, "/");
		return true;
	}

	uint8_t c = netbuf_fwd_read_u8(nb);
	netbuf_retreat_pos(nb, 1);

	if (c == '/') {
		url_parse_nb_uri_fast_copy(output->uri, output->uri + sizeof(output->uri), nb);
		return true;
	}

	char *base_uri_end = strrchr(base->uri, '/');
	if (!base_uri_end) {
		DEBUG_WARN("relative uri without base");
		DEBUG_PRINT_NETBUF_TEXT(nb, 0);
		return false;
	}

	base_uri_end++;
	size_t base_length = base_uri_end - base->uri;
	memcpy(output->uri, base->uri, base_length);

	url_parse_nb_uri_fast_copy(output->uri + base_length, output->uri + sizeof(output->uri), nb);
	return true;
}

bool url_parse_nb_with_base(struct url_t *output, struct url_t *base, struct netbuf *nb)
{
	if (!url_parse_nb_protocol_name_port(output, base, nb)) {
		url_wipe(output);
		return false;
	}

	if (!url_parse_nb_uri(output, base, nb))	{
		url_wipe(output);
		return false;
	}

	return true;
}

bool url_parse_nb(struct url_t *output, struct netbuf *nb)
{
	struct url_t base;
	url_wipe(&base);
	return url_parse_nb_with_base(output, &base, nb);
}

bool url_append_parameter(struct url_t *url, const char *name, const char *value)
{
	char *ptr = strchr(url->uri, 0);
	char *end = url->uri + sizeof(url->uri);

	if (strchr(url->uri, '?')) {
		return sprintf_custom_url(ptr, end, "&%s=%s", name, value);
	}

	return sprintf_custom_url(ptr, end, "?%s=%s", name, value);
}
