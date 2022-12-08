/*
 * url.c
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

bool url_to_str(struct url_t *url, char *buffer, char *end)
{
	bool success = true;
	char *ptr = buffer;

	switch (url->protocol) {
	case URL_PROTOCOL_HTTP:
		success &= sprintf_custom(ptr, end, "http://");
		ptr = strchr(ptr, 0);
		break;

	case URL_PROTOCOL_HTTPS:
		success &= sprintf_custom(ptr, end, "https://");
		ptr = strchr(ptr, 0);
		break;

	case URL_PROTOCOL_RTSP:
		success &= sprintf_custom(ptr, end, "rtsp://");
		ptr = strchr(ptr, 0);
		break;

	case URL_PROTOCOL_RTP:
		success &= sprintf_custom(ptr, end, "rtp://");
		ptr = strchr(ptr, 0);
		break;

	default:
		break;
	}

	if (url->dns_name[0]) {
		success &= sprintf_custom(ptr, end, "%s", url->dns_name);
		ptr = strchr(ptr, 0);
	} else if (ip_addr_is_non_zero(&url->ip_addr)) {
		success &= sprintf_custom(ptr, end, "%V", &url->ip_addr);
		ptr = strchr(ptr, 0);
	}

	if (url->flags & URL_FLAGS_PORT_SPECIFIED) {
		success &= sprintf_custom(ptr, end, ":%u", url->ip_port);
		ptr = strchr(ptr, 0);
	}

	success &= sprintf_custom(ptr, end, "%s", url->uri);
	return success;
}

void url_wipe(struct url_t *output)
{
	output->protocol = URL_PROTOCOL_UNKNOWN;
	output->ipv6_scope_id = 0;
	ip_addr_set_zero(&output->ip_addr);
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

	if (strcasecmp(protocol, "rtp") == 0) {
		output->protocol = URL_PROTOCOL_RTP;
		output->ip_port = 5004;
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

	if (sscanf_custom(output->dns_name, "%V", &output->ip_addr)) {
		if (ip_addr_is_zero(&output->ip_addr)) {
			DEBUG_WARN("zero ip addr");
			return false;
		}
		return true;
	}

	if (strcmp(output->dns_name, base->dns_name) == 0) {
		output->ip_addr = base->ip_addr;
		return true;
	}

	ip_addr_set_zero(&output->ip_addr);
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
		output->ipv6_scope_id = base->ipv6_scope_id;
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
	 * ipv6 scope id
	 */
	output->ipv6_scope_id = 0;

	/*
	 * DNS name.
	 */
	const char *str = *pstr;
	char *dns_name_ptr = output->dns_name;
	char *dns_name_end = output->dns_name + sizeof(output->dns_name) - 1;
	bool port_present = false;

	char c = *str;
	if (c == '[') {
		*dns_name_ptr++ = c;
		str++;

		while (1) {
			c = *str++;
			if (c == 0) {
				DEBUG_WARN("missing ']'");
				return false;
			}

			if (dns_name_ptr >= dns_name_end) {
				DEBUG_WARN("ip/name too long");
				return false;
			}

			*dns_name_ptr++ = c;

			if (c == ']') {
				c = *str++;
				if (c == 0) {
					str--;
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

				DEBUG_WARN("invalid char after ']'");
				return false;
			}
		}
	} else {
		while (1) {
			c = *str++;
			if (c == 0) {
				str--;
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

	strcpy(output->uri, base->uri);

	char *output_append_ptr = strchr(output->uri, '?');
	if (output_append_ptr) {
		*output_append_ptr = 0;
	}

	output_append_ptr = strrchr(output->uri, '/');
	if (!output_append_ptr) {
		DEBUG_WARN("relative uri without base: %s", str);
		return false;
	}

	const char *str_ptr = str;
	while (strncmp(str_ptr, "../", 3) == 0) {
		str_ptr += 3;
		*output_append_ptr = 0;

		output_append_ptr = strrchr(output->uri, '/');
		if (!output_append_ptr) {
			DEBUG_WARN("relative uri below base: %s", str);
			return false;
		}
	}

	sprintf_custom(output_append_ptr + 1, output->uri + sizeof(output->uri), "%s", str_ptr);
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
		output->ipv6_scope_id = base->ipv6_scope_id;
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
	 * ipv6 scope id
	 */
	output->ipv6_scope_id = 0;

	/*
	 * DNS name.
	 */
	char *dns_name_ptr = output->dns_name;
	char *dns_name_end = output->dns_name + sizeof(output->dns_name) - 1;
	bool port_present = false;

	if (!netbuf_fwd_check_space(nb, 1)) {
		return false;
	}

	char c = (char)netbuf_fwd_read_u8(nb);
	if (c == '[') {
		*dns_name_ptr++ = c;

		while (1) {
			if (!netbuf_fwd_check_space(nb, 1)) {
				DEBUG_WARN("missing ']'");
				return false;
			}

			c = (char)netbuf_fwd_read_u8(nb);

			if (dns_name_ptr >= dns_name_end) {
				DEBUG_WARN("ip/name too long");
				return false;
			}

			*dns_name_ptr++ = c;

			if (c == ']') {
				if (!netbuf_fwd_check_space(nb, 1)) {
					break;
				}

				c = (char)netbuf_fwd_read_u8(nb);

				if (c == '/') {
					netbuf_retreat_pos(nb, 1);
					break;
				}

				if (c == ':') {
					port_present = true;
					break;
				}

				DEBUG_WARN("invalid char after ']'");
				return false;
			}
		}
	} else {
		netbuf_retreat_pos(nb, 1);

		while (1) {
			if (!netbuf_fwd_check_space(nb, 1)) {
				break;
			}

			c = (char)netbuf_fwd_read_u8(nb);

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

	strcpy(output->uri, base->uri);

	char *output_append_ptr = strchr(output->uri, '?');
	if (output_append_ptr) {
		*output_append_ptr = 0;
	}

	output_append_ptr = strrchr(output->uri, '/');
	if (!output_append_ptr) {
		DEBUG_WARN("relative uri without base");
		DEBUG_PRINT_NETBUF_TEXT(nb, 0);
		return false;
	}

	while (netbuf_fwd_strncmp(nb, "../", 3) == 0) {
		netbuf_advance_pos(nb, 3);
		*output_append_ptr = 0;

		output_append_ptr = strrchr(output->uri, '/');
		if (!output_append_ptr) {
			DEBUG_WARN("relative uri below base");
			DEBUG_PRINT_NETBUF_TEXT(nb, 0);
			return false;
		}
	}

	url_parse_nb_uri_fast_copy(output_append_ptr + 1, output->uri + sizeof(output->uri), nb);
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

bool url_compare(struct url_t *a, struct url_t *b)
{
	if (strcmp(a->uri, b->uri) != 0) {
		return false;
	}
	if (strcmp(a->dns_name, b->dns_name) != 0) {
		return false;
	}

	if (a->protocol != b->protocol) {
		return false;
	}
	if (a->ipv6_scope_id != b->ipv6_scope_id) {
		return false;
	}
	if (!ip_addr_cmp(&a->ip_addr, &b->ip_addr)) {
		return false;
	}
	if (a->ip_port != b->ip_port) {
		return false;
	}
	if (a->flags != b->flags) {
		return false;
	}

	return true;
}
