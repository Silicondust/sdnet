/*
 * upnp_descriptor_loader.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("upnp_descriptor_loader");

#define UPNP_DESCRIPTOR_LOADER_TIMEOUT (30 * TICK_RATE)

#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_ROOT 0
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_URLBASE 1
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE 2
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION 3
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_TYPE 4
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_FRIENDLYNAME 5
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_DLNACAP 6
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_UDN 7
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE 8
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_INFORMATION 9
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_TYPE 10
#define UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_CONTROL 11
#define UPNP_DESCRIPTOR_LOADER_STATE_COMPLETE 12
#define UPNP_DESCRIPTOR_LOADER_STATE_ERROR 13

struct upnp_descriptor_loader_xml_element_lookup_t;
struct upnp_descriptor_loader_xml_text_lookup_t;

typedef xml_parser_error_t (*upnp_descriptor_loader_xml_element_handler_t)(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb);
typedef xml_parser_error_t (*upnp_descriptor_loader_xml_text_handler_t)(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_text_lookup_t *lookup, struct netbuf *nb);

struct upnp_descriptor_loader_xml_element_lookup_t {
	char *element_name;
	uint8_t level;
	uint8_t prev_state;
	uint8_t next_state;
	upnp_descriptor_loader_xml_element_handler_t start_handler;
	upnp_descriptor_loader_xml_element_handler_t end_handler;
};

struct upnp_descriptor_loader_xml_text_lookup_t {
	uint8_t level;
	uint8_t state;
	upnp_descriptor_loader_xml_text_handler_t handler;
	char *param_name;
};

struct upnp_descriptor_loader_t {
	struct upnp_descriptor_t *descriptor;
	struct http_parser_t *http_parser;
	struct xml_parser_t *xml_parser;
	struct tcp_connection *conn;
	struct oneshot timer;

	struct url_t descriptor_url;
	struct url_t base_url;

	uint8_t parser_state;
	uint8_t parser_element_level;
	struct slist_t current_device_stack;
	struct upnp_descriptor_device_t *current_device;
	struct upnp_descriptor_device_service_t current_service;
};

void upnp_descriptor_loader_free(struct upnp_descriptor_loader_t *loader)
{
	oneshot_detach(&loader->timer);

	if (loader->conn) {
		tcp_connection_reset(loader->conn);
		tcp_connection_deref(loader->conn);
	}

	if (loader->xml_parser) {
		xml_parser_deref(loader->xml_parser);
	}

	if (loader->http_parser) {
		http_parser_deref(loader->http_parser);
	}

	heap_free(loader);
}

static void upnp_descriptor_loader_result(struct upnp_descriptor_loader_t *loader)
{
	oneshot_detach(&loader->timer);

	if (loader->conn) {
		tcp_connection_close(loader->conn);
		tcp_connection_deref(loader->conn);
		loader->conn = NULL;
	}

	upnp_descriptor_detection_complete(loader->descriptor);
}

static void upnp_descriptor_loader_error(struct upnp_descriptor_loader_t *loader)
{
	DEBUG_INFO("upnp_descriptor_loader_error");
	slist_clear(struct upnp_descriptor_device_t, &loader->current_device_stack, upnp_descriptor_device_free);
	slist_clear(struct upnp_descriptor_device_t, &loader->descriptor->device_list, upnp_descriptor_device_free);
	upnp_descriptor_loader_result(loader);
}

static void upnp_descriptor_loader_timeout(void *arg)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;
	DEBUG_WARN("upnp_descriptor_loader_timeout");
	upnp_descriptor_loader_error(loader);
}

static void upnp_descriptor_loader_conn_close(void *arg, tcp_close_reason_t reason)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;

	tcp_connection_deref(loader->conn);
	loader->conn = NULL;

	if (loader->parser_state != UPNP_DESCRIPTOR_LOADER_STATE_COMPLETE) {
		DEBUG_WARN("upnp_descriptor_loader_conn_close: remote closed connection");
		upnp_descriptor_loader_error(loader);
		return;
	}

	DEBUG_TRACE("upnp_descriptor_loader_conn_close: success");
	upnp_descriptor_loader_result(loader);
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_start_default(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	loader->parser_state = lookup->next_state;
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_end_default(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	loader->parser_state = lookup->prev_state;
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_start_device(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	DEBUG_TRACE("xml: device start");

	if (loader->current_device) {
		slist_attach_head(struct upnp_descriptor_device_t, &loader->current_device_stack, loader->current_device);
		loader->parser_element_level -= 2;
	}

	loader->current_device = upnp_descriptor_device_alloc();
	if (!loader->current_device) {
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	return upnp_descriptor_loader_xml_element_start_default(loader, lookup, nb);
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_end_device(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	DEBUG_TRACE("xml: device end");

	slist_attach_head(struct upnp_descriptor_device_t, &loader->descriptor->device_list, loader->current_device);
	loader->current_device = slist_detach_head(struct upnp_descriptor_device_t, &loader->current_device_stack);

	if (loader->current_device) {
		loader->parser_element_level += 2;
	}

	return upnp_descriptor_loader_xml_element_end_default(loader, lookup, nb);
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_end_root(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	if (loader->current_device) {
		DEBUG_WARN("root end tag in sub device");
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	DEBUG_TRACE("xml: success");
	loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_COMPLETE;
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_start_service(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	memset(&loader->current_service, 0, sizeof(loader->current_service));
	return upnp_descriptor_loader_xml_element_start_default(loader, lookup, nb);
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_end_service(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_element_lookup_t *lookup, struct netbuf *nb)
{
	if ((loader->current_service.service_type_hash == 0) || (loader->current_service.control_url.uri[0] == 0)) {
		DEBUG_WARN("skipping incomplete service");
		return upnp_descriptor_loader_xml_element_end_default(loader, lookup, nb);
	}
	
	if (!upnp_descriptor_device_add_service(loader->current_device, &loader->current_service)) {
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	return upnp_descriptor_loader_xml_element_end_default(loader, lookup, nb);
}

static xml_parser_error_t upnp_descriptor_loader_xml_text_urlbase(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_text_lookup_t *lookup, struct netbuf *nb)
{
	if (!url_parse_nb_with_base(&loader->base_url, &loader->descriptor_url, nb)) {
		DEBUG_WARN("bad urlbase");
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	if (!ip_addr_cmp(&loader->base_url.ip_addr, &loader->descriptor_url.ip_addr)) {
		DEBUG_WARN("baseurl with different ip address");
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	loader->base_url.ipv6_scope_id = loader->descriptor_url.ipv6_scope_id;
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_text_device_default(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_text_lookup_t *lookup, struct netbuf *nb)
{
	if (!upnp_descriptor_device_add_param(loader->current_device, lookup->param_name, nb)) {
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_text_service_type(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_text_lookup_t *lookup, struct netbuf *nb)
{
	loader->current_service.service_type_hash = hash64_create_nb(nb, netbuf_get_remaining(nb));
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_text_service_control(struct upnp_descriptor_loader_t *loader, const struct upnp_descriptor_loader_xml_text_lookup_t *lookup, struct netbuf *nb)
{
	if (!url_parse_nb_with_base(&loader->current_service.control_url, &loader->base_url, nb)) {
		loader->current_service.control_url.uri[0] = 0;
		return XML_PARSER_OK;
	}

	if (!ip_addr_cmp(&loader->current_service.control_url.ip_addr, &loader->descriptor_url.ip_addr)) {
		DEBUG_WARN("ignoring service control with different ip address");
		loader->current_service.control_url.uri[0] = 0;
		return XML_PARSER_OK;
	}

	loader->current_service.control_url.ipv6_scope_id = loader->descriptor_url.ipv6_scope_id;
	return XML_PARSER_OK;
}

static const struct upnp_descriptor_loader_xml_element_lookup_t upnp_descriptor_loader_xml_element_lookup[] =
{
	{"root",         1, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_ROOT,                UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE,              upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_root},
	{"URLBase",      2, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE,              UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_URLBASE,             upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},

	{"device",       2, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE,              UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  upnp_descriptor_loader_xml_element_start_device,  upnp_descriptor_loader_xml_element_end_device},
	{"deviceType",   3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_TYPE,         upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"friendlyName", 3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_FRIENDLYNAME, upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"X_DLNACAP",    3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_DLNACAP,      upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"UDN",          3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_UDN,          upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"serviceList",  3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE,             upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"service",      4, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE,             UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_INFORMATION, upnp_descriptor_loader_xml_element_start_service, upnp_descriptor_loader_xml_element_end_service},
	{"serviceType",  5, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_INFORMATION, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_TYPE,        upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"controlURL",   5, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_INFORMATION, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_CONTROL,     upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},

	{"deviceList",   3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE,              upnp_descriptor_loader_xml_element_start_default, upnp_descriptor_loader_xml_element_end_default},
	{"device",       4, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE,              UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_INFORMATION,  upnp_descriptor_loader_xml_element_start_device,  upnp_descriptor_loader_xml_element_end_device},

	{NULL, 0, 0, 0, NULL, NULL}
};

static const struct upnp_descriptor_loader_xml_text_lookup_t upnp_descriptor_loader_xml_text_lookup[] =
{
	{2, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_URLBASE,             upnp_descriptor_loader_xml_text_urlbase,         NULL},

	{3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_TYPE,         upnp_descriptor_loader_xml_text_device_default,  "deviceType"},
	{3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_FRIENDLYNAME, upnp_descriptor_loader_xml_text_device_default,  "friendlyName"},
	{3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_DLNACAP,      upnp_descriptor_loader_xml_text_device_default,  "X_DLNACAP"},
	{3, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_DEVICE_UDN,          upnp_descriptor_loader_xml_text_device_default,  "UDN"},
	{5, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_TYPE,        upnp_descriptor_loader_xml_text_service_type,    NULL},
	{5, UPNP_DESCRIPTOR_LOADER_STATE_WAITING_FOR_SERVICE_CONTROL,     upnp_descriptor_loader_xml_text_service_control, NULL},

	{0, 0, NULL, NULL}
};

static xml_parser_error_t upnp_descriptor_loader_xml_element_name_start(struct upnp_descriptor_loader_t *loader, struct netbuf *nb)
{
	const struct upnp_descriptor_loader_xml_element_lookup_t *lookup = upnp_descriptor_loader_xml_element_lookup;
	while (lookup->start_handler) {
		if (lookup->level != loader->parser_element_level) {
			lookup++;
			continue;
		}

		if (lookup->prev_state != loader->parser_state) {
			lookup++;
			continue;
		}

		if (netbuf_fwd_strcmp(nb, lookup->element_name) != 0) {
			lookup++;
			continue;
		}

		return lookup->start_handler(loader, lookup, nb);
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_name_end(struct upnp_descriptor_loader_t *loader, struct netbuf *nb)
{
	const struct upnp_descriptor_loader_xml_element_lookup_t *lookup = upnp_descriptor_loader_xml_element_lookup;
	while (lookup->end_handler) {
		if (lookup->level != loader->parser_element_level) {
			lookup++;
			continue;
		}

		if (lookup->next_state != loader->parser_state) {
			lookup++;
			continue;
		}

		if (netbuf_fwd_strcmp(nb, lookup->element_name) != 0) {
			lookup++;
			continue;
		}

		return lookup->end_handler(loader, lookup, nb);
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_self_close(struct upnp_descriptor_loader_t *loader)
{
	DEBUG_INFO("element self close (level %u)", loader->parser_element_level);
	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_element_text(struct upnp_descriptor_loader_t *loader, struct netbuf *nb)
{
	const struct upnp_descriptor_loader_xml_text_lookup_t *lookup = upnp_descriptor_loader_xml_text_lookup;
	while (lookup->handler) {
		if (lookup->level != loader->parser_element_level) {
			lookup++;
			continue;
		}

		if (lookup->state != loader->parser_state) {
			lookup++;
			continue;
		}

		return lookup->handler(loader, lookup, nb);
	}

	return XML_PARSER_OK;
}

static xml_parser_error_t upnp_descriptor_loader_xml_callback(void *arg, xml_parser_event_t event, struct netbuf *nb)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;
	xml_parser_error_t ret;

	switch (event) {
	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		loader->parser_element_level++;
		return upnp_descriptor_loader_xml_element_name_start(loader, nb);

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
		ret = upnp_descriptor_loader_xml_element_name_end(loader, nb);
		if (ret != XML_PARSER_OK) {
			return ret;
		}
		loader->parser_element_level--;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		ret = upnp_descriptor_loader_xml_element_self_close(loader);
		if (ret != XML_PARSER_OK) {
			return ret;
		}
		loader->parser_element_level--;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_TEXT:
		return upnp_descriptor_loader_xml_element_text(loader, nb);

	case XML_PARSER_EVENT_PARSE_ERROR:
		DEBUG_WARN("xml reported error");
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;

	case XML_PARSER_EVENT_INTERNAL_ERROR:
		upnp_error_out_of_memory(__this_file, __LINE__);
		loader->parser_state = UPNP_DESCRIPTOR_LOADER_STATE_ERROR;
		return XML_PARSER_ESTOP;

	default:
		DEBUG_TRACE("event %u", event);
		return XML_PARSER_OK;
	}
}

static http_parser_error_t upnp_descriptor_loader_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		if (netbuf_fwd_strncmp(nb, "200", 3) == 0) {
			DEBUG_TRACE("upnp_descriptor_loader_http_event: 200");
			return HTTP_PARSER_OK;
		}
		DEBUG_WARN("upnp_descriptor_loader_http_event: non-ok status code");
		upnp_descriptor_loader_error(loader);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_DATA:
		xml_parser_recv_netbuf(loader->xml_parser, nb);
		if (loader->parser_state == UPNP_DESCRIPTOR_LOADER_STATE_ERROR) {
			upnp_descriptor_loader_error(loader);
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		if (loader->parser_state != UPNP_DESCRIPTOR_LOADER_STATE_COMPLETE) {
			upnp_descriptor_loader_error(loader);
			return HTTP_PARSER_ESTOP;
		}
		DEBUG_INFO("upnp_descriptor_loader_http_event: success");
		upnp_descriptor_loader_result(loader);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("upnp_descriptor_loader_http_event: error");
		upnp_descriptor_loader_error(loader);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void upnp_descriptor_loader_conn_recv(void *arg, struct netbuf *nb)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;
	DEBUG_TRACE("upnp_descriptor_loader_conn_recv");
	http_parser_recv_netbuf(loader->http_parser, nb);
}

static void upnp_descriptor_loader_conn_established(void *arg)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;
	DEBUG_TRACE("upnp_descriptor_loader_conn_established");

	struct netbuf *header_nb = netbuf_alloc();
	if (!header_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		upnp_descriptor_loader_error(loader);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(header_nb, "GET %s HTTP/1.1\r\n", loader->descriptor_url.uri);
	success &= netbuf_sprintf(header_nb, "Host: %V:%u\r\n", &loader->descriptor_url.ip_addr, loader->descriptor_url.ip_port);
	success &= netbuf_sprintf(header_nb, "Connection: close\r\n");
	success &= netbuf_sprintf(header_nb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(header_nb);
		upnp_descriptor_loader_error(loader);
		return;
	}

	netbuf_set_pos_to_start(header_nb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(loader->conn, header_nb);
	netbuf_free(header_nb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		upnp_descriptor_loader_error(loader);
		return;
	}
}

static void upnp_descriptor_loader_start(void *arg)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)arg;
	oneshot_attach(&loader->timer, UPNP_DESCRIPTOR_LOADER_TIMEOUT, upnp_descriptor_loader_timeout, loader);

	loader->conn = tcp_connection_alloc();
	if (!loader->conn) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		upnp_descriptor_loader_error(loader);
		return;
	}

	if (tcp_connection_connect(loader->conn, &loader->descriptor_url.ip_addr, loader->descriptor_url.ip_port, loader->descriptor_url.ipv6_scope_id, upnp_descriptor_loader_conn_established, upnp_descriptor_loader_conn_recv, upnp_descriptor_loader_conn_close, loader) != TCP_OK) {
		DEBUG_WARN("connect failed");
		tcp_connection_deref(loader->conn);
		loader->conn = NULL;
		upnp_descriptor_loader_error(loader);
		return;
	}
}

struct upnp_descriptor_loader_t *upnp_descriptor_loader_alloc(struct upnp_descriptor_t *descriptor, struct url_t *descriptor_url)
{
	struct upnp_descriptor_loader_t *loader = (struct upnp_descriptor_loader_t *)heap_alloc_and_zero(sizeof(struct upnp_descriptor_loader_t), PKG_OS, MEM_TYPE_OS_UPNP_DESCRIPTOR_LOADER);
	if (!loader) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	loader->descriptor = descriptor;
	loader->descriptor_url = *descriptor_url;
	loader->base_url = *descriptor_url;

	loader->http_parser = http_parser_alloc(upnp_descriptor_loader_http_event, loader);
	loader->xml_parser = xml_parser_alloc(upnp_descriptor_loader_xml_callback, loader);
	if (!loader->http_parser || !loader->xml_parser) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		upnp_descriptor_loader_free(loader);
		return NULL;
	}

	oneshot_init(&loader->timer);
	oneshot_attach(&loader->timer, 0, upnp_descriptor_loader_start, loader);

	return loader;
}
