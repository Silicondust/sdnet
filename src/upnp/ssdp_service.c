/*
 * ssdp_service.c
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

THIS_FILE("ssdp_service");

#define SSDP_NOTIFY_TIME (600 * TICK_RATE)
#define SSDP_NOTIFY_JITTER (SSDP_NOTIFY_TIME / 10)
#define SSDP_NOTIFY_RATE_DELAY 21
#define SSDP_START_DELAY (1 * TICK_RATE)

const char ssdp_service_root_device_urn[] = "upnp:rootdevice";

static struct ssdp_service_manager_t ssdp_service_manager;

static http_parser_error_t ssdp_service_manager_http_tag_man(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t ssdp_service_manager_http_tag_mx(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t ssdp_service_manager_http_tag_st(void *arg, const char *header, struct netbuf *nb);

const struct http_parser_tag_lookup_t ssdp_service_manager_msearch_http_tag_list[] = {
	{"MAN", ssdp_service_manager_http_tag_man},
	{"MX", ssdp_service_manager_http_tag_mx},
	{"ST", ssdp_service_manager_http_tag_st},
	{NULL, NULL}
};

static void ssdp_service_send_notify(struct ssdp_service_t *service, bool byebye)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "NOTIFY * HTTP/1.1\r\n");
	success &= netbuf_sprintf(txnb, "Host: 239.255.255.250:%u\r\n", SSDP_SERVICE_PORT);

	if (service->urn) {
		success &= netbuf_sprintf(txnb, "NT: %s\r\n", service->urn);
	} else {
		success &= netbuf_sprintf(txnb, "NT: uuid:%s\r\n", service->uuid);
	}

	if (byebye) {
		success &= netbuf_sprintf(txnb, "NTS: ssdp:byebye\r\n");
	} else {
		success &= netbuf_sprintf(txnb, "NTS: ssdp:alive\r\n");
		success &= netbuf_sprintf(txnb, "Server: %s\r\n", SSDP_SERVER_NAME);
		success &= netbuf_sprintf(txnb, "Location: http://%v:%u%s\r\n", ssdp_manager.local_ip, ssdp_manager.webserver_port, service->device_xml_uri);
		success &= http_header_write_cache_control(txnb, 1800);
	}

	if (service->urn) {
		success &= netbuf_sprintf(txnb, "USN: uuid:%s::%s\r\n", service->uuid, service->urn);
	} else {
		success &= netbuf_sprintf(txnb, "USN: uuid:%s\r\n", service->uuid);
	}

	success &= netbuf_sprintf(txnb, "\r\n");

	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	udp_socket_send_netbuf(ssdp_manager.sock, SSDP_MULTICAST_IP, SSDP_SERVICE_PORT, 4, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void ssdp_service_send_discover_response(struct ssdp_service_t *service, ipv4_addr_t remote_ip, uint16_t remote_port)
{
	DEBUG_TRACE("sending ssdp discover response for %s", (service->urn) ? service->urn : service->uuid);

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 200 OK\r\n");
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", SSDP_SERVER_NAME);

	if (service->urn) {
		success &= netbuf_sprintf(txnb, "ST: %s\r\n", service->urn);
	} else {
		success &= netbuf_sprintf(txnb, "ST: uuid:%s\r\n", service->uuid);
	}

	ipv4_addr_t local_ip = ip_get_local_ip_for_remote_ip(remote_ip);
	success &= netbuf_sprintf(txnb, "Location: http://%v:%u%s\r\n", local_ip, ssdp_manager.webserver_port, service->device_xml_uri);
	success &= http_header_write_cache_control(txnb, 1800);

	if (service->urn) {
		success &= netbuf_sprintf(txnb, "USN: uuid:%s::%s\r\n", service->uuid, service->urn);
	} else {
		success &= netbuf_sprintf(txnb, "USN: uuid:%s\r\n", service->uuid);
	}

	success &= netbuf_sprintf(txnb, "Ext:\r\n");
	success &= netbuf_sprintf(txnb, "Content-Length: 0\r\n");
	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");

	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	udp_socket_send_netbuf(ssdp_manager.sock, remote_ip, remote_port, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void ssdp_service_manager_populate_discover_list_all(void)
{
	ssdp_service_manager.discover_list = NULL;

	struct ssdp_service_t *service = slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list);
	while (service) {
		service->discover_next = ssdp_service_manager.discover_list;
		ssdp_service_manager.discover_list = service;
		service = slist_get_next(struct ssdp_service_t, service);
	}
}

static void ssdp_service_manager_populate_discover_list_by_uuid_netbuf(struct netbuf *nb)
{
	ssdp_service_manager.discover_list = NULL;

	struct ssdp_service_t *service = slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list);
	while (service) {
		if (service->urn) {
			service = slist_get_next(struct ssdp_service_t, service);
			continue;
		}

		/* Case insensitive compare required for UUIDs. */
		if (netbuf_fwd_strcasecmp(nb, service->uuid) == 0) {
			service->discover_next = ssdp_service_manager.discover_list;
			ssdp_service_manager.discover_list = service;
		}

		service = slist_get_next(struct ssdp_service_t, service);
	}
}

static void ssdp_service_manager_populate_discover_list_by_urn_netbuf(struct netbuf *nb)
{
	ssdp_service_manager.discover_list = NULL;

	struct ssdp_service_t *service = slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list);
	while (service) {
		if (!service->urn) {
			service = slist_get_next(struct ssdp_service_t, service);
			continue;
		}

		if (netbuf_fwd_strcmp(nb, service->urn) == 0) {
			service->discover_next = ssdp_service_manager.discover_list;
			ssdp_service_manager.discover_list = service;
		}

		service = slist_get_next(struct ssdp_service_t, service);
	}
}

static void ssdp_service_manager_populate_discover_list_by_st(struct netbuf *nb)
{
	if (netbuf_fwd_strcmp(nb, "ssdp:all") == 0) {
		ssdp_service_manager_populate_discover_list_all();
		return;
	}

	if (netbuf_fwd_strncmp(nb, "uuid:", 5) == 0) {
		netbuf_advance_pos(nb, 5);
		ssdp_service_manager_populate_discover_list_by_uuid_netbuf(nb);
		return;
	}

	ssdp_service_manager_populate_discover_list_by_urn_netbuf(nb);
}

static void ssdp_service_manager_notify_timer_callback(void *arg)
{
	struct ssdp_service_t *service = ssdp_service_manager.next_notify;
	if (!service) {
		service = slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list);
	}

	ssdp_service_send_notify(service, ssdp_service_manager.initial_byebye);

	ssdp_service_manager.next_notify = slist_get_next(struct ssdp_service_t, service);
	if (!ssdp_service_manager.next_notify) {
		if (ssdp_service_manager.resend_notify) {
			ssdp_service_manager.resend_notify = false;
			oneshot_attach(&ssdp_service_manager.notify_timer, SSDP_NOTIFY_RATE_DELAY, ssdp_service_manager_notify_timer_callback, NULL);
			return;
		}

		ssdp_service_manager.resend_notify = true;

		if (ssdp_service_manager.initial_byebye) {
			ssdp_service_manager.initial_byebye = false;
			oneshot_attach(&ssdp_service_manager.notify_timer, SSDP_NOTIFY_RATE_DELAY, ssdp_service_manager_notify_timer_callback, NULL);
			return;
		}

		oneshot_attach_with_jitter(&ssdp_service_manager.notify_timer, SSDP_NOTIFY_TIME, SSDP_NOTIFY_JITTER, ssdp_service_manager_notify_timer_callback, NULL);
		return;
	}

	oneshot_attach(&ssdp_service_manager.notify_timer, SSDP_NOTIFY_RATE_DELAY, ssdp_service_manager_notify_timer_callback, NULL);
}

static http_parser_error_t ssdp_service_manager_http_tag_man(void *arg, const char *header, struct netbuf *nb)
{
	if (netbuf_fwd_strcmp(nb, "\"ssdp:discover\"") != 0) {
		DEBUG_INFO("unexpected MAN str");
		return HTTP_PARSER_ESTOP;
	}

	DEBUG_TRACE("ssdp discover");
	ssdp_service_manager.discover_mode = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t ssdp_service_manager_http_tag_mx(void *arg, const char *header, struct netbuf *nb)
{
	ssdp_service_manager.mx_present = true;

	uint32_t mx_value;
	if (!netbuf_sscanf(nb, "%u", &mx_value)) {
		DEBUG_WARN("invalid mx value");
		mx_value = 0;
	}

	if (mx_value == 0) {
		ssdp_service_manager.max_delay = 200;
		return HTTP_PARSER_OK;
	}

	if (mx_value > 3) {
		mx_value = 3;
	}

	ssdp_service_manager.max_delay = (mx_value * 1000) - 200;
	return HTTP_PARSER_OK;
}

static http_parser_error_t ssdp_service_manager_http_tag_st(void *arg, const char *header, struct netbuf *nb)
{
	ssdp_service_manager_populate_discover_list_by_st(nb);

	if (!ssdp_service_manager.discover_list) {
		DEBUG_TRACE("ssdp discover for unknown service");
		return HTTP_PARSER_ESTOP;
	}

	DEBUG_TRACE("ssdp discover for supported service");
	return HTTP_PARSER_OK;
}

static void ssdp_service_manager_discover_timer_callback(void *arg)
{
	ticks_t current_time = timer_get_ticks();

	while (1) {
		struct ssdp_service_discover_reply_t *reply = slist_get_head(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list);
		if (!reply) {
			return;
		}

		if (reply->send_time > current_time) {
			ticks_t delay = reply->send_time - current_time;
			oneshot_attach(&ssdp_service_manager.discover_reply_timer, delay, ssdp_service_manager_discover_timer_callback, NULL);
			return;
		}

		ssdp_service_send_discover_response(reply->service, reply->remote_ip, reply->remote_port);
		heap_free(slist_detach_head(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list));
	}
}

static int8_t ssdp_service_manager_add_discover_reply_insert_before(struct ssdp_service_discover_reply_t *list_item, struct ssdp_service_discover_reply_t *item)
{
	return (list_item->send_time > item->send_time);
}

static void ssdp_service_manager_process_discover_service(struct ssdp_service_t *service, ipv4_addr_t remote_ip, uint16_t remote_port, ticks_t base_time, uint16_t max_delay)
{
	struct ssdp_service_discover_reply_t *reply = (struct ssdp_service_discover_reply_t *)heap_alloc_and_zero(sizeof(struct ssdp_service_discover_reply_t), PKG_OS, MEM_TYPE_OS_SSDP_REPLY);
	if (!reply) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	reply->service = service;
	reply->remote_ip = remote_ip;
	reply->remote_port = remote_port;
	reply->send_time = base_time + ((uint16_t)random_get32() % max_delay);

	slist_insert_custom(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list, reply, ssdp_service_manager_add_discover_reply_insert_before);
}

static void ssdp_service_manager_process_discover(ipv4_addr_t remote_ip, uint16_t remote_port)
{
	if (!ssdp_service_manager.mx_present) {
		return;
	}

	/*
	 * Generate reply state.
	 */
	ticks_t current_time = timer_get_ticks();
	uint16_t half_max_delay = ssdp_service_manager.max_delay / 2;

	while (ssdp_service_manager.discover_list) {
		struct ssdp_service_t *service = ssdp_service_manager.discover_list;
		ssdp_service_manager_process_discover_service(service, remote_ip, remote_port, current_time, half_max_delay);
		ssdp_service_manager_process_discover_service(service, remote_ip, remote_port, current_time + half_max_delay, half_max_delay);
		ssdp_service_manager.discover_list = service->discover_next;
	}

	/*
	 * Update timer.
	 */
	struct ssdp_service_discover_reply_t *first = slist_get_head(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list);
	if (!first) {
		return;
	}

	ticks_t delay = 0;
	if (first->send_time > current_time) {
		delay = first->send_time - current_time;
	}

	oneshot_detach(&ssdp_service_manager.discover_reply_timer);
	oneshot_attach(&ssdp_service_manager.discover_reply_timer, delay, ssdp_service_manager_discover_timer_callback, NULL);
}

void ssdp_service_manager_msearch_recv_complete(ipv4_addr_t remote_ip, uint16_t remote_port)
{
	if (ssdp_service_manager.discover_mode) {
		ssdp_service_manager_process_discover(remote_ip, remote_port);
	}

	ssdp_service_manager.mx_present = false;
	ssdp_service_manager.discover_mode = false;
	ssdp_service_manager.discover_list = NULL;
}

void ssdp_service_manager_resend_notify_now(void)
{
	if (!slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list)) {
		return;
	}

	if (ssdp_service_manager.initial_byebye) {
		return;
	}

	if (ssdp_service_manager.next_notify) {
		ssdp_service_manager.resend_notify = true;
		return;
	}

	/* No notify in progress - short-circuit timer to start notify now. */
	oneshot_detach(&ssdp_service_manager.notify_timer);
	oneshot_attach(&ssdp_service_manager.notify_timer, SSDP_NOTIFY_RATE_DELAY, ssdp_service_manager_notify_timer_callback, NULL);
}

void ssdp_service_manager_stop(void)
{
	oneshot_detach(&ssdp_service_manager.notify_timer);
	oneshot_detach(&ssdp_service_manager.discover_reply_timer);

	ssdp_service_manager.next_notify = NULL;

	while (slist_get_head(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list)) {
		heap_free(slist_detach_head(struct ssdp_service_discover_reply_t, &ssdp_service_manager.discover_reply_list));
	}
}

void ssdp_service_manager_start(void)
{
	if (!slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list)) {
		return;
	}

	ssdp_service_manager.resend_notify = true;
	ssdp_service_manager.initial_byebye = true;

	oneshot_attach(&ssdp_service_manager.notify_timer, SSDP_START_DELAY, ssdp_service_manager_notify_timer_callback, NULL);
}

static struct ssdp_service_t *ssdp_service_manager_add_service_internal(const char *uuid, const char *urn, const char *device_xml_uri)
{
	struct ssdp_service_t *service = (struct ssdp_service_t *)heap_alloc_and_zero(sizeof(struct ssdp_service_t), PKG_OS, MEM_TYPE_OS_SSDP_SERVICE);
	if (!service) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	service->uuid = uuid;
	service->urn = urn;
	service->device_xml_uri = device_xml_uri;

	slist_attach_tail(struct ssdp_service_t, &ssdp_service_manager.service_list, service);
	return service;
}

struct ssdp_service_t *ssdp_service_manager_add_service(const char *uuid, const char *urn, const char *device_xml_uri)
{
	DEBUG_ASSERT(uuid, "null uuid");
	DEBUG_ASSERT(urn, "null uuid");

	struct ssdp_service_t *p = slist_get_head(struct ssdp_service_t, &ssdp_service_manager.service_list);
	while (p) {
		if (strcmp(p->uuid, uuid) == 0) {
			break;
		}
		p = slist_get_next(struct ssdp_service_t, p);
	}

	if (!p) {
		ssdp_service_manager_add_service_internal(uuid, NULL, device_xml_uri);
	}

	return ssdp_service_manager_add_service_internal(uuid, urn, device_xml_uri);
}

void ssdp_service_manager_init(void)
{
	oneshot_init(&ssdp_service_manager.notify_timer);
	oneshot_init(&ssdp_service_manager.discover_reply_timer);
}
