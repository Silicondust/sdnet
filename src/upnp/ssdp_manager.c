/*
 * ssdp_manager.c
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("ssdp_manager");

static const ip_addr_t ssdp_multicast_ipv4 = IP_ADDR_INIT_IPV4(0xEFFFFFFA);
#if defined(IPV6_SUPPORT)
static const ip_addr_t ssdp_multicast_ipv6 = IP_ADDR_INIT_IPV6(0xFF02, 0, 0, 0, 0, 0, 0, 0xC);
#endif

struct ssdp_manager_t ssdp_manager;

static http_parser_error_t ssdp_manager_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	switch (event) {
	case HTTP_PARSER_EVENT_METHOD:
		if (netbuf_fwd_strcasecmp(nb, "M-SEARCH") == 0) {
			ssdp_manager.recv_complete = ssdp_service_manager_msearch_recv_complete;
			http_parser_set_tag_list(ssdp_manager.http_parser, ssdp_service_manager_msearch_http_tag_list, NULL);
			return HTTP_PARSER_OK;
		}
		if (netbuf_fwd_strcasecmp(nb, "NOTIFY") == 0) {
			ssdp_manager.recv_complete = ssdp_client_manager_notify_recv_complete;
			http_parser_set_tag_list(ssdp_manager.http_parser, ssdp_client_manager_notify_http_tag_list, NULL);
			return HTTP_PARSER_OK;
		}
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_STATUS_CODE:
		if (netbuf_fwd_strncmp(nb, "200", 3) == 0) {
			ssdp_manager.recv_complete = ssdp_client_manager_response_recv_complete;
			http_parser_set_tag_list(ssdp_manager.http_parser, ssdp_client_manager_response_http_tag_list, NULL);
			return HTTP_PARSER_OK;
		}
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void ssdp_manager_sock_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	http_parser_recv_netbuf(ssdp_manager.http_parser, nb);
	http_parser_reset(ssdp_manager.http_parser);
	http_parser_set_tag_list(ssdp_manager.http_parser, NULL, NULL);

	if (ssdp_manager.recv_complete) {
		ssdp_manager.recv_complete(src_addr, src_port, ipv6_scope_id);
		ssdp_manager.recv_complete = NULL;
	}
}

void ssdp_manager_network_stop(void)
{
	if (!ssdp_manager.running) {
		return;
	}

	ssdp_manager.running = false;
	ssdp_service_manager_network_stop();
	ssdp_client_manager_network_stop();
}

void ssdp_manager_network_start(void)
{
	if (ssdp_manager.running) {
		DEBUG_ASSERT(1, "already running");
		return;
	}

	ssdp_manager.running = true;
	ssdp_service_manager_network_start();
	ssdp_client_manager_network_start();
}

void ssdp_manager_init(uint16_t webserver_port)
{
	ssdp_manager.webserver_port = webserver_port;

	ssdp_service_manager_init();
	ssdp_client_manager_init();

	ssdp_manager.http_parser = http_parser_alloc(ssdp_manager_http_event, NULL);
	if (!ssdp_manager.http_parser) {
		DEBUG_ERROR("out of memory");
		return;
	}

	ssdp_manager.ipv4.multicast_ip = &ssdp_multicast_ipv4;
	ssdp_manager.ipv4.sock = udp_socket_alloc(IP_MODE_IPV4);
	if (ssdp_manager.ipv4.sock) {
		udp_socket_listen(ssdp_manager.ipv4.sock, SSDP_SERVICE_PORT, ssdp_manager_sock_recv, NULL, NULL);
		igmp_manager_join_group(ssdp_manager.ipv4.sock, &ssdp_multicast_ipv4);
	}

#if defined(IPV6_SUPPORT)
	ssdp_manager.ipv6.multicast_ip = &ssdp_multicast_ipv6;
	ssdp_manager.ipv6.sock = udp_socket_alloc(IP_MODE_IPV6);
	if (ssdp_manager.ipv6.sock) {
		udp_socket_listen(ssdp_manager.ipv6.sock, SSDP_SERVICE_PORT, ssdp_manager_sock_recv, NULL, NULL);
		igmp_manager_join_group(ssdp_manager.ipv6.sock, &ssdp_multicast_ipv6);
	}
#endif
}
