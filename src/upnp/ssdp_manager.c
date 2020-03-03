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

static void ssdp_manager_sock_recv(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb)
{
	http_parser_recv_netbuf(ssdp_manager.http_parser, nb);
	http_parser_reset(ssdp_manager.http_parser);
	http_parser_set_tag_list(ssdp_manager.http_parser, NULL, NULL);

	if (ssdp_manager.recv_complete) {
		ssdp_manager.recv_complete(src_addr, src_port);
		ssdp_manager.recv_complete = NULL;
	}
}

void ssdp_manager_stop(void)
{
	ssdp_manager.local_ip = 0;
	ssdp_service_manager_stop();
	ssdp_client_manager_stop();
}

void ssdp_manager_start(ipv4_addr_t local_ip)
{
	if (ssdp_manager.local_ip != 0) {
		ssdp_service_manager_stop();
		ssdp_client_manager_stop();
	}

	ssdp_manager.local_ip = local_ip;
	ssdp_service_manager_start();
	ssdp_client_manager_start();
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

	ssdp_manager.sock = udp_socket_alloc();
	if (!ssdp_manager.sock) {
		DEBUG_ERROR("out of memory");
		return;
	}

	if (udp_socket_listen(ssdp_manager.sock, 0, SSDP_SERVICE_PORT, ssdp_manager_sock_recv, NULL, NULL) != UDP_OK) {
		DEBUG_ERROR("failed to listen on socket");
		return;
	}

	igmp_manager_join_group(SSDP_MULTICAST_IP);
}
