/*
 * ./src/upnp/ssdp_client_dummy.c
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

THIS_FILE("ssdp_client_dummy");

const struct http_parser_tag_lookup_t ssdp_client_manager_notify_http_tag_list[] = {
	{NULL, NULL}
};

const struct http_parser_tag_lookup_t ssdp_client_manager_response_http_tag_list[] = {
	{NULL, NULL}
};

void ssdp_client_manager_notify_recv_complete(ipv4_addr_t remote_ip, uint16_t remote_port)
{
}

void ssdp_client_manager_response_recv_complete(ipv4_addr_t remote_ip, uint16_t remote_port)
{
}

void ssdp_client_manager_stop(void)
{
}

void ssdp_client_manager_start(void)
{
}

void ssdp_client_manager_init(void)
{
}
