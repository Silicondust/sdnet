/*
 * dhcp_client.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_managed_t;
struct dhcp_client_t;

typedef void (*dhcp_client_callback_t)(void *arg, ipv4_addr_t ip_addr, ipv4_addr_t subnet, ipv4_addr_t gateway, ipv4_addr_t dns_ip_primary, ipv4_addr_t dns_ip_secondary);

extern struct dhcp_client_t *dhcp_client_alloc(struct ip_managed_t *idi, const char *client_name, dhcp_client_callback_t callback, void *callback_arg);
extern void dhcp_client_link_up(struct dhcp_client_t *dc);
extern void dhcp_client_link_down(struct dhcp_client_t *dc);
