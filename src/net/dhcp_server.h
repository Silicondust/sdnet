/*
 * dhcp_server.h
 *
 * Copyright © 2010,2020-2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void dhcp_server_init(struct ip_managed_t *ipm, ipv4_addr_t local_ip_addr, ipv4_addr_t client_ip_first, ipv4_addr_t client_ip_last, ipv4_addr_t subnet_mask);
extern void dhcp_server_load_state(uint8_t *ptr, uint8_t *end);

extern void dhcp_server_store_state_impl(struct netbuf *nb);
