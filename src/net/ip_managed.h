/*
 * ip_managed.h
 *
 * Copyright © 2007-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_managed_t;

extern struct ip_managed_t *ip_managed_alloc(const char *interface_name, uint8_t metric);
	
extern char *ip_managed_get_interface_name(struct ip_managed_t *ipm);
extern uint32_t ip_managed_get_ifindex(struct ip_managed_t *ipm);
extern void ip_managed_get_mac_addr(struct ip_managed_t *ipm, uint8_t mac_addr[6]);
extern void ip_managed_get_local_ip(struct ip_managed_t *ipm, ip_addr_t *result);
extern void ip_managed_get_subnet_mask(struct ip_managed_t *ipm, ip_addr_t *result);

extern void ip_managed_set_mac_addr(struct ip_managed_t *ipm, uint8_t mac_addr[6]);
extern void ip_managed_set_ipv4_addr(struct ip_managed_t *ipm, ipv4_addr_t ip_addr, ipv4_addr_t subnet_mask, ipv4_addr_t gateway);
extern void ip_managed_set_wifi_ap(struct ip_managed_t *ipm);
extern void ip_managed_set_loopback(struct ip_managed_t *ipm);

extern bool ip_managed_read_ethernet_mii_register(struct ip_managed_t *ipm, uint8_t reg_addr, uint16_t *presult);
