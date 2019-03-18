/*
 * ip_datalink.h
 *
 * Copyright © 2007-2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_datalink_instance;

#define LOCALHOST 0x7F000001

#if !defined(ICMP_TYPE_ERR_DEST_UNREACHABLE)
#define ICMP_TYPE_ERR_DEST_UNREACHABLE 0
#define ICMP_TYPE_ERR_TIME_EXCEEDED 1
#endif

/* Datalink */
extern ipv4_addr_t ip_datalink_get_ipaddr(struct ip_datalink_instance *idi);
extern ipv4_addr_t ip_datalink_get_subnet_mask(struct ip_datalink_instance *idi);
extern ipv4_addr_t ip_datalink_get_subnet_broadcast(struct ip_datalink_instance *idi);

/* Datalink - Linux managed */
extern char *ip_datalink_get_interface_name(struct ip_datalink_instance *idi);
extern int ip_datalink_get_ifindex(struct ip_datalink_instance *idi);
extern void ip_datalink_get_hwaddr(struct ip_datalink_instance *idi, uint8_t *hwaddr, uint8_t hwaddr_len);
extern void ip_datalink_set_hwaddr(struct ip_datalink_instance *idi, uint8_t *hwaddr, uint8_t hwaddr_len);
extern void ip_datalink_set_ipaddr(struct ip_datalink_instance *idi, ipv4_addr_t ip_addr, ipv4_addr_t subnet_mask, ipv4_addr_t gateway);
extern void ip_datalink_set_loopback(struct ip_datalink_instance *idi);
extern bool ip_datalink_read_ethernet_mii_register(struct ip_datalink_instance *idi, uint8_t reg_addr, uint16_t *presult);

/* Manager. */
extern void ip_datalink_manager_init(void);
extern struct ip_datalink_instance *ip_datalink_manager_get_head(void);
extern struct ip_datalink_instance *ip_datalink_manager_get_by_local_ip(ipv4_addr_t local_ip);
extern struct ip_datalink_instance *ip_datalink_manager_get_by_remote_ip(ipv4_addr_t remote_ip);

/* Manager - Linux managed. */
extern struct ip_datalink_instance *ip_datalink_manager_ip_datalink_alloc(const char *interface_name, uint8_t metric);

/* Utils. */
static inline bool ip_addr_is_unicast(ipv4_addr_t addr)
{
	return (addr > 0x00000000) && (addr < 0xE0000000);
}

static inline bool ip_addr_is_multicast(ipv4_addr_t addr)
{
	return (addr >= 0xE0000000) && (addr < 0xF0000000);
}

static inline ipv4_addr_t ip_get_local_ip_for_remote_ip(ipv4_addr_t remote_ip)
{
	struct ip_datalink_instance *idi = ip_datalink_manager_get_by_remote_ip(remote_ip);
	return (idi) ? ip_datalink_get_ipaddr(idi) : 0;
}
