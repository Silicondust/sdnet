/*
 * ip_interface.h
 *
 * Copyright © 2007-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_interface_t;

#if !defined(ICMP_TYPE_ERR_DEST_UNREACHABLE)
#define ICMP_TYPE_ERR_DEST_UNREACHABLE 0
#define ICMP_TYPE_ERR_TIME_EXCEEDED 1
#endif

typedef void (*ip_interface_new_callback_t)(void *arg, struct ip_interface_t *idi);
typedef void (*ip_interface_lost_callback_t)(void *arg, struct ip_interface_t *idi);

extern uint32_t ip_interface_get_ifindex(struct ip_interface_t *idi);
extern uint32_t ip_interface_get_ipv6_scope_id(struct ip_interface_t *idi);
extern void ip_interface_get_local_ip(struct ip_interface_t *idi, ip_addr_t *result);
extern void ip_interface_get_subnet_mask(struct ip_interface_t *idi, ip_addr_t *result);
extern bool ip_interface_is_same_subnet(struct ip_interface_t *idi, const ip_addr_t *ip_addr);
extern bool ip_interface_is_ipv4_autoip_and_interface_has_ipv4_routable_ip(struct ip_interface_t *idi);
extern bool ip_interface_is_ipv6(struct ip_interface_t *idi);
extern bool ip_interface_is_ipv6_link_local(struct ip_interface_t *idi);

extern void ip_interface_manager_init(void);
extern void ip_interface_manager_register_callbacks(ip_interface_new_callback_t callback_new, ip_interface_lost_callback_t callback_lost, void *callback_arg, bool trigger_now);
extern bool ip_interface_manager_has_routable_ipv4(void);
extern bool ip_interface_manager_has_public_ipv6(void);
extern struct ip_interface_t *ip_interface_manager_get_head(void);
extern struct ip_interface_t *ip_interface_manager_get_by_local_ip(const ip_addr_t *local_ip, uint32_t ipv6_scope_id);
extern struct ip_interface_t *ip_interface_manager_get_by_remote_ip(const ip_addr_t *remote_ip, uint32_t ipv6_scope_id);
extern void ip_interface_manager_get_local_ip_for_remote_ip(const ip_addr_t *remote_ip, uint32_t ipv6_scope_id, ip_addr_t *result);

#if !defined(IPV6_SUPPORT)
extern inline uint32_t ip_interface_get_ipv6_scope_id(struct ip_interface_t *idi) { return 0; }
extern inline bool ip_interface_is_ipv6(struct ip_interface_t *idi) { return false; }
extern inline bool ip_interface_is_ipv6_link_local(struct ip_interface_t *idi) { return false; }
extern inline bool ip_interface_manager_has_public_ipv6(void) { return false; }
#endif
