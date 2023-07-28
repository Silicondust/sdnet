/*
 * udp_multipath.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("udp");

#if !defined(IP_ONESBCAST)
#error use net/libc/udp_multipath.c for bsd platforms that dont require IP_ONESBCAST
#endif

struct udp_multipath_t {
	struct slist_prefix_t slist_prefix;
	struct udp_socket *us;
	uint32_t ifindex;
	uint32_t ipv6_scope_id;
	ip_addr_t addr;
	bool bind_ok;
};

static struct udp_multipath_t *udp_socket_multipath_find_create(struct udp_socket *us, struct ip_interface_t *idi)
{
	ip_addr_t local_ip;
	ip_interface_get_local_ip(idi, &local_ip);
	uint32_t ifindex = ip_interface_get_ifindex(idi);

	struct udp_multipath_t *ump = slist_get_head(struct udp_multipath_t, &us->multipath_list);
	while (ump) {
		if (ip_addr_cmp(&ump->addr, &local_ip) && (ump->ifindex == ifindex)) {
			return ump;
		}

		ump = slist_get_next(struct udp_multipath_t, ump);
	}

	ump = heap_alloc_and_zero(sizeof(struct udp_multipath_t), PKG_OS, MEM_TYPE_OS_UDP_MULTIPATH);
	if (!ump) {
		return NULL;
	}

	ump->us = udp_socket_alloc(us->ip_mode);
	if (!ump->us) {
		heap_free(ump);
		return NULL;
	}

	if (us->allow_ipv4_broadcast) {
		udp_socket_allow_ipv4_broadcast(ump->us);
	}

	ump->addr = local_ip;
	ump->ifindex = ifindex;
	ump->ipv6_scope_id = ip_interface_get_ipv6_scope_id(idi);
	ump->bind_ok = (udp_socket_listen_idi(ump->us, idi, us->port, us->recv_callback, us->recv_icmp_callback, us->callback_inst) == UDP_OK);

	slist_attach_head(struct udp_multipath_t, &us->multipath_list, ump);
	return ump;
}

static void udp_socket_multipath_set_onesbcast(struct udp_socket *us, bool onesbcast)
{
	if (us->onesbcast_set == onesbcast) {
		return;
	}

	int sock_opt_onesbcast = (int)onesbcast;
	if (setsockopt(us->sock, IPPROTO_IP, IP_ONESBCAST, (char *)&sock_opt_onesbcast, sizeof(sock_opt_onesbcast)) < 0) {
		DEBUG_WARN("setsockopt IP_ONESBCAST error %d", errno);
		return;
	}

	us->onesbcast_set = onesbcast;
}

udp_error_t udp_socket_send_multipath(struct udp_socket *us, const ip_addr_t *dest_addr, uint16_t dest_port, struct ip_interface_t *idi, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	if (ip_addr_is_zero(dest_addr)) {
		return UDP_ERROR_FAILED;
	}

	ip_addr_t local_ip;
	ip_interface_get_local_ip(idi, &local_ip);
	if (ip_addr_is_zero(&local_ip)) {
		return UDP_ERROR_FAILED;
	}

	ip_addr_t send_addr = *dest_addr;
	bool dest_ipv4_broadcast = ip_addr_is_ipv4_broadcast(dest_addr);
	if (dest_ipv4_broadcast) {
		if (!us->allow_ipv4_broadcast) {
			return UDP_ERROR_FAILED;
		}

		ip_addr_t subnet_mask;
		ip_interface_get_subnet_mask(idi, &subnet_mask);

		ip_addr_set_ipv4(&send_addr, ip_addr_get_ipv4(&local_ip) | ~ip_addr_get_ipv4(&subnet_mask));

		if (ip_addr_is_zero(&send_addr) || ip_addr_is_ipv4_broadcast(&send_addr)) {
			return UDP_ERROR_FAILED;
		}
	}

	struct udp_multipath_t *ump = udp_socket_multipath_find_create(us, idi);
	if (!ump || !ump->bind_ok) {
		return UDP_ERROR_FAILED;
	}

	udp_socket_multipath_set_onesbcast(ump->us, dest_ipv4_broadcast);

	return udp_socket_send_netbuf(ump->us, &send_addr, dest_port, ump->ipv6_scope_id, ttl, tos, nb);
}
