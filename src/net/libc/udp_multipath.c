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

#if defined(IP_ONESBCAST)
#error use net/bsd/udp_multipath.c for bsd platforms that require IP_ONESBCAST
#endif

struct udp_multipath_t {
	struct slist_prefix_t slist_prefix;
	struct udp_socket *us;
	ipv4_addr_t addr;
	bool bind_ok;
};

static struct udp_multipath_t *udp_socket_multipath_find_create(struct udp_socket *us, ipv4_addr_t addr)
{
	struct udp_multipath_t *ump = slist_get_head(struct udp_multipath_t, &us->multipath_list);
	while (ump) {
		if (ump->addr == addr) {
			return ump;
		}

		ump = slist_get_next(struct udp_multipath_t, ump);
	}

	ump = heap_alloc_and_zero(sizeof(struct udp_multipath_t), PKG_OS, MEM_TYPE_OS_UDP_MULTIPATH);
	if (!ump) {
		return NULL;
	}

	ump->us = udp_socket_alloc();
	if (!ump->us) {
		heap_free(ump);
		return NULL;
	}

	ump->addr = addr;
	ump->bind_ok = (udp_socket_listen(ump->us, addr, us->port, us->recv_callback, us->recv_icmp_callback, us->callback_inst) == UDP_OK);

	slist_attach_head(struct udp_multipath_t, &us->multipath_list, ump);
	return ump;
}

udp_error_t udp_socket_send_multipath(struct udp_socket *us, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	if (src_addr != 0) {
		struct udp_multipath_t *ump = udp_socket_multipath_find_create(us, src_addr);
		if (!ump || !ump->bind_ok) {
			return UDP_ERROR_FAILED;
		}

		return udp_socket_send_netbuf(ump->us, dest_addr, dest_port, ttl, tos, nb);
	}

	bool global_broadcast = (dest_addr == 0xFFFFFFFF);
	bool filter = !global_broadcast && !ip_addr_is_multicast(dest_addr);
	udp_error_t result = UDP_ERROR_FAILED;

	struct ip_datalink_instance *idi = ip_datalink_manager_get_head();
	while (idi) {
		src_addr = ip_datalink_get_ipaddr(idi);
		if (src_addr == 0) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if (filter) {
			ipv4_addr_t subnet_mask = ip_datalink_get_subnet_mask(idi);
			if (subnet_mask == 0) {
				idi = slist_get_next(struct ip_datalink_instance, idi);
				continue;
			}
			if ((dest_addr & subnet_mask) != (src_addr & subnet_mask)) {
				idi = slist_get_next(struct ip_datalink_instance, idi);
				continue;
			}
		}

		struct udp_multipath_t *ump = udp_socket_multipath_find_create(us, src_addr);
		if (!ump || !ump->bind_ok) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if (udp_socket_send_netbuf(ump->us, dest_addr, dest_port, ttl, tos, nb) != UDP_OK) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		result = UDP_OK;
		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	if (result != UDP_OK) {
		result = udp_socket_send_netbuf(us, dest_addr, dest_port, ttl, tos, nb);
	}

	return result;
}
