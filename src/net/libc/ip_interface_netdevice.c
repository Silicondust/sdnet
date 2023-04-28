/*
 * ip_interface_netdevice.c
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/if.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_interface_netdevice");

void ip_interface_manager_detect_execute(void)
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		return;
	}

	int ifreq_buffer_size = 128 * sizeof(struct ifreq);
	char *ifreq_buffer = (char *)calloc(ifreq_buffer_size, 1);
	if (!ifreq_buffer) {
		close(sock);
		return;
	}

	struct ifconf ifc;
	ifc.ifc_len = ifreq_buffer_size;
	ifc.ifc_buf = ifreq_buffer;

	if (ioctl(sock, SIOCGIFCONF, &ifc) != 0) {
		free(ifreq_buffer);
		close(sock);
		return;
	}

	if (ifc.ifc_len > ifreq_buffer_size) {
		ifc.ifc_len = ifreq_buffer_size;
	}

	char *ptr = ifc.ifc_buf;
	char *end = ifc.ifc_buf + ifc.ifc_len;

	while (ptr + sizeof(struct ifreq) <= end) {
		struct ifreq *ifr = (struct ifreq *)ptr;
		ptr += sizeof(struct ifreq);

		/*
		 * ip address
		 */
		ip_addr_t ip_addr;
		struct sockaddr_in *ip_addr_in = (struct sockaddr_in *)&ifr->ifr_addr;
		ip_addr_set_ipv4(&ip_addr, ntohl(ip_addr_in->sin_addr.s_addr));
		if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
			continue;
		}

		/*
		 * interface flags
		 */
		if (ioctl(sock, SIOCGIFFLAGS, ifr) != 0) {
			continue;
		}

		uint32_t flags = ifr->ifr_flags;
		flags &= (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING | IFF_MULTICAST);
		if (flags != (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) {
			continue;
		}

		/*
		 * subnet mask
		 */
		if (ioctl(sock, SIOCGIFNETMASK, ifr) != 0) {
			continue;
		}

		struct sockaddr_in *subnet_mask_in = (struct sockaddr_in *)&ifr->ifr_netmask;
		uint32_t subnet_mask_u32 = ntohl(subnet_mask_in->sin_addr.s_addr);
		if ((subnet_mask_u32 == 0) || (subnet_mask_u32 == 0xFFFFFFFF)) {
			continue;
		}

		ip_addr_t subnet_mask;
		ip_addr_set_ipv4(&subnet_mask, subnet_mask_u32);

		/*
		 * ifindex
		 */
		if (ioctl(sock, SIOCGIFINDEX, ifr) != 0) {
			continue;
		}

		uint32_t ifindex = ifr->ifr_ifindex;
		if (ifindex == 0) {
			continue;
		}

		/*
		 * record
		 */
		uint64_t detect_hash = hash64_create(&ifindex, sizeof(ifindex));
		detect_hash = hash64_append(detect_hash, &ip_addr, sizeof(ip_addr_t));
		detect_hash = hash64_append(detect_hash, &subnet_mask, sizeof(ip_addr_t));

		if (ip_interface_manager_detect_reactivate(detect_hash)) {
			continue;
		}

		struct ip_interface_t *idi = (struct ip_interface_t *)heap_alloc_and_zero(sizeof(struct ip_interface_t), PKG_OS, MEM_TYPE_OS_IP_INTERFACE);
		if (!idi) {
			continue;
		}

		idi->detect_hash = detect_hash;
		idi->ifindex = ifindex;
		idi->ip_addr = ip_addr;
		idi->subnet_mask = subnet_mask;
		idi->ip_score = ip_addr_compute_score(&ip_addr);
		ip_interface_manager_detect_add(idi);
	}

	free(ifreq_buffer);
	close(sock);
}
