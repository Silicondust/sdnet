/*
 * ./src/net/linux/ip_passive.c
 *
 * Copyright © 2012-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/ip_passive_common.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_passive");

#ifndef _SIZEOF_ADDR_IFREQ
#define _SIZEOF_ADDR_IFREQ(x) sizeof(x)
#endif

void ip_datalink_manager_detect_execute(void)
{
	int ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock == -1) {
		return;
	}

	struct ifconf ifc;
	size_t ifreq_buffer_size = 1024;

	while (1) {
		ifc.ifc_len = ifreq_buffer_size;
		ifc.ifc_buf = (char *)malloc(ifreq_buffer_size);
		if (!ifc.ifc_buf) {
			close(ioctl_sock);
			return;
		}

		memset(ifc.ifc_buf, 0, ifreq_buffer_size);

		if (ioctl(ioctl_sock, SIOCGIFCONF, &ifc) != 0) {
			free(ifc.ifc_buf);
			close(ioctl_sock);
			return;
		}

		if (ifc.ifc_len < (int)ifreq_buffer_size) {
			break;
		}

		free(ifc.ifc_buf);
		ifreq_buffer_size += 1024;
	}

	char *ptr = ifc.ifc_buf;
	char *end = ifc.ifc_buf + ifc.ifc_len;

	while (ptr < end) {
		struct ifreq *ifr = (struct ifreq *)ptr;
		ptr += _SIZEOF_ADDR_IFREQ(*ifr);

		/* Flags. */
		if (ioctl(ioctl_sock, SIOCGIFFLAGS, ifr) != 0) {
			continue;
		}

		if ((ifr->ifr_flags & IFF_UP) == 0) {
			continue;
		}
		if ((ifr->ifr_flags & IFF_RUNNING) == 0) {
			continue;
		}
		if (ifr->ifr_flags & IFF_LOOPBACK) {
			continue;
		}

		/* Local IP address. */
		if (ioctl(ioctl_sock, SIOCGIFADDR, ifr) != 0) {
			continue;
		}

		struct sockaddr_in *ip_addr_in = (struct sockaddr_in *)&(ifr->ifr_addr);
		uint32_t ip_addr = ntohl(ip_addr_in->sin_addr.s_addr);
		if (ip_addr == 0) {
			continue;
		}

		/* Subnet mask. */
		if (ioctl(ioctl_sock, SIOCGIFNETMASK, ifr) != 0) {
			continue;
		}

		struct sockaddr_in *subnet_mask_in = (struct sockaddr_in *)&(ifr->ifr_addr);
		uint32_t subnet_mask = ntohl(subnet_mask_in->sin_addr.s_addr);

		/* Detect hash. */
		uint32_t detect_hash = hash32_create(&ip_addr, sizeof(ip_addr));
		detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(subnet_mask));

		if (ip_datalink_manager_detect_reactivate(detect_hash)) {
			continue;
		}

		/* Create idi. */
		struct ip_datalink_instance *idi = (struct ip_datalink_instance *)heap_alloc_and_zero(sizeof(struct ip_datalink_instance), PKG_OS, MEM_TYPE_OS_IP_DATALINK);
		if (!idi) {
			continue;
		}

		idi->detect_hash = detect_hash;
		idi->ip_addr = ip_addr;
		idi->subnet_mask = subnet_mask;
		ip_datalink_manager_detect_add(idi);
	}

	free(ifc.ifc_buf);
	close(ioctl_sock);
}
