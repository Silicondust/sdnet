/*
 * ip_passive.c
 *
 * Copyright © 2012-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/ip_passive_common.h>
#include <ifaddrs.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_passive");

void ip_datalink_manager_detect_execute(void)
{
	struct ifaddrs *ifaddrs;
	if (getifaddrs(&ifaddrs) != 0) {
		return;
	}

	struct ifaddrs *ifa = ifaddrs;
	while (ifa) {
		if (ifa->ifa_addr == NULL) {
			ifa = ifa->ifa_next;
			continue;
		}

		if (ifa->ifa_addr->sa_family != AF_INET) {
			ifa = ifa->ifa_next;
			continue;
		}

		unsigned int flags = ifa->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING);
		if (flags != (IFF_UP | IFF_RUNNING)) {
			ifa = ifa->ifa_next;
			continue;
		}

		struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
		uint32_t ip_addr = ntohl(addr_in->sin_addr.s_addr);

		struct sockaddr_in *netmask_in = (struct sockaddr_in *)ifa->ifa_netmask;
		uint32_t subnet_mask = ntohl(netmask_in->sin_addr.s_addr);

		ifa = ifa->ifa_next;

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

	freeifaddrs(ifaddrs);
}
