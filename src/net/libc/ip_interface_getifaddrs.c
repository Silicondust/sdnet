/*
 * ip_interface_getifaddrs.c
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/if.h>
#include <netinet6/in6_var.h>
#include <ifaddrs.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_interface_getifaddrs");

void ip_interface_manager_detect_execute(void)
{
	int af6_sock = -1;
#if defined(IPV6_SUPPORT)
	af6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (af6_sock == -1) {
		DEBUG_ERROR("socket failed");
		return;
	}
#endif

	struct ifaddrs *ifaddrs;
	if (getifaddrs(&ifaddrs) != 0) {
		close(af6_sock);
		return;
	}

	struct ifaddrs *ifa = ifaddrs;
	while (ifa) {
		if (ifa->ifa_addr == NULL) {
			ifa = ifa->ifa_next;
			continue;
		}

		/*
		 * interface flags 
		 */
		unsigned int flags = ifa->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING | IFF_MULTICAST);
		if (flags != (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) {
			ifa = ifa->ifa_next;
			continue;
		}

		/*
		 * ifindex
		 */
		uint32_t ifindex = if_nametoindex(ifa->ifa_name);

		/*
		 * filter out ipv6 temporary addresses
		 */
#if defined(IPV6_SUPPORT)
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct in6_ifreq ifr6;
			memset(&ifr6, 0, sizeof(ifr6));

			struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)ifa->ifa_addr;
			strcpy(ifr6.ifr_name, ifa->ifa_name);
			ifr6.ifr_addr = *addr_in;

			if (ioctl(af6_sock, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
				DEBUG_ERROR("ioctl SIOCGIFALIFETIME_IN6 failed");
				ifa = ifa->ifa_next;
				continue;
			}

			if (ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime != 0xFFFFFFFF) {
				ifa = ifa->ifa_next;
				continue;
			}
		}
#endif

		/*
		 * ip address
		 */
		ip_addr_t ip_addr;
		ip_addr_t subnet_mask;
		ip_addr_set_zero(&ip_addr);
		ip_addr_set_zero(&subnet_mask);

#if defined(IPV6_SUPPORT)
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)ifa->ifa_addr;
			ip_addr_set_ipv6_bytes(&ip_addr, addr_in->sin6_addr.s6_addr);

			struct sockaddr_in6 *netmask_in = (struct sockaddr_in6 *)ifa->ifa_netmask;
			ip_addr_set_ipv6_bytes(&subnet_mask, netmask_in->sin6_addr.s6_addr);
		}
#endif
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			ip_addr_set_ipv4(&ip_addr, ntohl(addr_in->sin_addr.s_addr));

			struct sockaddr_in *netmask_in = (struct sockaddr_in *)ifa->ifa_netmask;
			ip_addr_set_ipv4(&subnet_mask, ntohl(netmask_in->sin_addr.s_addr));
		}

		if (!ip_addr_is_unicast_not_localhost(&ip_addr) || ip_addr_is_zero(&subnet_mask)) {
			ifa = ifa->ifa_next;
			continue;
		}

		/*
		 * record
		 */
		ifa = ifa->ifa_next;

		uint32_t detect_hash = hash32_create(&ifindex, sizeof(ifindex));
		detect_hash = hash32_append(detect_hash, &ip_addr, sizeof(ip_addr_t));
		detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(ip_addr_t));

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
		ip_interface_manager_detect_add(idi);
	}

	close(af6_sock);
	freeifaddrs(ifaddrs);
}
