/*
 * ip_interface_detect.c
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("ip_interface_detect");

#if defined(IPV6_SUPPORT)
#define AF_MODE AF_UNSPEC
#else
#define AF_MODE AF_INET
#endif

void ip_interface_manager_detect_execute(void)
{
	IP_ADAPTER_ADDRESSES *adapter_addresses;
	ULONG adapter_addresses_length = sizeof(IP_ADAPTER_ADDRESSES) * 16;

	while (1) {
		adapter_addresses = (IP_ADAPTER_ADDRESSES *)heap_alloc(adapter_addresses_length, PKG_OS, MEM_TYPE_OS_IP_INTERFACE_DETECT);
		if (!adapter_addresses) {
			return;
		}

		ULONG length_needed = adapter_addresses_length;
		DWORD ret = GetAdaptersAddresses(AF_MODE, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, adapter_addresses, &length_needed);
		if (ret == NO_ERROR) {
			break;
		}

		heap_free(adapter_addresses);

		if (ret != ERROR_BUFFER_OVERFLOW) {
			return;
		}
		if (adapter_addresses_length >= length_needed) {
			return;
		}

		adapter_addresses_length = length_needed;
	}

	IP_ADAPTER_ADDRESSES *adapter = adapter_addresses;

	while (adapter) {
		if ((adapter->IfType != MIB_IF_TYPE_ETHERNET) && (adapter->IfType != IF_TYPE_IEEE80211)) {
			adapter = adapter->Next;
			continue;
		}

		if (adapter->PhysicalAddressLength != 6) {
			adapter = adapter->Next;
			continue;
		}

		uint32_t ifindex = adapter->IfIndex;

		IP_ADAPTER_UNICAST_ADDRESS *adapter_address = adapter->FirstUnicastAddress;
		while (adapter_address) {
			if (adapter_address->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) {
				adapter_address = adapter_address->Next;
				continue;
			}

			ip_addr_t ip_addr;
			ip_addr_set_zero(&ip_addr);

			struct sockaddr *sock_addr = adapter_address->Address.lpSockaddr;
#if defined(IPV6_SUPPORT)
			if (sock_addr->sa_family == AF_INET6) {
				if (adapter_address->ValidLifetime != 0xFFFFFFFF) {
					adapter_address = adapter_address->Next;
					continue; /* skip temporary IPv6 addresses */
				}

				struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)sock_addr;
				ip_addr_set_ipv6_bytes(&ip_addr, sock_addr_in->sin6_addr.s6_addr);
			}
#endif
			if (sock_addr->sa_family == AF_INET) {
				struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)sock_addr;
				ip_addr_set_ipv4(&ip_addr, ntohl(sock_addr_in->sin_addr.s_addr));
			}

			if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
				adapter_address = adapter_address->Next;
				continue;
			}

			ip_addr_t subnet_mask;
			ip_addr_set_subnet_mask_from_cidr(&subnet_mask, &ip_addr, adapter_address->OnLinkPrefixLength);
			if (ip_addr_is_zero(&subnet_mask)) {
				adapter_address = adapter_address->Next;
				continue;
			}

			/* Detect hash. */
			uint32_t detect_hash = hash32_create(&ifindex, sizeof(ifindex));
			detect_hash = hash32_append(detect_hash, &ip_addr, sizeof(ip_addr_t));
			detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(ip_addr_t));

			if (ip_interface_manager_detect_reactivate(detect_hash)) {
				adapter_address = adapter_address->Next;
				continue;
			}

			/* Create idi. */
			struct ip_interface_t *idi = (struct ip_interface_t *)heap_alloc_and_zero(sizeof(struct ip_interface_t), PKG_OS, MEM_TYPE_OS_IP_INTERFACE);
			if (!idi) {
				adapter_address = adapter_address->Next;
				continue;
			}

			idi->detect_hash = detect_hash;
			idi->ifindex = ifindex;
			idi->ip_addr = ip_addr;
			idi->subnet_mask = subnet_mask;
			ip_interface_manager_detect_add(idi);

			adapter_address = adapter_address->Next;
		}

		adapter = adapter->Next;
	}

	heap_free(adapter_addresses);
}
