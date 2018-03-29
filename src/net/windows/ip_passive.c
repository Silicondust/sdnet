/*
 * ./src/net/windows/ip_passive.c
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

void ip_datalink_manager_detect_execute(void)
{
	PIP_ADAPTER_INFO adapter_info;
	ULONG adapter_info_length = sizeof(IP_ADAPTER_INFO) * 16;

	while (1) {
		adapter_info = (IP_ADAPTER_INFO *)malloc(adapter_info_length);
		if (!adapter_info) {
			return;
		}

		ULONG length_needed = adapter_info_length;
		DWORD ret = GetAdaptersInfo(adapter_info, &length_needed);
		if (ret == NO_ERROR) {
			break;
		}

		free(adapter_info);

		if (ret != ERROR_BUFFER_OVERFLOW) {
			return;
		}
		if (adapter_info_length >= length_needed) {
			return;
		}

		adapter_info_length = length_needed;
	}

	PIP_ADAPTER_INFO adapter = adapter_info;

	while (adapter) {
		if ((adapter->Type != MIB_IF_TYPE_ETHERNET) && (adapter->Type != IF_TYPE_IEEE80211)) {
			adapter = adapter->Next;
			continue;
		}

		if (adapter->AddressLength != 6) {
			adapter = adapter->Next;
			continue;
		}

		IP_ADDR_STRING *ip_addr_struct = &adapter->IpAddressList;
		while (ip_addr_struct) {
			uint32_t ip_addr = ntohl(inet_addr(ip_addr_struct->IpAddress.String));
			uint32_t subnet_mask = ntohl(inet_addr(ip_addr_struct->IpMask.String));

			if (ip_addr == 0) {
				ip_addr_struct = ip_addr_struct->Next;
				continue;
			}

			/* Detect hash. */
			uint32_t detect_hash = hash32_create(&ip_addr, sizeof(ip_addr));
			detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(subnet_mask));

			if (ip_datalink_manager_detect_reactivate(detect_hash)) {
				ip_addr_struct = ip_addr_struct->Next;
				continue;
			}

			/* Create idi. */
			struct ip_datalink_instance *idi = (struct ip_datalink_instance *)heap_alloc_and_zero(sizeof(struct ip_datalink_instance), PKG_OS, MEM_TYPE_OS_IP_DATALINK);
			if (!idi) {
				ip_addr_struct = ip_addr_struct->Next;
				continue;
			}

			idi->detect_hash = detect_hash;
			idi->ip_addr = ip_addr;
			idi->subnet_mask = subnet_mask;
			ip_datalink_manager_detect_add(idi);

			ip_addr_struct = ip_addr_struct->Next;
		}

		adapter = adapter->Next;
	}

	free(adapter_info);
}
