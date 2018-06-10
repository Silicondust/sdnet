/*
 * igmp.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("igmp");

#define IGMP_MANAGER_MAX_ADDR_COUNT 4

struct igmp_manager_t {
	ipv4_addr_t addr_list[IGMP_MANAGER_MAX_ADDR_COUNT];
	uint8_t addr_count;
	bool active;
	int igmp_sock;
};

static struct igmp_manager_t igmp_manager;

void igmp_manager_join_group(ipv4_addr_t addr)
{
	DEBUG_ASSERT(!igmp_manager.active, "igmp join when igmp active");

	ipv4_addr_t *p = igmp_manager.addr_list;
	for (uint8_t index = 0; index < igmp_manager.addr_count; index++) {
		if (*p++ == addr) {
			return;
		}
	}

	DEBUG_ASSERT(igmp_manager.addr_count < IGMP_MANAGER_MAX_ADDR_COUNT, "too many igmp addrs");

	*p = addr;
	igmp_manager.addr_count++;
}

void igmp_manager_network_stop(void)
{
	if (!igmp_manager.active) {
		return;
	}

	igmp_manager.active = false;

	ipv4_addr_t *p = igmp_manager.addr_list;
	for (uint8_t index = 0; index < igmp_manager.addr_count; index++) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(*p++);
		if (setsockopt(igmp_manager.igmp_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to leave multicast group (error %d %s)", errno, strerror(errno));
		}
	}
}

void igmp_manager_network_start(void)
{
	DEBUG_ASSERT(!igmp_manager.active, "igmp_manager_network_start called when already active");
	igmp_manager.active = true;

	ipv4_addr_t *p = igmp_manager.addr_list;
	for (uint8_t index = 0; index < igmp_manager.addr_count; index++) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(*p++);
		if (setsockopt(igmp_manager.igmp_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to join multicast group (error %d %s)", errno, strerror(errno));
		}
	}
}

void igmp_manager_init(void)
{
	igmp_manager.igmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	DEBUG_ASSERT(igmp_manager.igmp_sock != -1, "failed to allocate socket");
}
