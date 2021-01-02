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

struct igmp_entry_t {
	struct slist_prefix_t slist_prefix;
	int sock;
	ipv4_addr_t addr;
};

struct igmp_manager_t {
	struct slist_t list;
	bool active;
};

static struct igmp_manager_t igmp_manager;

void igmp_manager_join_group(struct udp_socket *us, ipv4_addr_t addr)
{
	DEBUG_ASSERT(!igmp_manager.active, "igmp join when igmp active");

	struct igmp_entry_t *entry = (struct igmp_entry_t *)heap_alloc_and_zero(sizeof(struct igmp_entry_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
	if (!entry) {
		return;
	}

	entry->sock = us->sock;
	entry->addr = addr;

	slist_attach_head(struct igmp_entry_t, &igmp_manager.list, entry);
}

void igmp_manager_network_stop(void)
{
	if (!igmp_manager.active) {
		return;
	}

	igmp_manager.active = false;

	struct igmp_entry_t *entry = slist_get_head(struct igmp_entry_t, &igmp_manager.list);
	while (entry) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(entry->addr);

		if (setsockopt(entry->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to leave multicast group (error %d)", WSAGetLastError());
		}

		entry = slist_get_next(struct igmp_entry_t, entry);
	}
}

void igmp_manager_network_start(void)
{
	DEBUG_ASSERT(!igmp_manager.active, "igmp_manager_network_start called when already active");
	igmp_manager.active = true;

	struct igmp_entry_t *entry = slist_get_head(struct igmp_entry_t, &igmp_manager.list);
	while (entry) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(entry->addr);

		if (setsockopt(entry->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to join multicast group (error %d)", WSAGetLastError());
		}

		entry = slist_get_next(struct igmp_entry_t, entry);
	}
}

void igmp_manager_init(void)
{
}
