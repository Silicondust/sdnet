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

struct igmp_local_ip_t {
	struct slist_prefix_t slist_prefix;
	ipv4_addr_t addr;
};

struct igmp_manager_t {
	struct slist_t igmp_ip_list;
	struct slist_t local_ip_list;
};

static struct igmp_manager_t igmp_manager;

void igmp_manager_join_group(struct udp_socket *us, ipv4_addr_t addr)
{
	if (!ip_addr_is_multicast(addr)) {
		DEBUG_ERROR("not multicast ip: %v", addr);
		return;
	}

	struct igmp_entry_t *igmp_entry = (struct igmp_entry_t *)heap_alloc_and_zero(sizeof(struct igmp_entry_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
	if (!igmp_entry) {
		DEBUG_ERROR("out of memory");
		return;
	}

	igmp_entry->sock = us->sock;
	igmp_entry->addr = addr;

	slist_attach_head(struct igmp_entry_t, &igmp_manager.igmp_ip_list, igmp_entry);

	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ip_list);
	while (p) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(igmp_entry->addr);
		mreq.imr_interface.s_addr = htonl(p->addr);

		if (setsockopt(igmp_entry->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to join multicast group %v:%v (error %d %s)", p->addr, igmp_entry->addr, errno, strerror(errno));
		}

		p = slist_get_next(struct igmp_local_ip_t, p);
	}
}

static void igmp_manager_local_ip_changed_add_ip(ipv4_addr_t local_ip)
{
	DEBUG_INFO("adding %v", local_ip);

	struct igmp_entry_t *igmp_entry = slist_get_head(struct igmp_entry_t, &igmp_manager.igmp_ip_list);
	while (igmp_entry) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(igmp_entry->addr);
		mreq.imr_interface.s_addr = htonl(local_ip);

		if (setsockopt(igmp_entry->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to join multicast group %v:%v (error %d %s)", local_ip, igmp_entry->addr, errno, strerror(errno));
		}

		igmp_entry = slist_get_next(struct igmp_entry_t, igmp_entry);
	}
}

static void igmp_manager_local_ip_changed_del_ip(ipv4_addr_t local_ip)
{
	DEBUG_INFO("removing %v", local_ip);

	struct igmp_entry_t *igmp_entry = slist_get_head(struct igmp_entry_t, &igmp_manager.igmp_ip_list);
	while (igmp_entry) {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = htonl(igmp_entry->addr);
		mreq.imr_interface.s_addr = htonl(local_ip);

		if (setsockopt(igmp_entry->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to leave multicast group %v:%v (error %d %s)", local_ip, igmp_entry->addr, errno, strerror(errno));
		}

		igmp_entry = slist_get_next(struct igmp_entry_t, igmp_entry);
	}
}

void igmp_manager_local_ip_changed(void)
{
	struct ip_datalink_instance *idi = ip_datalink_manager_get_head();
	struct igmp_local_ip_t **pprev = slist_get_phead(struct igmp_local_ip_t, &igmp_manager.local_ip_list);
	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ip_list);
	while (idi) {
		ipv4_addr_t local_ip = ip_datalink_get_ipaddr(idi);
		if (!ip_addr_is_unicast(local_ip) || ip_addr_is_localhost(local_ip)) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		while (p && (p->addr < local_ip)) {
			igmp_manager_local_ip_changed_del_ip(p->addr);
			slist_detach_pprev(struct igmp_local_ip_t, pprev, p);
			heap_free(p);
			p = *pprev;
		}

		if (p && (p->addr == local_ip)) {
			pprev = slist_get_pnext(struct igmp_local_ip_t, p);
			p = slist_get_next(struct igmp_local_ip_t, p);
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		struct igmp_local_ip_t *newp = (struct igmp_local_ip_t *)heap_alloc_and_zero(sizeof(struct igmp_local_ip_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
		if (!newp) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		newp->addr = local_ip;
		slist_insert_pprev(struct igmp_local_ip_t, pprev, newp);
		igmp_manager_local_ip_changed_add_ip(newp->addr);

		pprev = slist_get_pnext(struct igmp_local_ip_t, newp);
		p = slist_get_next(struct igmp_local_ip_t, newp);
		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	while (p) {
		igmp_manager_local_ip_changed_del_ip(p->addr);
		slist_detach_pprev(struct igmp_local_ip_t, pprev, p);
		heap_free(p);
		p = *pprev;
	}
}

void igmp_manager_start(void)
{
	igmp_manager_local_ip_changed();
}

void igmp_manager_init(void)
{
}
