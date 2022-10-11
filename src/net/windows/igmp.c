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
	ip_addr_t addr;
};

struct igmp_local_ip_t {
	struct slist_prefix_t slist_prefix;
	ip_addr_t addr;
	uint32_t ifindex;
	bool match_flag;
};

struct igmp_manager_t {
	struct slist_t igmp_ipv4_list;
	struct slist_t local_ipv4_list;

	struct slist_t igmp_ipv6_list;
	struct slist_t local_ipv6_list;
};

static struct igmp_manager_t igmp_manager;

static void igmp_manager_add_group_internal(struct igmp_entry_t *igmp_entry, struct igmp_local_ip_t *local_entry)
{
#if defined(IPV6_SUPPORT)
	if (ip_addr_is_ipv6(&igmp_entry->addr)) {
		struct ipv6_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		ip_addr_get_ipv6_bytes(&igmp_entry->addr, mreq.ipv6mr_multiaddr.s6_addr);
		mreq.ipv6mr_interface = (unsigned int)local_entry->ifindex;

		if (setsockopt(igmp_entry->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to join multicast group %V:%V (error %d)", &local_entry->addr, &igmp_entry->addr, WSAGetLastError());
		}

		return;
	}
#endif

	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = htonl(ip_addr_get_ipv4(&igmp_entry->addr));
	mreq.imr_interface.s_addr = htonl(ip_addr_get_ipv4(&local_entry->addr));

	if (setsockopt(igmp_entry->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
		DEBUG_ERROR("failed to join multicast group %V:%V (error %d)", &local_entry->addr, &igmp_entry->addr, WSAGetLastError());
	}
}

static void igmp_manager_leave_group_internal(struct igmp_entry_t *igmp_entry, struct igmp_local_ip_t *local_entry)
{
#if defined(IPV6_SUPPORT)
	if (ip_addr_is_ipv6(&igmp_entry->addr)) {
		struct ipv6_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		ip_addr_get_ipv6_bytes(&igmp_entry->addr, mreq.ipv6mr_multiaddr.s6_addr);
		mreq.ipv6mr_interface = (unsigned int)local_entry->ifindex;

		if (setsockopt(igmp_entry->sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, (char *)&mreq, sizeof(mreq)) < 0) {
			DEBUG_ERROR("failed to leave multicast group %V:%V (error %d)", &local_entry->addr, &igmp_entry->addr, WSAGetLastError());
		}

		return;
	}
#endif

	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = htonl(ip_addr_get_ipv4(&igmp_entry->addr));
	mreq.imr_interface.s_addr = htonl(ip_addr_get_ipv4(&local_entry->addr));

	if (setsockopt(igmp_entry->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
		DEBUG_ERROR("failed to leave multicast group %V:%V (error %d)", &local_entry->addr, &igmp_entry->addr, WSAGetLastError());
	}
}

static void igmp_manager_leave_group_free(struct igmp_entry_t *igmp_entry)
{
	bool ipv6 = ip_addr_is_ipv6(&igmp_entry->addr);
	struct slist_t *local_ip_list = (ipv6) ? &igmp_manager.local_ipv6_list : &igmp_manager.local_ipv4_list;

	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, local_ip_list);
	while (p) {
		igmp_manager_leave_group_internal(igmp_entry, p);
		p = slist_get_next(struct igmp_local_ip_t, p);
	}

	heap_free(igmp_entry);
}

static bool igmp_manager_leave_group_filter(struct igmp_entry_t *item, size_t index, void *state)
{
	struct igmp_entry_t *reference = (struct igmp_entry_t *)state;
	return ip_addr_cmp(&item->addr, &reference->addr) && (item->sock == reference->sock);
}

void igmp_manager_leave_group(struct udp_socket *us, const ip_addr_t *addr)
{
	if (!ip_addr_is_multicast(addr)) {
		DEBUG_ERROR("not multicast ip: %V", addr);
		return;
	}

	struct igmp_entry_t reference;
	reference.sock = us->sock;
	reference.addr = *addr;

	bool ipv6 = ip_addr_is_ipv6(addr);
	struct slist_t *igmp_ip_list = (ipv6) ? &igmp_manager.igmp_ipv6_list : &igmp_manager.igmp_ipv4_list;
	slist_clear_custom(struct igmp_entry_t, igmp_ip_list, &reference, igmp_manager_leave_group_filter, igmp_manager_leave_group_free);
}

void igmp_manager_join_group(struct udp_socket *us, const ip_addr_t *addr)
{
	if (!ip_addr_is_multicast(addr)) {
		DEBUG_ERROR("not multicast ip: %V", addr);
		return;
	}

	struct igmp_entry_t *igmp_entry = (struct igmp_entry_t *)heap_alloc_and_zero(sizeof(struct igmp_entry_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
	if (!igmp_entry) {
		DEBUG_ERROR("out of memory");
		return;
	}

	igmp_entry->sock = us->sock;
	igmp_entry->addr = *addr;

	bool ipv6 = ip_addr_is_ipv6(addr);
	struct slist_t *igmp_ip_list = (ipv6) ? &igmp_manager.igmp_ipv6_list : &igmp_manager.igmp_ipv4_list;
	slist_attach_head(struct igmp_entry_t, igmp_ip_list, igmp_entry);

	struct slist_t *local_ip_list = (ipv6) ? &igmp_manager.local_ipv6_list : &igmp_manager.local_ipv4_list;
	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, local_ip_list);
	while (p) {
		igmp_manager_add_group_internal(igmp_entry, p);
		p = slist_get_next(struct igmp_local_ip_t, p);
	}
}

static void igmp_manager_local_ip_changed_add_ip(struct igmp_local_ip_t *local_entry, struct slist_t *igmp_ip_list)
{
	DEBUG_INFO("adding %V", &local_entry->addr);

	struct igmp_entry_t *igmp_entry = slist_get_head(struct igmp_entry_t, igmp_ip_list);
	while (igmp_entry) {
		igmp_manager_add_group_internal(igmp_entry, local_entry);
		igmp_entry = slist_get_next(struct igmp_entry_t, igmp_entry);
	}
}

static void igmp_manager_local_ip_changed_del_ip(struct igmp_local_ip_t *local_entry, struct slist_t *igmp_ip_list)
{
	DEBUG_INFO("removing %V", &local_entry->addr);

	struct igmp_entry_t *igmp_entry = slist_get_head(struct igmp_entry_t, igmp_ip_list);
	while (igmp_entry) {
		igmp_manager_leave_group_internal(igmp_entry, local_entry);
		igmp_entry = slist_get_next(struct igmp_entry_t, igmp_entry);
	}
}

static void igmp_manager_local_ip_changed_ipv4(void)
{
	struct igmp_local_ip_t **pprev;
	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv4_list);
	while (p) {
		p->match_flag = false;
		p = slist_get_next(struct igmp_local_ip_t, p);
	}

	struct ip_interface_t *idi = ip_interface_manager_get_head();
	while (idi) {
		ip_addr_t local_ip;
		ip_interface_get_local_ip(idi, &local_ip);

		if (!ip_addr_is_ipv4(&local_ip)) {
			idi = slist_get_next(struct ip_interface_t, idi);
			continue;
		}

		uint32_t ifindex = ip_interface_get_ifindex(idi);

		pprev = slist_get_phead(struct igmp_local_ip_t, &igmp_manager.local_ipv4_list);
		p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv4_list);
		while (p) {
			if (ip_addr_cmp_greater_than_or_equal(&p->addr, &local_ip)) {
				if (ip_addr_cmp(&p->addr, &local_ip)) {
					p->match_flag = true;
				} else {
					p = NULL;
				}
				break;
			}

			pprev = slist_get_pnext(struct igmp_local_ip_t, p);
			p = slist_get_next(struct igmp_local_ip_t, p);
		}

		if (!p) {
			struct igmp_local_ip_t *newp = (struct igmp_local_ip_t *)heap_alloc_and_zero(sizeof(struct igmp_local_ip_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
			if (!newp) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}

			newp->addr = local_ip;
			newp->ifindex = ifindex;
			newp->match_flag = true;
			slist_insert_pprev(struct igmp_local_ip_t, pprev, newp);
			igmp_manager_local_ip_changed_add_ip(newp, &igmp_manager.igmp_ipv4_list);
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	pprev = slist_get_phead(struct igmp_local_ip_t, &igmp_manager.local_ipv4_list);
	p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv4_list);
	while (p) {
		if (p->match_flag) {
			pprev = slist_get_pnext(struct igmp_local_ip_t, p);
			p = slist_get_next(struct igmp_local_ip_t, p);
			continue;
		}

		igmp_manager_local_ip_changed_del_ip(p, &igmp_manager.igmp_ipv4_list);
		slist_detach_pprev(struct igmp_local_ip_t, pprev, p);
		heap_free(p);
		p = *pprev;
	}
}

static void igmp_manager_local_ip_changed_ipv6(void)
{
#if defined(IPV6_SUPPORT)
	struct igmp_local_ip_t **pprev;
	struct igmp_local_ip_t *p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv6_list);
	while (p) {
		p->match_flag = false;
		p = slist_get_next(struct igmp_local_ip_t, p);
	}

	struct ip_interface_t *idi = ip_interface_manager_get_head();
	while (idi) {
		ip_addr_t local_ip;
		ip_interface_get_local_ip(idi, &local_ip);

		if (!ip_addr_is_ipv6(&local_ip)) {
			idi = slist_get_next(struct ip_interface_t, idi);
			continue;
		}

		uint32_t ifindex = ip_interface_get_ifindex(idi);

		pprev = slist_get_phead(struct igmp_local_ip_t, &igmp_manager.local_ipv6_list);
		p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv6_list);
		while (p) {
			if (p->ifindex >= ifindex) {
				if (p->ifindex == ifindex) {
					p->match_flag = true;
				} else {
					p = NULL;
				}
				break;
			}

			pprev = slist_get_pnext(struct igmp_local_ip_t, p);
			p = slist_get_next(struct igmp_local_ip_t, p);
		}

		if (!p) {
			struct igmp_local_ip_t *newp = (struct igmp_local_ip_t *)heap_alloc_and_zero(sizeof(struct igmp_local_ip_t), PKG_OS, MEM_TYPE_OS_IGMP_ENTRY);
			if (!newp) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}

			newp->addr = local_ip;
			newp->ifindex = ifindex;
			newp->match_flag = true;
			slist_insert_pprev(struct igmp_local_ip_t, pprev, newp);
			igmp_manager_local_ip_changed_add_ip(newp, &igmp_manager.igmp_ipv6_list);
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	pprev = slist_get_phead(struct igmp_local_ip_t, &igmp_manager.local_ipv6_list);
	p = slist_get_head(struct igmp_local_ip_t, &igmp_manager.local_ipv6_list);
	while (p) {
		if (p->match_flag) {
			pprev = slist_get_pnext(struct igmp_local_ip_t, p);
			p = slist_get_next(struct igmp_local_ip_t, p);
			continue;
		}

		igmp_manager_local_ip_changed_del_ip(p, &igmp_manager.igmp_ipv6_list);
		slist_detach_pprev(struct igmp_local_ip_t, pprev, p);
		heap_free(p);
		p = *pprev;
	}
#endif
}

void igmp_manager_local_ip_changed(void)
{
	igmp_manager_local_ip_changed_ipv4();
	igmp_manager_local_ip_changed_ipv6();
}

void igmp_manager_start(void)
{
	igmp_manager_local_ip_changed_ipv4();
	igmp_manager_local_ip_changed_ipv6();
}

void igmp_manager_init(void)
{
}
