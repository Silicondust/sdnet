/*
 * ip_interface.c
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

THIS_FILE("ip_interface");

struct ip_interface_manager_t {
	struct slist_t active_list;
	struct slist_t inactive_list;
	ticks_t last_detect_time;

	struct ip_interface_t localhost_ipv4;
	struct ip_interface_t localhost_ipv6;

	ip_interface_new_callback_t callback_new;
	ip_interface_lost_callback_t callback_lost;
	void *callback_arg;
};

static struct ip_interface_manager_t ip_interface_manager;

uint32_t ip_interface_get_ifindex(struct ip_interface_t *idi)
{
	return idi->ifindex;
}

#if defined(IPV6_SUPPORT)
uint32_t ip_interface_get_ipv6_scope_id(struct ip_interface_t *idi)
{
	if (ip_addr_is_ipv6_link_local(&idi->ip_addr)) {
		return idi->ifindex;
	}
	return 0;
}
#endif

void ip_interface_get_local_ip(struct ip_interface_t *idi, ip_addr_t *result)
{
	*result = idi->ip_addr;
}

void ip_interface_get_subnet_mask(struct ip_interface_t *idi, ip_addr_t *result)
{
	*result = idi->subnet_mask;
}

bool ip_interface_is_same_subnet(struct ip_interface_t *idi, const ip_addr_t *ip_addr)
{
	return ip_addr_cmp_subnet(ip_addr, &idi->ip_addr, &idi->subnet_mask);
}

bool ip_interface_is_ipv4_autoip_and_interface_has_ipv4_routable_ip(struct ip_interface_t *idi)
{
	if (!ip_addr_is_ipv4_autoip(&idi->ip_addr)) {
		return false;
	}

	struct ip_interface_t *list_idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (list_idi) {
		if ((list_idi->ifindex == idi->ifindex) && ip_addr_is_ipv4_routable(&list_idi->ip_addr)) {
			return true;
		}

		list_idi = slist_get_next(struct ip_interface_t, list_idi);
	}

	return false;
}

#if defined(IPV6_SUPPORT)
bool ip_interface_is_ipv6(struct ip_interface_t *idi)
{
	return ip_addr_is_ipv6(&idi->ip_addr);
}
#endif

#if defined(IPV6_SUPPORT)
bool ip_interface_is_ipv6_link_local(struct ip_interface_t *idi)
{
	return ip_addr_is_ipv6_link_local(&idi->ip_addr);
}
#endif

void ip_interface_manager_detect_add(struct ip_interface_t *idi)
{
	slist_attach_head(struct ip_interface_t, &ip_interface_manager.active_list, idi);
}

bool ip_interface_manager_detect_reactivate(uint32_t detect_hash)
{
	struct ip_interface_t **pprev = slist_get_phead(struct ip_interface_t, &ip_interface_manager.inactive_list);
	struct ip_interface_t *p = slist_get_head(struct ip_interface_t, &ip_interface_manager.inactive_list);
	while (p) {
		if (p->detect_hash == detect_hash) {
			(void)slist_detach_pprev(struct ip_interface_t, pprev, p);
			slist_attach_tail(struct ip_interface_t, &ip_interface_manager.active_list, p);
			return true;
		}

		pprev = slist_get_pnext(struct ip_interface_t, p);
		p = slist_get_next(struct ip_interface_t, p);
	}

	p = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (p) {
		if (p->detect_hash == detect_hash) {
			return true;
		}

		p = slist_get_next(struct ip_interface_t, p);
	}

	return false;
}

static void ip_interface_manager_detect(void)
{
	/* move all active entries to inactive list */
	while (1) {
		struct ip_interface_t *idi = slist_detach_head(struct ip_interface_t, &ip_interface_manager.active_list);
		if (!idi) {
			break;
		}

		slist_attach_head(struct ip_interface_t, &ip_interface_manager.inactive_list, idi);
	}

	ip_interface_manager_detect_execute();
	ip_interface_manager.last_detect_time = timer_get_ticks();

	struct ip_interface_t *p = slist_get_head(struct ip_interface_t, &ip_interface_manager.inactive_list);
	while (p) {
		if (!p->notified_new) {
			p = slist_get_next(struct ip_interface_t, p);
			continue;
		}

		p->notified_new = false;

		if (ip_interface_manager.callback_lost) {
			ip_interface_manager.callback_lost(ip_interface_manager.callback_arg, p);
		}

		p = slist_get_next(struct ip_interface_t, p);
	}

	p = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (p) {
		if (p->notified_new) {
			p = slist_get_next(struct ip_interface_t, p);
			continue;
		}

		p->notified_new = true;

		if (ip_interface_manager.callback_new) {
			ip_interface_manager.callback_new(ip_interface_manager.callback_arg, p);
		}

		p = slist_get_next(struct ip_interface_t, p);
	}

	igmp_manager_local_ip_changed();
}

bool ip_interface_manager_has_routable_ipv4(void)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (ip_addr_is_ipv4_routable(&idi->ip_addr)) {
			return true;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	return false;
}

#if defined(IPV6_SUPPORT)
bool ip_interface_manager_has_public_ipv6(void)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (ip_addr_is_ipv6_public(&idi->ip_addr)) {
			return true;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	return false;
}
#endif

struct ip_interface_t *ip_interface_manager_get_head(void)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

	return slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
}

struct ip_interface_t *ip_interface_manager_get_by_local_ip(const ip_addr_t *local_ip, uint32_t ipv6_scope_id)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

#if defined(IPV6_SUPPORT)
	if (ipv6_scope_id != 0) {
		if (!ip_addr_is_ipv6_link_local(local_ip)) {
			DEBUG_ERROR("invalid lookup configuration");
			return NULL;
		}

		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (ip_addr_cmp(&idi->ip_addr, local_ip) && (ip_interface_get_ipv6_scope_id(idi) == ipv6_scope_id)) {
				return idi;
			}

			idi = slist_get_next(struct ip_interface_t, idi);
		}

		return NULL;
	}

	if (ip_addr_is_ipv6_localhost(local_ip)) {
		return &ip_interface_manager.localhost_ipv6;
	}
#endif

	if (ip_addr_cmp(local_ip, &ip_interface_manager.localhost_ipv4.ip_addr)) {
		return &ip_interface_manager.localhost_ipv4;
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (ip_addr_cmp(&idi->ip_addr, local_ip)) {
			return idi;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}
	
	return NULL;
}

struct ip_interface_t *ip_interface_manager_get_by_remote_ip(const ip_addr_t *remote_ip, uint32_t ipv6_scope_id)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

#if defined(IPV6_SUPPORT)
	if (ipv6_scope_id != 0) {
		if (!ip_addr_is_ipv6_link_local(remote_ip) && !ip_addr_is_ipv6_multicast(remote_ip)) {
			DEBUG_ERROR("invalid lookup configuration");
			return NULL;
		}
			
		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (ip_addr_is_ipv6_link_local(&idi->ip_addr) && (ip_interface_get_ipv6_scope_id(idi) == ipv6_scope_id)) {
				return idi;
			}

			idi = slist_get_next(struct ip_interface_t, idi);
		}

		return NULL;
	}

	if (ip_addr_is_ipv6_link_local(remote_ip)) {
		DEBUG_WARN("link-local ip without scope-id");

		struct ip_interface_t *link_local_idi = NULL;
		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (!ip_interface_is_ipv6_link_local(idi)) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}

			if (link_local_idi) {
				return NULL; /* multiple link-local interfaces */
			}

			link_local_idi = idi;
			idi = slist_get_next(struct ip_interface_t, idi);
		}

		return link_local_idi;
	}

	if (ip_addr_is_ipv6_localhost(remote_ip)) {
		return &ip_interface_manager.localhost_ipv6;
	}
#endif

	if (ip_addr_cmp_subnet(remote_ip, &ip_interface_manager.localhost_ipv4.ip_addr, &ip_interface_manager.localhost_ipv4.subnet_mask)) {
		return &ip_interface_manager.localhost_ipv4;
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (ip_addr_cmp_subnet(remote_ip, &idi->ip_addr, &idi->subnet_mask)) {
			return idi;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	if (!ip_addr_is_routable(remote_ip) && !ip_addr_is_multicast(remote_ip) && !ip_addr_is_ipv4_broadcast(remote_ip)) {
		return NULL;
	}

	bool ipv6 = ip_addr_is_ipv6(remote_ip);
	idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if ((ip_addr_is_ipv6(&idi->ip_addr) == ipv6) && ip_addr_is_routable(&idi->ip_addr)) {
			return idi;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	return NULL;
}

void ip_interface_manager_get_local_ip_for_remote_ip(const ip_addr_t *remote_ip, uint32_t ipv6_scope_id, ip_addr_t *result)
{
	struct ip_interface_t *idi = ip_interface_manager_get_by_remote_ip(remote_ip, ipv6_scope_id);
	if (!idi) {
		ip_addr_set_zero(result);
		return;
	}

	ip_interface_get_local_ip(idi, result);
}

void ip_interface_manager_redetect_required(void)
{
	ip_interface_manager.last_detect_time = 0;
}

void ip_interface_manager_register_callbacks(ip_interface_new_callback_t callback_new, ip_interface_lost_callback_t callback_lost, void *callback_arg, bool trigger_now)
{
	ip_interface_manager.callback_new = callback_new;
	ip_interface_manager.callback_lost = callback_lost;
	ip_interface_manager.callback_arg = callback_arg;

	if (!trigger_now || !callback_new) {
		return;
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		callback_new(callback_arg, idi);
		idi = slist_get_next(struct ip_interface_t, idi);
	}
}

void ip_interface_manager_init(void)
{
	ip_addr_set_ipv4(&ip_interface_manager.localhost_ipv4.ip_addr, 0x7F000001);
	ip_addr_set_subnet_mask_from_cidr(&ip_interface_manager.localhost_ipv4.subnet_mask, &ip_interface_manager.localhost_ipv4.ip_addr, 8);

#if defined(IPV6_SUPPORT)
	ip_addr_t localhost_ipv6 = IP_ADDR_INIT_IPV6(0, 0, 0, 0, 0, 0, 0, 1);
	ip_interface_manager.localhost_ipv6.ip_addr = localhost_ipv6;
	ip_addr_set_subnet_mask_from_cidr(&ip_interface_manager.localhost_ipv6.subnet_mask, &ip_interface_manager.localhost_ipv6.ip_addr, 128);
#endif

	ip_interface_manager_detect();
}
