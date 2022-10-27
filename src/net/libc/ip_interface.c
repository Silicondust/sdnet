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
	if (ip_addr_is_ipv6_linklocal(&idi->ip_addr)) {
		return idi->ifindex;
	}
	return 0;
}
#endif

uint8_t ip_interface_get_ip_score(struct ip_interface_t *idi)
{
	return idi->ip_score;
}

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

#if defined(IPV6_SUPPORT)
bool ip_interface_is_ipv6(struct ip_interface_t *idi)
{
	return ip_addr_is_ipv6(&idi->ip_addr);
}
#endif

#if defined(IPV6_SUPPORT)
bool ip_interface_is_ipv6_linklocal(struct ip_interface_t *idi)
{
	return ip_addr_is_ipv6_linklocal(&idi->ip_addr);
}
#endif

void ip_interface_manager_detect_add(struct ip_interface_t *idi)
{
	struct ip_interface_t **pprev = slist_get_phead(struct ip_interface_t, &ip_interface_manager.active_list);
	struct ip_interface_t *p = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (p) {
		if (p->ifindex < idi->ifindex) {
			pprev = slist_get_pnext(struct ip_interface_t, p);
			p = slist_get_next(struct ip_interface_t, p);
			continue;
		}
		if (p->ifindex > idi->ifindex) {
			break;
		}

		if (p->ip_score < idi->ip_score) {
			pprev = slist_get_pnext(struct ip_interface_t, p);
			p = slist_get_next(struct ip_interface_t, p);
			continue;
		}
		if (p->ip_score > idi->ip_score) {
			break;
		}

		if (ip_addr_cmp_less_than(&p->ip_addr, &idi->ip_addr)) {
			pprev = slist_get_pnext(struct ip_interface_t, p);
			p = slist_get_next(struct ip_interface_t, p);
			continue;
		}

		break;
	}

	slist_insert_pprev(struct ip_interface_t, pprev, idi);
}

bool ip_interface_manager_detect_reactivate(uint32_t detect_hash)
{
	struct ip_interface_t **pprev = slist_get_phead(struct ip_interface_t, &ip_interface_manager.inactive_list);
	struct ip_interface_t *p = slist_get_head(struct ip_interface_t, &ip_interface_manager.inactive_list);
	while (p) {
		if (p->detect_hash == detect_hash) {
			(void)slist_detach_pprev(struct ip_interface_t, pprev, p);
			ip_interface_manager_detect_add(p);
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

struct ip_interface_t *ip_interface_manager_get_by_ifindex_best_ipv6(uint32_t ifindex)
{
#if defined(IPV6_SUPPORT)
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (idi->ifindex < ifindex) {
			idi = slist_get_next(struct ip_interface_t, idi);
			continue;
		}
		if (idi->ifindex > ifindex) {
			return NULL;
		}

		if (ip_addr_is_ipv6(&idi->ip_addr)) {
			return idi;
		}
		
		idi = slist_get_next(struct ip_interface_t, idi);
	}
#endif

	return NULL;
}

struct ip_interface_t *ip_interface_manager_get_by_ifindex_best_ipv4(uint32_t ifindex)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

	struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (idi->ifindex < ifindex) {
			idi = slist_get_next(struct ip_interface_t, idi);
			continue;
		}
		if (idi->ifindex > ifindex) {
			return NULL;
		}

		if (ip_addr_is_ipv4(&idi->ip_addr)) {
			return idi;
		}
		
		idi = slist_get_next(struct ip_interface_t, idi);
	}

	return NULL;
}

struct ip_interface_t *ip_interface_manager_get_by_local_ip(const ip_addr_t *local_ip, uint32_t ipv6_scope_id)
{
	if (timer_get_ticks() >= ip_interface_manager.last_detect_time + TICK_RATE * 5) {
		ip_interface_manager_detect();
	}

#if defined(IPV6_SUPPORT)
	if (ipv6_scope_id != 0) {
		if (!ip_addr_is_ipv6_linklocal(local_ip)) {
			DEBUG_ERROR("invalid lookup configuration");
			return NULL;
		}

		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (idi->ifindex < ipv6_scope_id) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}
			if (idi->ifindex > ipv6_scope_id) {
				return NULL;
			}

			if (ip_addr_cmp(&idi->ip_addr, local_ip)) {
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
		if (!ip_addr_is_ipv6_linklocal_or_multicast_linklocal(remote_ip)) {
			DEBUG_ERROR("invalid lookup configuration");
			return NULL;
		}
			
		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (idi->ifindex < ipv6_scope_id) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}
			if (idi->ifindex > ipv6_scope_id) {
				return NULL;
			}

			if (ip_addr_is_ipv6_linklocal(&idi->ip_addr)) {
				return idi;
			}

			idi = slist_get_next(struct ip_interface_t, idi);
		}

		return NULL;
	}

	if (ip_addr_is_ipv6_linklocal(remote_ip)) {
		DEBUG_WARN("linklocal ip without scope-id");

		struct ip_interface_t *linklocal_idi = NULL;
		struct ip_interface_t *idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
		while (idi) {
			if (!ip_interface_is_ipv6_linklocal(idi)) {
				idi = slist_get_next(struct ip_interface_t, idi);
				continue;
			}

			if (linklocal_idi) {
				return NULL; /* multiple link-local interfaces */
			}

			linklocal_idi = idi;
			idi = slist_get_next(struct ip_interface_t, idi);
		}

		return linklocal_idi;
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

	bool ipv6 = ip_addr_is_ipv6(remote_ip);
	struct ip_interface_t *best_idi = NULL;

	idi = slist_get_head(struct ip_interface_t, &ip_interface_manager.active_list);
	while (idi) {
		if (ip_addr_is_ipv6(&idi->ip_addr) != ipv6) {
			idi = slist_get_next(struct ip_interface_t, idi);
			continue;
		}

		if (!best_idi || (idi->ip_score < best_idi->ip_score)) { /* lower is better */
			best_idi = idi;
		}

		idi = slist_get_next(struct ip_interface_t, idi);
	}

	if (!best_idi) {
		return NULL;
	}

	if (ip_addr_is_routable(remote_ip) && ip_addr_is_routable(&best_idi->ip_addr)) {
		return best_idi;
	}

	if (ip_addr_is_multicast(remote_ip) || ip_addr_is_ipv4_broadcast(remote_ip)) {
		return best_idi;
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
	struct ip_interface_t *localhost_ipv4 = &ip_interface_manager.localhost_ipv4;
	localhost_ipv4->ip_addr = ip_addr_ipv4_localhost;
	localhost_ipv4->ip_score = ip_addr_compute_score(&localhost_ipv4->ip_addr);
	ip_addr_set_subnet_mask_from_cidr(&localhost_ipv4->subnet_mask, &localhost_ipv4->ip_addr, 8);

#if defined(IPV6_SUPPORT)
	struct ip_interface_t *localhost_ipv6 = &ip_interface_manager.localhost_ipv6;
	localhost_ipv6->ip_addr = ip_addr_ipv6_localhost;
	localhost_ipv6->ip_score = ip_addr_compute_score(&localhost_ipv6->ip_addr);
	ip_addr_set_subnet_mask_from_cidr(&localhost_ipv6->subnet_mask, &localhost_ipv6->ip_addr, 128);
#endif

	ip_interface_manager_detect();
}
