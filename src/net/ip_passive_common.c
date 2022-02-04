/*
 * ip_passive_common.c
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

THIS_FILE("ip_datalink");

struct ip_datalink_manager_t {
	struct slist_t active_list;
	struct slist_t inactive_list;
	ticks_t last_detect_time;
};

static struct ip_datalink_manager_t ip_datalink_manager;

ipv4_addr_t ip_datalink_get_ipaddr(struct ip_datalink_instance *idi)
{
	return idi->ip_addr;
}

ipv4_addr_t ip_datalink_get_subnet_mask(struct ip_datalink_instance *idi)
{
	return idi->subnet_mask;
}

ipv4_addr_t ip_datalink_get_subnet_broadcast(struct ip_datalink_instance *idi)
{
	ipv4_addr_t subnet_broadcast = idi->ip_addr | ~idi->subnet_mask;
	if (subnet_broadcast == idi->ip_addr) {
		return 0;
	}

	return subnet_broadcast;
}

void ip_datalink_manager_detect_add(struct ip_datalink_instance *idi)
{
	slist_attach_head(struct ip_datalink_instance, &ip_datalink_manager.active_list, idi);
}

bool ip_datalink_manager_detect_reactivate(uint32_t detect_hash)
{
	struct ip_datalink_instance **pprev = slist_get_phead(struct ip_datalink_instance, &ip_datalink_manager.inactive_list);
	struct ip_datalink_instance *p = slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.inactive_list);
	while (p) {
		if (p->detect_hash == detect_hash) {
			(void)slist_detach_pprev(struct ip_datalink_instance, pprev, p);
			slist_attach_tail(struct ip_datalink_instance, &ip_datalink_manager.active_list, p);
			return true;
		}

		pprev = slist_get_pnext(struct ip_datalink_instance, p);
		p = slist_get_next(struct ip_datalink_instance, p);
	}

	p = slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
	while (p) {
		if (p->detect_hash == detect_hash) {
			return true;
		}

		p = slist_get_next(struct ip_datalink_instance, p);
	}

	return false;
}

static void ip_datalink_manager_detect(void)
{
	/* move all active entries to inactive list */
	while (1) {
		struct ip_datalink_instance *idi = slist_detach_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
		if (!idi) {
			break;
		}

		slist_attach_head(struct ip_datalink_instance, &ip_datalink_manager.inactive_list, idi);
	}

	ip_datalink_manager_detect_execute();
	ip_datalink_manager.last_detect_time = timer_get_ticks();

	igmp_manager_local_ip_changed();
}

struct ip_datalink_instance *ip_datalink_manager_get_head(void)
{
	if (timer_get_ticks() >= ip_datalink_manager.last_detect_time + TICK_RATE * 5) {
		ip_datalink_manager_detect();
	}

	return slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
}

struct ip_datalink_instance *ip_datalink_manager_get_by_local_ip(ipv4_addr_t local_ip)
{
	if (timer_get_ticks() >= ip_datalink_manager.last_detect_time + TICK_RATE * 5) {
		ip_datalink_manager_detect();
	}

	struct ip_datalink_instance *idi = slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
	while (idi) {
		if (idi->ip_addr == local_ip) {
			return idi;
		}

		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	return NULL;
}

struct ip_datalink_instance *ip_datalink_manager_get_by_remote_ip(ipv4_addr_t remote_ip)
{
	if (timer_get_ticks() >= ip_datalink_manager.last_detect_time + TICK_RATE * 5) {
		ip_datalink_manager_detect();
	}

	struct ip_datalink_instance *idi = slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
	while (idi) {
		if (idi->subnet_mask == 0) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if ((idi->ip_addr & idi->subnet_mask) == (remote_ip & idi->subnet_mask)) {
			return idi;
		}

		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	return slist_get_head(struct ip_datalink_instance, &ip_datalink_manager.active_list);
}

void ip_datalink_manager_init(void)
{
	ip_datalink_manager_detect();
}
