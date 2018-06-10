/*
 * ip_passive_common.h
 *
 * Copyright © 2015-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_datalink_instance {
	struct slist_prefix_t slist_prefix;
	uint32_t detect_hash;
	ipv4_addr_t ip_addr;
	ipv4_addr_t subnet_mask;
};

extern void ip_datalink_manager_detect_execute(void);
extern void ip_datalink_manager_detect_add(struct ip_datalink_instance *idi);
extern bool ip_datalink_manager_detect_reactivate(uint32_t detech_hash);
