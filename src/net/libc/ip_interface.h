/*
 * ip_interface.h
 *
 * Copyright © 2015-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ip_interface_t {
	struct slist_prefix_t slist_prefix;
	uint32_t detect_hash;
	uint32_t ifindex;
	ip_addr_t ip_addr;
	ip_addr_t subnet_mask;
	bool notified_new;
};

extern void ip_interface_manager_redetect_required(void);

extern void ip_interface_manager_detect_execute(void);
extern void ip_interface_manager_detect_add(struct ip_interface_t *idi);
extern bool ip_interface_manager_detect_reactivate(uint32_t detech_hash);
