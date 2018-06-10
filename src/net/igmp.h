/*
 * igmp.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void igmp_manager_init(void);
extern void igmp_manager_network_start(void);
extern void igmp_manager_network_stop(void);
extern void igmp_manager_join_group(ipv4_addr_t addr);
