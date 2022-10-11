/*
 * igmp.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct udp_socket;

extern void igmp_manager_init(void);
extern void igmp_manager_start(void);
extern void igmp_manager_local_ip_changed(void);
extern void igmp_manager_join_group(struct udp_socket *us, const ip_addr_t *addr);
extern void igmp_manager_leave_group(struct udp_socket *us, const ip_addr_t *addr);
