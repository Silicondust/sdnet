/*
 * dhcp_usbd.h
 *
 * Copyright © 2010,2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void dhcp_usbd_init(uint8_t host_mac_addr[6], ipv4_addr_t host_ip_addr, ipv4_addr_t device_ip_addr, ipv4_addr_t subnet_mask);
