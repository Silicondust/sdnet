/*
 * udp_dhcp.h
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


extern struct udp_socket *udp_dhcp_socket_alloc(void);
extern udp_error_t udp_dhcp_socket_listen(struct udp_socket *us, struct ip_managed_t *ipm, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst);
extern udp_error_t udp_dhcp_socket_send_netbuf(struct udp_socket *us, struct ip_managed_t *ipm, const ip_addr_t *dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb);

extern void udp_dhcp_manager_init(void);
