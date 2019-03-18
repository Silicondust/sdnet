/*
 * udp.h
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define UDP_TTL_DEFAULT 64
#define UDP_TOS_DEFAULT 0x00
#define UDP_TOS_VIDEO (5 << 5)

#define UDP_OK 0
#define UDP_ERROR_FAILED -1
#define UDP_ERROR_SOCKET_BUSY -2

struct udp_socket;

typedef int8_t udp_error_t;
typedef void (*udp_recv_callback_t)(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb);
typedef void (*udp_recv_icmp_callback_t)(void *inst, ipv4_addr_t icmp_src_addr, uint8_t icmp_type, ipv4_addr_t dest_addr, uint16_t dest_port);

extern struct udp_socket *udp_socket_alloc(void);
extern void udp_socket_set_recv_netbuf_size(struct udp_socket *us, size_t recv_netbuf_size);
extern udp_error_t udp_socket_listen(struct udp_socket *us, struct ip_datalink_instance *link, ipv4_addr_t addr, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst);
extern void udp_socket_set_icmp_callback(struct udp_socket *us, udp_recv_icmp_callback_t recv_icmp);
extern udp_error_t udp_socket_send_netbuf(struct udp_socket *us, ipv4_addr_t dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb);
extern uint16_t udp_socket_get_port(struct udp_socket *us);

extern void udp_manager_init(void);
extern void udp_manager_start(void);
