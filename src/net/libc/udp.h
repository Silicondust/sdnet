/*
 * ./src/net/libc/udp.h
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct udp_socket {
	struct udp_socket *next;
	struct ip_datalink_instance *link;
	int sock;
	uint16_t port;
	uint8_t ttl_set;
	uint8_t tos_set;
	udp_recv_callback_t recv_callback;
	volatile udp_recv_icmp_callback_t recv_icmp_callback;
	void *callback_inst;
};

extern void udp_set_sock_send_buffer_size(int sock, size_t size);
