/*
 * udp_dhcp.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("udp_dhcp");

static int udp_dhcp_sock_raw = -1;

static uint16_t udp_dhcp_socket_checksum(void *addr, int count)
{
	uint32_t sum;
	uint16_t *ptr;

	for (sum = 0, ptr = (uint16_t *)addr; count > 1; count -= 2) {
		sum += *ptr++;
	}

	if (count > 0) {
		uint16_t tmp = 0;
		*(uint8_t*)&tmp = *(uint8_t*)ptr;
		sum += tmp;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

udp_error_t udp_dhcp_socket_send_netbuf(struct udp_socket *us, struct ip_managed_t *ipm, const ip_addr_t *dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	DEBUG_ASSERT(ipm, "no ipm");

	uint16_t src_port = us->port;

	ip_addr_t local_ip;
	ip_managed_get_local_ip(ipm, &local_ip);
	if (ip_addr_is_non_zero(&local_ip)) {
		return udp_socket_send_netbuf(us, dest_addr, dest_port, 0, ttl, tos, nb);
	}

	if (!ip_addr_is_ipv4_broadcast(dest_addr)) {
		DEBUG_ERROR("no local ip and not broadcast packet");
		return UDP_ERROR_FAILED;
	}

	if (udp_dhcp_sock_raw == -1) {
		DEBUG_ERROR("no raw socket");
		return UDP_ERROR_FAILED;
	}

	DEBUG_INFO("send raw %V:%u -> %V:%u", &ip_addr_zero, src_port, dest_addr, dest_port);

	struct sockaddr_ll sock_sll;
	sock_sll.sll_family = AF_PACKET;
	sock_sll.sll_protocol = htons(ETH_P_IP);
	sock_sll.sll_ifindex = ip_managed_get_ifindex(ipm);

	uint8_t dest_mac[6] = { [0 ... 5] = 0xff };
	memcpy(sock_sll.sll_addr, &dest_mac, 6);
	sock_sll.sll_halen = 6;

	int length = (int)netbuf_get_remaining(nb);

	struct ip_udp_t {
		struct iphdr ip;
		struct udphdr udp;
	} __attribute__((packed)) *packet;

	if (!netbuf_rev_make_space(nb, sizeof(struct ip_udp_t))) {
		DEBUG_ERROR("netbuf_rev_make_space failed");
		return UDP_ERROR_FAILED;
	}

	netbuf_set_pos_to_start(nb);
	packet = (struct ip_udp_t *)netbuf_get_ptr(nb);

	DEBUG_ASSERT(((addr_t)packet & 3) == 0, "unaligned netbuf not yet supported");

	memset(packet, 0, sizeof(struct ip_udp_t));

	packet->ip.protocol = IPPROTO_UDP;
	packet->ip.saddr = htonl(0);
	packet->ip.daddr = htonl(ip_addr_get_ipv4(dest_addr));
	packet->udp.source = htons(src_port);
	packet->udp.dest = htons(dest_port);

	length += sizeof(packet->udp);
	packet->udp.len = htons(length);
	packet->ip.tot_len = packet->udp.len;

	length += sizeof(packet->ip);
	packet->udp.check = udp_dhcp_socket_checksum(&packet->ip, length);
	packet->ip.version = IPVERSION;
	packet->ip.ihl = (sizeof(packet->ip) >> 2);
	packet->ip.tot_len = htons(length);
	packet->ip.frag_off = htons(0x4000);
	packet->ip.ttl = ttl;
	packet->ip.check = udp_dhcp_socket_checksum(&packet->ip, sizeof(packet->ip));

	int ret = sendto(udp_dhcp_sock_raw, packet, length, 0, (struct sockaddr *) &sock_sll, sizeof(sock_sll));
	if (ret != length) {
		DEBUG_INFO("udp send failed (%d)", errno);
		return UDP_ERROR_FAILED;
	}

	return UDP_OK;
}

udp_error_t udp_dhcp_socket_listen(struct udp_socket *us, struct ip_managed_t *ipm, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst)
{
	DEBUG_ASSERT(ipm, "no ipm");
	udp_socket_allow_ipv4_broadcast(us);

	const char *interface_name = ip_managed_get_interface_name(ipm);
	if (setsockopt(us->sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name) + 1) < 0) {
		DEBUG_WARN("setsockopt SO_BINDTODEVICE error %d", errno);
	}

	return udp_socket_listen(us, port, recv, recv_icmp, inst);
}

struct udp_socket *udp_dhcp_socket_alloc(void)
{
	return udp_socket_alloc(IP_MODE_IPV4);
}

void udp_dhcp_manager_init(void)
{
	errno = 0; /* workaround Abilis bug */
	udp_dhcp_sock_raw = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (udp_dhcp_sock_raw == -1) {
		DEBUG_ERROR("failed to allocate raw socket (%d)", errno);
	}
}
