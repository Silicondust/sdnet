/*
 * ntp_server.c
 *
 * Copyright © 2012-2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ntp_server");

#define NTP_PORT 123

struct dns_respodnder_transport_t {
	struct udp_socket *sock;
};

struct ntp_server_t {
	struct dns_respodnder_transport_t ipv4;
	struct dns_respodnder_transport_t ipv6;
};

static struct ntp_server_t ntp_server;

static void ntp_server_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	struct dns_respodnder_transport_t *transport = (struct dns_respodnder_transport_t *)inst;

	if (!netbuf_fwd_check_space(nb, 48)) {
		DEBUG_WARN("short packet");
		return;
	}

	uint8_t flags = netbuf_fwd_read_u8(nb);

	uint8_t version = (flags >> 3) & 0x07;
	if ((version != 3) && (version != 4)) {
		DEBUG_WARN("unsupported version (version=%u)", version);
		return;
	}

	uint8_t mode = flags & 0x07;
	if (mode != 3) {
		DEBUG_WARN("not a client request (mode=%u)", mode);
		return;
	}

	netbuf_advance_pos(nb, 39);
	uint64_t rx_transmit_time_ntp = netbuf_fwd_read_u64(nb);

	time64_t current_time_unix = unix_time();
	if (current_time_unix < UNIX_TIME_MIN_VALID) {
		return;
	}

	struct netbuf *txnb = netbuf_alloc_with_rev_space(48);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	uint64_t current_time_ntp_sec = current_time_unix + 2208988800ULL;
	uint64_t originate_time_ntp = rx_transmit_time_ntp;

	time64_t last_set_time_unix = unix_time_last_set();
	uint64_t last_set_time_ntp_sec = (last_set_time_unix) ? last_set_time_unix + 2208988800ULL : 0;

	netbuf_rev_write_u64(txnb, current_time_ntp_sec << 32); /* transmit timestamp */
	netbuf_rev_write_u64(txnb, current_time_ntp_sec << 32); /* receive timestamp */
	netbuf_rev_write_u64(txnb, originate_time_ntp); /* originate timestamp */
	netbuf_rev_write_u64(txnb, last_set_time_ntp_sec << 32); /* reference timestamp */
	netbuf_rev_write_u32(txnb, 0); /* reference id */
	netbuf_rev_write_u32(txnb, 0); /* root dispersion */
	netbuf_rev_write_u32(txnb, 0); /* root delay */
	netbuf_rev_write_u8(txnb, 0); /* clock precision = 2^0 = 1 second */
	netbuf_rev_write_u8(txnb, 17); /* peer pooling interval = 2^17 seconds = 36.4 hours */
	netbuf_rev_write_u8(txnb, 3); /* peer clock stratum */
	netbuf_rev_write_u8(txnb, (version << 3) | 4); /* flags */

	udp_socket_send_netbuf(transport->sock, src_addr, src_port, ipv6_scope_id, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);

	netbuf_free(txnb);
}

void ntp_server_init(void)
{
	ntp_server.ipv4.sock = udp_socket_alloc(IP_MODE_IPV4);
	udp_socket_listen(ntp_server.ipv4.sock, NTP_PORT, ntp_server_recv, NULL, &ntp_server.ipv4);

#if defined(IPV6_SUPPORT)
	ntp_server.ipv6.sock = udp_socket_alloc(IP_MODE_IPV6);
	udp_socket_listen(ntp_server.ipv6.sock, NTP_PORT, ntp_server_recv, NULL, &ntp_server.ipv6);
#endif
}
