/*
 * dns_lookup_udp.c
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/dns_lookup_internal.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("dns_lookup_udp");

#define DNS_SERVER_PORT 53

static void dns_manager_udp_recv(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb)
{
	if (src_port != DNS_SERVER_PORT) {
		DEBUG_WARN("unexpected server port");
		return;
	}

	dns_manager_recv_common(nb);
}

void dns_entry_send_request(struct dns_entry_t *dns_entry)
{
	uint8_t dns_ip_index = dns_entry_get_dns_ip_index(dns_entry);
	if (dns_ip_index == 0xFF) {
		return;
	}

	ipv4_addr_t dns_ip = dns_manager.dns_ip[dns_ip_index];
	if (dns_ip == 0) {
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	struct netbuf *txnb = dns_manager_generate_request_nb(dns_entry);
	if (!txnb) {
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	DEBUG_INFO("sending DNS request for %s", dns_entry->name);
	dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_SENT);

	if (udp_socket_send_netbuf(dns_manager.udp_sock, dns_ip, DNS_SERVER_PORT, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb) != UDP_OK) {
		netbuf_free(txnb);
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	netbuf_free(txnb);
}

void dns_manager_init(void)
{
	dns_manager_init_common();

	dns_manager.udp_sock = udp_socket_alloc();
	if (!dns_manager.udp_sock) {
		DEBUG_ASSERT(0, "out of memory");
		return;
	}

	udp_socket_listen(dns_manager.udp_sock, 0, 0, dns_manager_udp_recv, NULL, NULL);
}
