/*
 * dns_lookup_tls.c
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

THIS_FILE("dns_lookup_tls");

#define DNS_SERVER_PORT 853

static void dns_manager_tls_close(struct dns_manager_tls_t *dns_tls)
{
	slist_detach_item(struct dns_manager_tls_t, &dns_manager.tls_list, dns_tls);

	if (dns_tls->recv_nb) {
		netbuf_free(dns_tls->recv_nb);
		dns_tls->recv_nb = NULL;
	}

	if (dns_tls->tls_conn) {
		tls_client_connection_close(dns_tls->tls_conn);
		tls_client_connection_deref(dns_tls->tls_conn);
		dns_tls->tls_conn = NULL;
	}

	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		uint8_t dns_ip_index = dns_tls->dns_ip_index;
		uint8_t connection_state = dns_entry->connection_state[dns_ip_index];

		if ((connection_state == DNS_ENTRY_CONNECTION_STATE_COMPLETE) || (connection_state == DNS_ENTRY_CONNECTION_STATE_ERROR)) {
			dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
			continue;
		}

		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
	}

	heap_free(dns_tls);
}

static void dns_manager_tls_close_callback(void *arg, tcp_close_reason_t reason)
{
	struct dns_manager_tls_t *dns_tls = (struct dns_manager_tls_t *)arg;

	tls_client_connection_deref(dns_tls->tls_conn);
	dns_tls->tls_conn = NULL;

	dns_manager_tls_close(dns_tls);
}

static void dns_manager_tls_recv_callback(void *arg, struct netbuf *nb)
{
	struct dns_manager_tls_t *dns_tls = (struct dns_manager_tls_t *)arg;

	if (dns_tls->recv_nb) {
		netbuf_set_pos_to_start(dns_tls->recv_nb);
		size_t prepend = netbuf_get_remaining(dns_tls->recv_nb);

		if (!netbuf_rev_make_space(nb, prepend)) {
			DEBUG_ERROR("out of memory");
			dns_manager_tls_close(dns_tls);
			return;
		}

		netbuf_rev_copy(nb, dns_tls->recv_nb, prepend);

		netbuf_free(dns_tls->recv_nb);
		dns_tls->recv_nb = NULL;
	}

	while (1) {
		if (!netbuf_fwd_check_space(nb, 2)) {
			break;
		}

		size_t length = netbuf_fwd_read_u16(nb);
		if (length < 12) {
			DEBUG_WARN("under-length dns response");
			dns_manager_tls_close(dns_tls);
			return;
		}
		if (length > 4096) {
			DEBUG_WARN("over-length dns response");
			dns_manager_tls_close(dns_tls);
			return;
		}

		size_t remain = netbuf_get_remaining(nb);
		if (remain < length) {
			netbuf_retreat_pos(nb, 2);
			break;
		}

		if (remain == length) {
			netbuf_set_start_to_pos(nb);
			dns_manager_recv_common(nb);
			return;
		}

		struct netbuf *nb_frame = netbuf_alloc_with_rev_space(length);
		if (!nb_frame) {
			DEBUG_ERROR("out of memory");
			dns_manager_tls_close(dns_tls);
			return;
		}

		netbuf_rev_copy(nb_frame, nb, length);
		dns_manager_recv_common(nb_frame);
		netbuf_free(nb_frame);
	}

	size_t remain = netbuf_get_remaining(nb);
	dns_tls->recv_nb = netbuf_alloc_with_fwd_space(remain);
	if (!dns_tls->recv_nb) {
		DEBUG_ERROR("out of memory");
		dns_manager_tls_close(dns_tls);
		return;
	}

	netbuf_fwd_copy(dns_tls->recv_nb, nb, remain);
}

static void dns_entry_send_request_internal(struct dns_entry_t *dns_entry, struct dns_manager_tls_t *dns_tls)
{
	uint8_t dns_ip_index = dns_tls->dns_ip_index;

	if (dns_tls->tls_state == DNS_TLS_CONNECTION_STATE_CONNECTING) {
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_CONNECTING);
		return;
	}

	struct netbuf *txnb = dns_manager_generate_request_nb(dns_entry);
	if (!txnb) {
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	DEBUG_INFO("sending DNS request for %s", dns_entry->name);
	dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_SENT);

	if (!tls_client_connection_send_netbuf(dns_tls->tls_conn, txnb)) {
		netbuf_free(txnb);
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	netbuf_free(txnb);
}

static void dns_manager_tls_establish_callback(void *arg)
{
	struct dns_manager_tls_t *dns_tls = (struct dns_manager_tls_t *)arg;
	dns_tls->tls_state = DNS_TLS_CONNECTION_STATE_ACTIVE;

	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		if (dns_entry->connection_state[dns_tls->dns_ip_index] == DNS_ENTRY_CONNECTION_STATE_CONNECTING) {
			dns_entry_send_request_internal(dns_entry, dns_tls);
		}

		dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
	}
}

/*
 * Look for index match to ensure the second attempt uses a different connection when primary and secondary IPs are the same.
 * Look for an IP match in case the IPs have changed.
 */
static struct dns_manager_tls_t *dns_manager_find_create_tls(uint8_t dns_ip_index)
{
	ipv4_addr_t dns_ip = dns_manager.dns_ip[dns_ip_index];
	if (dns_ip == 0) {
		return NULL;
	}

	struct dns_manager_tls_t *dns_tls = slist_get_head(struct dns_manager_tls_t, &dns_manager.tls_list);
	while (dns_tls) {
		if ((dns_tls->dns_ip == dns_ip) && (dns_tls->dns_ip_index == dns_ip_index)) {
			return dns_tls;
		}

		dns_tls = slist_get_next(struct dns_manager_tls_t, dns_tls);
	}

	dns_tls = heap_alloc_and_zero(sizeof(struct dns_manager_tls_t), PKG_OS, MEM_TYPE_OS_DNS_TLS);
	if (!dns_tls) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	dns_tls->tls_conn = tls_client_connection_alloc();
	if (!dns_tls->tls_conn) {
		DEBUG_ERROR("out of memory");
		heap_free(dns_tls);
		return NULL;
	}

	dns_tls->dns_ip = dns_ip;
	dns_tls->dns_ip_index = dns_ip_index;
	dns_tls->tls_state = DNS_TLS_CONNECTION_STATE_CONNECTING;

	slist_attach_head(struct dns_manager_tls_t, &dns_manager.tls_list, dns_tls);

	if (!tls_client_connection_connect(dns_tls->tls_conn, dns_ip, DNS_SERVER_PORT, 0, 0, "cloudflare-dns.com", dns_manager_tls_establish_callback, dns_manager_tls_recv_callback, NULL, dns_manager_tls_close_callback, dns_tls)) {
		DEBUG_ERROR("connect failed");
		tls_client_connection_deref(dns_tls->tls_conn);
		dns_tls->tls_conn = NULL;
		dns_manager_tls_close(dns_tls);
		return NULL;
	}

	return dns_tls;
}

void dns_entry_send_request(struct dns_entry_t *dns_entry)
{
	uint8_t dns_ip_index = dns_entry_get_dns_ip_index(dns_entry);
	if (dns_ip_index == 0xFF) {
		return;
	}

	struct dns_manager_tls_t *dns_tls = dns_manager_find_create_tls(dns_ip_index);
	if (!dns_tls) {
		dns_manager_update_dns_entry_connection_state(dns_entry, dns_ip_index, DNS_ENTRY_CONNECTION_STATE_ERROR);
		return;
	}

	dns_entry_send_request_internal(dns_entry, dns_tls);
}

void dns_manager_init(void)
{
	dns_manager_init_common();
}
