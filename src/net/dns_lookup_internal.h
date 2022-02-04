/*
 * dns_lookup_internal.h
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DNS_TLS_CONNECTION_STATE_CONNECTING 0
#define DNS_TLS_CONNECTION_STATE_ACTIVE 1

#define DNS_ENTRY_CONNECTION_STATE_NEW 0
#define DNS_ENTRY_CONNECTION_STATE_CONNECTING 1
#define DNS_ENTRY_CONNECTION_STATE_SENT 2
#define DNS_ENTRY_CONNECTION_STATE_ERROR 3
#define DNS_ENTRY_CONNECTION_STATE_COMPLETE 4

#define DNS_ENTRY_STATE_PRIMARY 0
#define DNS_ENTRY_STATE_SECONDARY 1
#define DNS_ENTRY_STATE_COMPLETE 2

struct dns_lookup_t {
	struct slist_prefix_t slist_prefix;
	int refs;
	dns_lookup_gethostbyname_callback_t callback;
	void *callback_arg;
};

struct dns_entry_t {
	struct slist_prefix_t slist_prefix;
	struct slist_t dns_lookup_list;
	ticks_t expire_time;
	ipv4_addr_t ip_addr;
	char name[128];
	uint8_t connection_state[2];
	uint8_t state;
};

struct dns_manager_tls_t {
	struct slist_prefix_t slist_prefix;
	struct tls_client_connection_t *tls_conn;
	struct netbuf *recv_nb;
	ipv4_addr_t dns_ip;
	uint8_t dns_ip_index;
	uint8_t tls_state;
};

struct dns_manager_t {
	struct slist_t dns_list;
	struct oneshot timer;
	struct udp_socket *udp_sock;
	struct slist_t tls_list;
	ipv4_addr_t dns_ip[2];
};

extern struct dns_manager_t dns_manager;

extern uint8_t dns_entry_get_dns_ip_index(struct dns_entry_t *dns_entry);
extern void dns_entry_send_request(struct dns_entry_t *dns_entry);

extern void dns_manager_init_common(void);
extern void dns_manager_recv_common(struct netbuf *nb);
extern struct netbuf *dns_manager_generate_request_nb(struct dns_entry_t *dns_entry);
extern void dns_manager_update_dns_entry_connection_state(struct dns_entry_t *dns_entry, uint8_t dns_ip_index, uint8_t connection_state);
