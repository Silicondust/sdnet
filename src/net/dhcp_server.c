/*
 * dhcp_server.c
 *
 * Copyright © 2010,2020-2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("dhcp_server");

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_BOOTP_REQUEST 0x01
#define DHCP_BOOTP_REPLY 0x02

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_TAG_PAD 0x00
#define DHCP_TAG_SUBNET_MASK 0x01
#define DHCP_TAG_ROUTER 0x03
#define DHCP_TAG_DOMAIN_NAME_SERVER 0x06
#define DHCP_TAG_HOST_NAME 0x0c
#define DHCP_TAG_DOMAIN_NAME 0x0f
#define DHCP_TAG_BROADCAST_ADDRESS 0x1c
#define DHCP_TAG_REQUESTED_IP_ADDRESS 0x32
#define DHCP_TAG_IP_ADDR_LEASE_TIME 0x33
#define DHCP_TAG_DHCP_MESSAGE_TYPE 0x35
#define DHCP_TAG_DHCP_SERVER_IDENTIFIER 0x36
#define DHCP_TAG_REQUESTED_PARAMETER_LIST 0x37
#define DHCP_TAG_RENEWAL_TIME_VALUE 0x3a
#define DHCP_TAG_REBINDING_TIME_VALUE 0x3b
#define DHCP_TAG_CLIENT_IDENTIFIER 0x3d
#define DHCP_TAG_CAPTIVE_PORTAL 0x72
#define DHCP_TAG_END 0xff

#define DHCP_MESSAGE_TYPE_DISCOVER 0x01
#define DHCP_MESSAGE_TYPE_OFFER 0x02
#define DHCP_MESSAGE_TYPE_REQUEST 0x03
#define DHCP_MESSAGE_TYPE_DECLINE 0x04
#define DHCP_MESSAGE_TYPE_ACK 0x05
#define DHCP_MESSAGE_TYPE_NACK 0x06
#define DHCP_MESSAGE_TYPE_RELEASE 0x07
#define DHCP_MESSAGE_TYPE_INFORM 0x08

#define DHCP_HARDWARE_TYPE_ETHERNET 0x01

#define DHCP_LEASE_TIME (24 * 60 * 60)

struct dhcp_server_client_t {
	struct slist_prefix_t slist_prefix;
	ipv4_addr_t client_ip_addr;
	uint64_t client_mac_addr;
	ticks_t lease_timeout;
};

struct dhcp_server_t {
	struct udp_socket *sock;
	struct ip_interface_t *idi;
	ipv4_addr_t local_ip_addr;
	ipv4_addr_t client_ip_first;
	ipv4_addr_t client_ip_last;
	ipv4_addr_t subnet_mask;
	struct slist_t client_list;
};

static struct dhcp_server_t dhcp_server;

static void dhcp_server_client_list_load_entry(ipv4_addr_t client_ip_addr, uint64_t client_mac_addr, ticks_t current_time)
{
	if ((client_ip_addr < dhcp_server.client_ip_first) || (client_ip_addr > dhcp_server.client_ip_last)) {
		DEBUG_WARN("invalid ip %v", client_ip_addr);
		return;
	}

	struct dhcp_server_client_t *entry = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (entry) {
		if (entry->client_mac_addr == client_mac_addr) {
			DEBUG_WARN("duplicate macaddr");
			return;
		}

		entry = slist_get_next(struct dhcp_server_client_t, entry);
	}

	struct dhcp_server_client_t **pprev = slist_get_phead(struct dhcp_server_client_t, &dhcp_server.client_list);
	struct dhcp_server_client_t *p = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (p) {
		if (p->client_ip_addr >= client_ip_addr) {
			if (p->client_ip_addr > client_ip_addr) {
				break;
			}

			DEBUG_WARN("duplicate ip");
			return;
		}

		pprev = slist_get_pnext(struct dhcp_server_client_t, p);
		p = slist_get_next(struct dhcp_server_client_t, p);
	}

	entry = (struct dhcp_server_client_t *)heap_alloc_and_zero(sizeof(struct dhcp_server_client_t), PKG_OS, MEM_TYPE_OS_DHCP_SERVER_CLIENT);
	if (!entry) {
		DEBUG_ERROR("out of memory");
		return;
	}

	entry->client_ip_addr = client_ip_addr;
	entry->client_mac_addr = client_mac_addr;
	entry->lease_timeout = current_time + (ticks_t)DHCP_LEASE_TIME * TICK_RATE;

	slist_insert_pprev(struct dhcp_server_client_t, pprev, entry);
}

static ipv4_addr_t dhcp_server_client_list_allocate_addr_select(ipv4_addr_t requested_ip_addr, ipv4_addr_t available_virgin_ip_addr, ipv4_addr_t available_recycled_ip_addr)
{
	if (requested_ip_addr) {
		return requested_ip_addr;
	}

	if (available_virgin_ip_addr <= dhcp_server.client_ip_last) {
		return available_virgin_ip_addr;
	}

	if (available_recycled_ip_addr <= dhcp_server.client_ip_last) {
		return available_recycled_ip_addr;
	}

	return 0;
}

static ipv4_addr_t dhcp_server_client_list_allocate_addr(ipv4_addr_t requested_ip_addr, uint64_t client_mac_addr)
{
	if ((requested_ip_addr < dhcp_server.client_ip_first) || (requested_ip_addr > dhcp_server.client_ip_last)) {
		requested_ip_addr = 0;
	}

	struct dhcp_server_client_t *existing_entry = NULL;
	ipv4_addr_t available_virgin_ip_addr = dhcp_server.client_ip_first;
	ipv4_addr_t available_recycled_ip_addr = dhcp_server.client_ip_first;
	ticks_t current_time = timer_get_ticks();

	struct dhcp_server_client_t *entry = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (entry) {
		if (entry->client_mac_addr == client_mac_addr) {
			existing_entry = entry;
			entry = slist_get_next(struct dhcp_server_client_t, entry);
			continue;
		}

		if (entry->client_ip_addr == available_virgin_ip_addr) {
			available_virgin_ip_addr++;
		}
		if ((entry->client_ip_addr == available_recycled_ip_addr) && (current_time < entry->lease_timeout)) {
			available_recycled_ip_addr++;
		}
		if (entry->client_ip_addr == requested_ip_addr) {
			requested_ip_addr = 0;
		}

		entry = slist_get_next(struct dhcp_server_client_t, entry);
	}

	if (existing_entry) {
		if (requested_ip_addr != 0) {
			existing_entry->client_ip_addr = requested_ip_addr;
		}

		existing_entry->lease_timeout = current_time + (ticks_t)DHCP_LEASE_TIME * TICK_RATE;
		return existing_entry->client_ip_addr;
	}

	ipv4_addr_t chosen_ip_addr = dhcp_server_client_list_allocate_addr_select(requested_ip_addr, available_virgin_ip_addr, available_recycled_ip_addr);
	if (chosen_ip_addr == 0) {
		DEBUG_WARN("no available ip addresses");
		return 0;
	}

	struct dhcp_server_client_t **pprev = slist_get_phead(struct dhcp_server_client_t, &dhcp_server.client_list);
	struct dhcp_server_client_t *p = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (p) {
		if (p->client_ip_addr >= chosen_ip_addr) {
			break;
		}

		pprev = slist_get_pnext(struct dhcp_server_client_t, p);
		p = slist_get_next(struct dhcp_server_client_t, p);
	}

	entry = (struct dhcp_server_client_t *)heap_alloc_and_zero(sizeof(struct dhcp_server_client_t), PKG_OS, MEM_TYPE_OS_DHCP_SERVER_CLIENT);
	if (!entry) {
		DEBUG_ERROR("out of memory");
		return 0;
	}

	entry->client_ip_addr = chosen_ip_addr;
	entry->client_mac_addr = client_mac_addr;
	entry->lease_timeout = current_time + (ticks_t)DHCP_LEASE_TIME * TICK_RATE;

	slist_insert_pprev(struct dhcp_server_client_t, pprev, entry);
	return chosen_ip_addr;
}

static bool dhcp_server_client_list_check_addr(ipv4_addr_t requested_ip_addr, uint64_t mac_addr)
{
	if ((requested_ip_addr < dhcp_server.client_ip_first) || (requested_ip_addr > dhcp_server.client_ip_last)) {
		return false;
	}

	struct dhcp_server_client_t *p = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (p) {
		if (p->client_ip_addr >= requested_ip_addr) {
			return (p->client_ip_addr == requested_ip_addr);
		}

		p = slist_get_next(struct dhcp_server_client_t, p);
	}

	return false;
}

static void dhcp_server_store_state(void)
{
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	ticks_t current_time = timer_get_ticks();

	struct dhcp_server_client_t **pprev = slist_get_phead(struct dhcp_server_client_t, &dhcp_server.client_list);
	struct dhcp_server_client_t *p = slist_get_head(struct dhcp_server_client_t, &dhcp_server.client_list);
	while (p) {
		if (current_time >= p->lease_timeout) {
			slist_detach_pprev(struct dhcp_server_client_t, pprev, p);
			heap_free(p);
			p = *pprev;
			continue;
		}

		if (!netbuf_fwd_make_space(nb, 10)) {
			DEBUG_ERROR("out of memory");
			pprev = slist_get_pnext(struct dhcp_server_client_t, p);
			p = slist_get_next(struct dhcp_server_client_t, p);
			continue;
		}

		netbuf_fwd_write_u32(nb, p->client_ip_addr);
		netbuf_fwd_write_u48(nb, p->client_mac_addr);

		pprev = slist_get_pnext(struct dhcp_server_client_t, p);
		p = slist_get_next(struct dhcp_server_client_t, p);
	}

	netbuf_set_pos_to_start(nb);
	dhcp_server_store_state_impl(nb);
	netbuf_free(nb);
}

static void dhcp_server_send(const ip_addr_t *dest_addr, uint8_t message_type, uint32_t transaction_id, ipv4_addr_t chosen_ip_addr, uint64_t client_mac_addr)
{
	DEBUG_ASSERT((message_type != DHCP_MESSAGE_TYPE_NACK) || (chosen_ip_addr == 0), "chosen_ip_addr must be zero when sending NACK");

	struct netbuf *txnb = netbuf_alloc_with_fwd_space(512);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	netbuf_fwd_write_u8(txnb, DHCP_BOOTP_REPLY);
	netbuf_fwd_write_u8(txnb, DHCP_HARDWARE_TYPE_ETHERNET);
	netbuf_fwd_write_u8(txnb, 6);				/* Hadrware address length = 6 */
	netbuf_fwd_write_u8(txnb, 0);				/* Hops = 0 */
	netbuf_fwd_write_u32(txnb, transaction_id);
	netbuf_fwd_write_u16(txnb, 0);				/* Seconds elapsed = 0 */
	netbuf_fwd_write_u16(txnb, 0x0000);			/* Bootp flags = unicast */

	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Client IP address */
	netbuf_fwd_write_u32(txnb, chosen_ip_addr); /* Your IP address */
	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Next server IP address */
	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Relay agent IP address */

	netbuf_fwd_write_u48(txnb, client_mac_addr);
	netbuf_fwd_fill_u8(txnb, 10, 0x00);

	netbuf_fwd_fill_u8(txnb, 192, 0x00);

	netbuf_fwd_write_u32(txnb, DHCP_MAGIC_COOKIE);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_MESSAGE_TYPE);
	netbuf_fwd_write_u8(txnb, 1);
	netbuf_fwd_write_u8(txnb, message_type);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_SERVER_IDENTIFIER);
	netbuf_fwd_write_u8(txnb, 4);
	netbuf_fwd_write_u32(txnb, dhcp_server.local_ip_addr);

	if ((message_type == DHCP_MESSAGE_TYPE_OFFER) || (message_type == DHCP_MESSAGE_TYPE_ACK)) {
		netbuf_fwd_write_u8(txnb, DHCP_TAG_IP_ADDR_LEASE_TIME);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, DHCP_LEASE_TIME);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_RENEWAL_TIME_VALUE);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, DHCP_LEASE_TIME / 2);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_REBINDING_TIME_VALUE);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, DHCP_LEASE_TIME * 7 / 8);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_SUBNET_MASK);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, dhcp_server.subnet_mask);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_BROADCAST_ADDRESS);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, dhcp_server.local_ip_addr | ~dhcp_server.subnet_mask);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_ROUTER);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, dhcp_server.local_ip_addr);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_DOMAIN_NAME_SERVER);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, dhcp_server.local_ip_addr);

#if defined(DHCP_SERVER_DOMAIN_NAME)
		static const char dhcp_domain_name[] = DHCP_SERVER_DOMAIN_NAME;
		size_t dhcp_domain_name_len = strlen(dhcp_domain_name);
		netbuf_fwd_write_u8(txnb, DHCP_TAG_DOMAIN_NAME);
		netbuf_fwd_write_u8(txnb, dhcp_domain_name_len);
		netbuf_fwd_write(txnb, dhcp_domain_name, dhcp_domain_name_len);
#endif

#if defined(DHCP_SERVER_CAPTIVE_PORTAL_URL)
		static const char dhcp_captive_portal_url[] = DHCP_SERVER_CAPTIVE_PORTAL_URL;
		size_t dhcp_captive_portal_len = strlen(dhcp_captive_portal_url);
		netbuf_fwd_write_u8(txnb, DHCP_TAG_CAPTIVE_PORTAL);
		netbuf_fwd_write_u8(txnb, dhcp_captive_portal_len);
		netbuf_fwd_write(txnb, dhcp_captive_portal_url, dhcp_captive_portal_len);
#endif
	}

	netbuf_fwd_write_u8(txnb, DHCP_TAG_END);

	size_t length = netbuf_get_preceding(txnb);
	if (length < 300) {
		netbuf_fwd_fill_u8(txnb, 300 - length, 0x00);
	}

	netbuf_set_end_to_pos(txnb);
	netbuf_set_pos_to_start(txnb);
	udp_socket_send_netbuf(dhcp_server.sock, dest_addr, DHCP_CLIENT_PORT, 0, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void dhcp_server_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	if (src_port != DHCP_CLIENT_PORT) {
		DEBUG_WARN("unexpected client port");
		return;
	}

	if (!netbuf_fwd_check_space(nb, 240)) {
		DEBUG_WARN("short packet");
		return;
	}

	uint8_t header[36];
	netbuf_fwd_read(nb, header, 34);

	if (header[0] != DHCP_BOOTP_REQUEST) {
		DEBUG_WARN("not bootp request");
		return;
	}
	if (header[1] != DHCP_HARDWARE_TYPE_ETHERNET) {
		DEBUG_WARN("not hardware type ethernet");
		return;
	}
	if (header[2] != 6) {
		DEBUG_WARN("macaddr length error");
		return;
	}

	uint32_t transaction_id = mem_int_read_be_u32(header + 4);
	ipv4_addr_t client_ip_addr = mem_int_read_be_u32(header + 12);
	uint64_t client_mac_addr = mem_int_read_be_u48(header + 28);

	netbuf_advance_pos(nb, 236 - 34);

	if (netbuf_fwd_read_u32(nb) != DHCP_MAGIC_COOKIE) {
		DEBUG_WARN("not dhcp magic");
		return;
	}

	uint8_t message_type = 0;
	ipv4_addr_t requested_ip_addr = 0;

	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			break;
		}

		uint8_t tag = netbuf_fwd_read_u8(nb);
		if (tag == DHCP_TAG_PAD) {
			continue;
		}
		if (tag == DHCP_TAG_END) {
			break;
		}

		if (!netbuf_fwd_check_space(nb, 1)) {
			break;
		}

		uint8_t len = netbuf_fwd_read_u8(nb);
		if (!netbuf_fwd_check_space(nb, len)) {
			DEBUG_WARN("bad tag length");
			break;
		}

		addr_t end_bookmark = netbuf_get_pos(nb) + len;

		switch (tag) {
		case DHCP_TAG_DHCP_MESSAGE_TYPE:
			if (len != 1) {
				DEBUG_WARN("unexpected tag data length"); 
				break;
			}
			message_type = netbuf_fwd_read_u8(nb);
			break;

		case DHCP_TAG_REQUESTED_IP_ADDRESS:
			if (len != 4) {
				DEBUG_WARN("unexpected tag data length"); 
				break;
			}
			requested_ip_addr = netbuf_fwd_read_u32(nb);
			break;

		case DHCP_TAG_CLIENT_IDENTIFIER:
			if (len != 7) {
				DEBUG_WARN("client identifier missmatch");
				return; /* drop request */
			}
			if (netbuf_fwd_read_u8(nb) != DHCP_HARDWARE_TYPE_ETHERNET) {
				DEBUG_WARN("client identifier missmatch");
				return; /* drop request */
			}
			if (netbuf_fwd_read_u48(nb) != client_mac_addr) {
				DEBUG_WARN("client identifier missmatch");
				return; /* drop request */
			}
			break;

		default:
			break;
		}

		netbuf_set_pos(nb, end_bookmark);
	}

	ip_addr_t dest_addr;
	if (ip_addr_is_non_zero(src_addr)) {
		dest_addr = *src_addr;
	} else {
		dest_addr = ip_addr_ipv4_broadcast;
	}

	if (requested_ip_addr == 0) {
		requested_ip_addr = client_ip_addr;
	}

	if (message_type == DHCP_MESSAGE_TYPE_DISCOVER) {
		ipv4_addr_t chosen_ip_addr = dhcp_server_client_list_allocate_addr(requested_ip_addr, client_mac_addr);
		if (chosen_ip_addr == 0) {
			return;
		}

		dhcp_server_send(&dest_addr, DHCP_MESSAGE_TYPE_OFFER, transaction_id, chosen_ip_addr, client_mac_addr);
		return;
	}

	if (message_type == DHCP_MESSAGE_TYPE_REQUEST) {
		if (requested_ip_addr == 0) {
			DEBUG_WARN("request without ip address request");
			return;
		}

		if (!dhcp_server_client_list_check_addr(requested_ip_addr, client_mac_addr)) {
			dhcp_server_send(&dest_addr, DHCP_MESSAGE_TYPE_NACK, transaction_id, 0, client_mac_addr);
			return;
		}

		dhcp_server_send(&dest_addr, DHCP_MESSAGE_TYPE_ACK, transaction_id, requested_ip_addr, client_mac_addr);
		dhcp_server_store_state();
		return;
	}
}

void dhcp_server_load_state(uint8_t *ptr, uint8_t *end)
{
	ticks_t current_time = timer_get_ticks();

	while (ptr + 10 <= end) {
		ipv4_addr_t client_ip_addr = mem_int_read_be_u32(ptr + 0);
		uint64_t client_mac_addr = mem_int_read_be_u48(ptr + 4);
		dhcp_server_client_list_load_entry(client_ip_addr, client_mac_addr, current_time);
		ptr += 10;
	}
}

void dhcp_server_init(struct ip_interface_t *idi, ipv4_addr_t local_ip_addr, ipv4_addr_t client_ip_first, ipv4_addr_t client_ip_last, ipv4_addr_t subnet_mask)
{
	dhcp_server.idi = idi;
	dhcp_server.local_ip_addr = local_ip_addr;
	dhcp_server.client_ip_first = client_ip_first;
	dhcp_server.client_ip_last = client_ip_last;
	dhcp_server.subnet_mask = subnet_mask;

	dhcp_server.sock = udp_socket_alloc(IP_MODE_IPV4);
	udp_socket_listen_idi(dhcp_server.sock, idi, DHCP_SERVER_PORT, dhcp_server_recv, NULL, NULL);
}
