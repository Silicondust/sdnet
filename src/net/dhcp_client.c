/*
 * dhcp_client.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("dhcp_client");

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
#define DHCP_TAG_REQUESTED_IP_ADDRESS 0x32
#define DHCP_TAG_IP_ADDR_LEASE_TIME 0x33
#define DHCP_TAG_DHCP_MESSAGE_TYPE 0x35
#define DHCP_TAG_DHCP_SERVER_IDENTIFIER 0x36
#define DHCP_TAG_REQUESTED_PARAMETER_LIST 0x37
#define DHCP_TAG_RENEWAL_TIME_VALUE 0x3a
#define DHCP_TAG_REBINDING_TIME_VALUE 0x3b
#define DHCP_TAG_CLIENT_IDENTIFIER 0x3d
#define DHCP_TAG_END 0xff

#define DHCP_MESSAGE_TYPE_DISCOVER 0x01
#define DHCP_MESSAGE_TYPE_OFFER 0x02
#define DHCP_MESSAGE_TYPE_REQUEST 0x03
#define DHCP_MESSAGE_TYPE_DECLINE 0x04
#define DHCP_MESSAGE_TYPE_ACK 0x05
#define DHCP_MESSAGE_TYPE_NACK 0x06
#define DHCP_MESSAGE_TYPE_RELEASE 0x07
#define DHCP_MESSAGE_TYPE_INFORM 0x08

struct dhcp_client_t {
	struct ip_datalink_instance *idi;
	struct udp_socket *sock;
	struct oneshot timer;

	ticks_t lease_expire_time;
	ticks_t lease_rebind_time;
	ticks_t discover_start_time;
	uint32_t transaction_id;
	ipv4_addr_t bound_server_ip;
	ipv4_addr_t bound_local_ip;

	char client_name[16];
	dhcp_client_callback_t callback;
	void *callback_arg;
};

static void dhcp_client_timer_callback(void *arg);

static void dhcp_client_lease_expire(struct dhcp_client_t *dc)
{
	dc->bound_server_ip = 0;
	dc->bound_local_ip = 0;

	dc->lease_expire_time = TICKS_INFINITE;
	dc->lease_rebind_time = TICKS_INFINITE;

	if (dc->callback) {
		dc->callback(dc->callback_arg, 0, 0, 0, 0, 0);
	}
}

static void dhcp_client_send(struct dhcp_client_t *dc, uint8_t message_type, ipv4_addr_t server_ip, ipv4_addr_t requested_ip)
{
	struct netbuf *txnb = netbuf_alloc_with_fwd_space(300); /* DHCP packets must be padded to 300 bytes if shorter. */
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	uint8_t mac_addr[6];
	ip_datalink_get_hwaddr(dc->idi, mac_addr, 6);

	netbuf_fwd_write_u8(txnb, DHCP_BOOTP_REQUEST);
	netbuf_fwd_write_u8(txnb, 0x01); /* hardware type (ethernet) */
	netbuf_fwd_write_u8(txnb, 6); /* hadrware address length */
	netbuf_fwd_write_u8(txnb, 0); /* hops */
	netbuf_fwd_write_u32(txnb, dc->transaction_id);
	netbuf_fwd_write_u16(txnb, (timer_get_ticks() - dc->discover_start_time) / TICK_RATE);
	netbuf_fwd_write_u16(txnb, 0x8000); /* flags */
	netbuf_fwd_write_u32(txnb, dc->bound_local_ip); /* client ip address */
	netbuf_fwd_write_u32(txnb, 0x00000000); /* your ip address */
	netbuf_fwd_write_u32(txnb, 0x00000000); /* next server ip address */
	netbuf_fwd_write_u32(txnb, 0x00000000); /* relay agent ip address */
	netbuf_fwd_write(txnb, mac_addr, 6);
	netbuf_fwd_fill_u8(txnb, 10 + 64 + 128, 0);
	netbuf_fwd_write_u32(txnb, DHCP_MAGIC_COOKIE);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_MESSAGE_TYPE);
	netbuf_fwd_write_u8(txnb, 1);
	netbuf_fwd_write_u8(txnb, message_type);

	if (server_ip != 0) {
		netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_SERVER_IDENTIFIER);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, server_ip);
	}
	
	netbuf_fwd_write_u8(txnb, DHCP_TAG_CLIENT_IDENTIFIER);
	netbuf_fwd_write_u8(txnb, 7);
	netbuf_fwd_write_u8(txnb, 0x01);
	netbuf_fwd_write(txnb, mac_addr, 6);

	if (dc->client_name[0] != 0) {
		size_t len = strlen(dc->client_name);
		netbuf_fwd_write_u8(txnb, DHCP_TAG_HOST_NAME);
		netbuf_fwd_write_u8(txnb, len);
		netbuf_fwd_write(txnb, dc->client_name, len);
	}

	if (requested_ip != 0) {
		netbuf_fwd_write_u8(txnb, DHCP_TAG_REQUESTED_IP_ADDRESS);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, requested_ip);
	}
	
	netbuf_fwd_write_u8(txnb, DHCP_TAG_REQUESTED_PARAMETER_LIST);
	netbuf_fwd_write_u8(txnb, 3);
	netbuf_fwd_write_u8(txnb, DHCP_TAG_DOMAIN_NAME_SERVER);
	netbuf_fwd_write_u8(txnb, DHCP_TAG_ROUTER);
	netbuf_fwd_write_u8(txnb, DHCP_TAG_SUBNET_MASK);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_END);
	netbuf_fwd_fill_u8(txnb, netbuf_get_remaining(txnb), 0);

	netbuf_set_pos_to_start(txnb);
	udp_dhcp_socket_send_netbuf(dc->sock, dc->idi, 0xFFFFFFFF, DHCP_SERVER_PORT, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void dhcp_client_recv(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb)
{
	struct dhcp_client_t *dc = (struct dhcp_client_t *)inst;

	if (src_port != DHCP_SERVER_PORT) {
		DEBUG_WARN("unexpected server port");
		return;
	}

	if (!netbuf_fwd_check_space(nb, 240)) {
		DEBUG_WARN("short packet");
		return;
	}

	if (netbuf_fwd_read_u8(nb) != DHCP_BOOTP_REPLY) {
		DEBUG_WARN("not bootp request");
		return;
	}

	netbuf_advance_pos(nb, 3);
	if (netbuf_fwd_read_u32(nb) != dc->transaction_id) {
		DEBUG_WARN("unexpected transaction id");
		return;
	}

	netbuf_advance_pos(nb, 8);
	ipv4_addr_t ip_addr = netbuf_fwd_read_u32(nb);
	netbuf_advance_pos(nb, 8);

	uint8_t mac_addr[6];
	ip_datalink_get_hwaddr(dc->idi, mac_addr, 6);
	if (netbuf_fwd_memcmp(nb, mac_addr, 6) != 0) {
		DEBUG_INFO("dhcp packet for unknown mac");
		return;
	}

	netbuf_set_pos(nb, netbuf_get_start(nb) + 236);
	if (netbuf_fwd_read_u32(nb) != DHCP_MAGIC_COOKIE) {
		DEBUG_WARN("not dhcp magic");
		return;
	}

	uint8_t message_type = 0;
	ipv4_addr_t server_ip = 0;
	ipv4_addr_t subnet = 0;
	ipv4_addr_t gateway = 0;
	ipv4_addr_t dns_ip_primary = 0;
	ipv4_addr_t dns_ip_secondary = 0;
	uint32_t lease_duration = 0;

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
			if (len == 1) {
				message_type = netbuf_fwd_read_u8(nb);
			}
			break;

		case DHCP_TAG_DHCP_SERVER_IDENTIFIER:
			if (len == 4) {
				server_ip = netbuf_fwd_read_u32(nb);
			}
			break;

		case DHCP_TAG_SUBNET_MASK:
			if (len == 4) {
				subnet = netbuf_fwd_read_u32(nb);
			}
			break;

		case DHCP_TAG_ROUTER:
			if (len >= 4) {
				gateway = netbuf_fwd_read_u32(nb);
			}
			break;

		case DHCP_TAG_DOMAIN_NAME_SERVER:
			if (len >= 4) {
				dns_ip_primary = netbuf_fwd_read_u32(nb);
			}
			if (len >= 8) {
				dns_ip_secondary = netbuf_fwd_read_u32(nb);
			}
			break;

		case DHCP_TAG_IP_ADDR_LEASE_TIME:
			if (len == 4) {
				lease_duration = netbuf_fwd_read_u32(nb);
			}
			break;

		default:
			break;
		}

		netbuf_set_pos(nb, end_bookmark);
	}

	if (server_ip == 0) {
		DEBUG_WARN("no server ip specified");
		return;
	}
	if ((dc->bound_server_ip != 0) && (dc->bound_server_ip != server_ip)) {
		DEBUG_WARN("ignoring renew discover reply from different server");
		return;
	}

	switch (message_type) {
	case DHCP_MESSAGE_TYPE_OFFER:
		if (!ip_addr_is_unicast(ip_addr)) {
			DEBUG_WARN("invalid ip addr %v", ip_addr);
			break;
		}
		if (subnet == 0) {
			DEBUG_WARN("no subnet specified");
			break;
		}

		dhcp_client_send(dc, DHCP_MESSAGE_TYPE_REQUEST, server_ip, ip_addr);
		break;

	case DHCP_MESSAGE_TYPE_ACK:
		if (!ip_addr_is_unicast(ip_addr)) {
			DEBUG_WARN("invalid ip addr %v", ip_addr);
			break;
		}
		if (subnet == 0) {
			DEBUG_WARN("no subnet specified");
			break;
		}
		if (lease_duration < 30) {
			DEBUG_WARN("no lease time specified or too short");
			break;
		}

		oneshot_detach(&dc->timer);

		dc->bound_server_ip = server_ip;
		dc->bound_local_ip = ip_addr;
		dc->discover_start_time = 0;

		if (lease_duration == 0xFFFFFFFFUL) {
			dc->lease_expire_time = TICKS_INFINITE;
			dc->lease_rebind_time = TICKS_INFINITE;
		} else {
			ticks_t lease_duration_ticks = (ticks_t)lease_duration * TICK_RATE;
			dc->lease_expire_time = timer_get_ticks() + lease_duration_ticks;
			dc->lease_rebind_time = dc->lease_expire_time - (lease_duration_ticks / 4);
			oneshot_attach(&dc->timer, lease_duration_ticks / 2, dhcp_client_timer_callback, dc);
		}

		if (dc->callback) {
			dc->callback(dc->callback_arg, ip_addr, subnet, gateway, dns_ip_primary, dns_ip_secondary);
		}
		break;

	case DHCP_MESSAGE_TYPE_NACK:
		dhcp_client_lease_expire(dc);
		break;

	default:
		DEBUG_WARN("unknown message type %u", message_type);
		return;
	}
}

static void dhcp_client_timer_callback(void *arg)
{
	struct dhcp_client_t *dc = (struct dhcp_client_t *)arg;

	ticks_t current_time = timer_get_ticks();
	if (current_time >= dc->lease_expire_time) {
		dhcp_client_lease_expire(dc);
	}

	if (current_time >= dc->lease_rebind_time) {
		dc->bound_server_ip = 0;
		dc->discover_start_time = 0;
		dc->lease_rebind_time = TICKS_INFINITE;
	}

	if (dc->discover_start_time == 0) {
		dc->discover_start_time = current_time;
	}

	if (current_time - dc->discover_start_time < TICK_RATE * 60) {
		oneshot_attach(&dc->timer, TICK_RATE * 5, dhcp_client_timer_callback, dc);
	} else {
		oneshot_attach(&dc->timer, TICK_RATE * 60, dhcp_client_timer_callback, dc);
	}

	dc->transaction_id = random_get32();

	if (dc->bound_server_ip != 0) {
		dhcp_client_send(dc, DHCP_MESSAGE_TYPE_REQUEST, dc->bound_server_ip, dc->bound_local_ip);
	} else {
		dhcp_client_send(dc, DHCP_MESSAGE_TYPE_DISCOVER, 0, dc->bound_local_ip);
	}
}

void dhcp_client_link_up(struct dhcp_client_t *dc)
{
	if (oneshot_is_attached(&dc->timer)) {
		return;
	}

	oneshot_attach(&dc->timer, TICK_RATE, dhcp_client_timer_callback, dc);
}

void dhcp_client_link_down(struct dhcp_client_t *dc)
{
	oneshot_detach(&dc->timer);
	dhcp_client_lease_expire(dc);
	dc->discover_start_time = 0;
}

struct dhcp_client_t *dhcp_client_alloc(struct ip_datalink_instance *idi, const char *client_name, dhcp_client_callback_t callback, void *callback_arg)
{
	struct dhcp_client_t *dc = (struct dhcp_client_t *)heap_alloc_and_zero(sizeof(struct dhcp_client_t), PKG_OS, MEM_TYPE_OS_DHCP_CLIENT);
	if (!dc) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	dc->sock = udp_dhcp_socket_alloc();
	if (!dc->sock) {
		DEBUG_ERROR("out of memory");
		heap_free(dc);
		return NULL;
	}

	dc->idi = idi;
	dc->callback = callback;
	dc->callback_arg = callback_arg;
	strncpy(dc->client_name, client_name, sizeof(dc->client_name) - 1);

	dc->lease_expire_time = TICKS_INFINITE;
	dc->lease_rebind_time = TICKS_INFINITE;

	oneshot_init(&dc->timer);
	udp_dhcp_socket_listen(dc->sock, idi, 0, DHCP_CLIENT_PORT, dhcp_client_recv, NULL, dc);

	return dc;
}
