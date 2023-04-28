/*
 * dhcp_usbd.c
 *
 * Copyright © 2010,2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
THIS_FILE("dhcp_usbd");

/*
 * The RNDIS layer returns the physical medium as NdisPhysicalMediumUnspecified - same as the ATI OCUR product.
 * Starting with Windows 10 Fall Creators Edition - Windows sends a DHCP request with a hardware type of ARCNET
 * and ignores the OFFER unless it is sent with a matching hardware type.
 * Solution - send DHCP responses specifing the same hardware type as the request.
 */

struct dhcp_usbd_instance {
	struct udp_socket *sock;
	uint8_t host_mac_addr[6];
	ipv4_addr_t host_ip_addr;
	ipv4_addr_t device_ip_addr;
	ipv4_addr_t subnet_mask;
};

static struct dhcp_usbd_instance dhcp_usbd_inst;

static void dhcp_usbd_send(struct dhcp_usbd_instance *ddi, uint8_t message_type, uint8_t hardware_type, uint32_t transaction_id)
{
	struct netbuf *txnb = netbuf_alloc_with_fwd_space(300);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	netbuf_fwd_write_u8(txnb, DHCP_BOOTP_REPLY);
	netbuf_fwd_write_u8(txnb, hardware_type);	/* Hardware type = Ethernet */
	netbuf_fwd_write_u8(txnb, 6);				/* Hadrware address length = 6 */
	netbuf_fwd_write_u8(txnb, 0);				/* Hops = 0 */
	netbuf_fwd_write_u32(txnb, transaction_id);
	netbuf_fwd_write_u16(txnb, 0);				/* Seconds elapsed = 0 */
	netbuf_fwd_write_u16(txnb, 0x8000);			/* Bootp flags = broadcast */

	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Client IP address */
	if (message_type == DHCP_MESSAGE_TYPE_NACK) {
		netbuf_fwd_write_u32(txnb, 0x00000000);
	} else {
		netbuf_fwd_write_u32(txnb, ddi->host_ip_addr);
	}
	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Next server IP address */
	netbuf_fwd_write_u32(txnb, 0x00000000);		/* Relay agent IP address */

	netbuf_fwd_write(txnb, ddi->host_mac_addr, 6);
	netbuf_fwd_fill_u8(txnb, 10, 0x00);

	netbuf_fwd_fill_u8(txnb, 192, 0x00);

	netbuf_fwd_write_u32(txnb, DHCP_MAGIC_COOKIE);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_MESSAGE_TYPE);
	netbuf_fwd_write_u8(txnb, 1);
	netbuf_fwd_write_u8(txnb, message_type);

	netbuf_fwd_write_u8(txnb, DHCP_TAG_DHCP_SERVER_IDENTIFIER);
	netbuf_fwd_write_u8(txnb, 4);
	netbuf_fwd_write_u32(txnb, ddi->device_ip_addr);

	if ((message_type == DHCP_MESSAGE_TYPE_OFFER) || (message_type == DHCP_MESSAGE_TYPE_ACK)) {
		netbuf_fwd_write_u8(txnb, DHCP_TAG_SUBNET_MASK);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, ddi->subnet_mask);

		netbuf_fwd_write_u8(txnb, DHCP_TAG_IP_ADDR_LEASE_TIME);
		netbuf_fwd_write_u8(txnb, 4);
		netbuf_fwd_write_u32(txnb, 0xFFFFFFFF);
	}

	netbuf_fwd_write_u8(txnb, DHCP_TAG_END);

	netbuf_fwd_fill_u8(txnb, netbuf_get_remaining(txnb), 0x00);

	netbuf_set_pos_to_start(txnb);
	udp_socket_send_netbuf(ddi->sock, &ip_addr_ipv4_broadcast, DHCP_CLIENT_PORT, 0, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void dhcp_usbd_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	struct dhcp_usbd_instance *ddi = (struct dhcp_usbd_instance *)inst;

	if (src_port != DHCP_CLIENT_PORT) {
		DEBUG_WARN("unexpected client port");
		return;
	}

	if (!netbuf_fwd_check_space(nb, 240)) {
		DEBUG_WARN("short packet");
		return;
	}

	if (netbuf_fwd_read_u8(nb) != DHCP_BOOTP_REQUEST) {
		DEBUG_WARN("not bootp request");
		return;
	}

	netbuf_set_pos(nb, netbuf_get_start(nb) + 236);
	if (netbuf_fwd_read_u32(nb) != DHCP_MAGIC_COOKIE) {
		DEBUG_WARN("not dhcp magic");
		return;
	}

	netbuf_set_pos(nb, netbuf_get_start(nb) + 28);
	if (netbuf_fwd_memcmp(nb, ddi->host_mac_addr, 6) != 0) {
		DEBUG_INFO("dhcp packet for unknown mac");
		return;
	}

	netbuf_set_pos(nb, netbuf_get_start(nb) + 1);
	uint8_t hardware_type = netbuf_fwd_read_u8(nb);
	netbuf_advance_pos(nb, 2);
	uint32_t transaction_id = netbuf_fwd_read_u32(nb);
	netbuf_advance_pos(nb, 4);
	ipv4_addr_t client_ip = netbuf_fwd_read_u32(nb);

	netbuf_set_pos(nb, netbuf_get_start(nb) + 240);
	uint8_t message_type = 0;

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
			client_ip = netbuf_fwd_read_u32(nb);
			break;

		default:
			break;
		}

		netbuf_set_pos(nb, end_bookmark);
	}

	switch (message_type) {
	case DHCP_MESSAGE_TYPE_DISCOVER:
		dhcp_usbd_send(ddi, DHCP_MESSAGE_TYPE_OFFER, hardware_type, transaction_id);
		break;

	case DHCP_MESSAGE_TYPE_REQUEST:
		if (client_ip != ddi->host_ip_addr) {
			dhcp_usbd_send(ddi, DHCP_MESSAGE_TYPE_NACK, hardware_type, transaction_id);
			break;
		}

		dhcp_usbd_send(ddi, DHCP_MESSAGE_TYPE_ACK, hardware_type, transaction_id);
		break;

	default:
		return;
	}
}

void dhcp_usbd_init(uint8_t host_mac_addr[6], ipv4_addr_t host_ip_addr, ipv4_addr_t device_ip_addr, ipv4_addr_t subnet_mask)
{
	struct dhcp_usbd_instance *ddi = &dhcp_usbd_inst;

	memcpy(ddi->host_mac_addr, host_mac_addr, 6);
	ddi->host_ip_addr = host_ip_addr;
	ddi->device_ip_addr = device_ip_addr;
	ddi->subnet_mask = subnet_mask;

	ddi->sock = udp_socket_alloc(IP_MODE_IPV4);
	udp_socket_allow_ipv4_broadcast(ddi->sock);
	udp_socket_listen(ddi->sock, DHCP_SERVER_PORT, dhcp_usbd_recv, NULL, ddi);
}
