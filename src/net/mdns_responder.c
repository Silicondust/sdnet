/*
 * mdns_responder.c
 *
 * Copyright © 2012-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("mdns_responder");

#define MDNS_MULTICAST_IP 0xE00000FB
#define MDNS_PORT 5353

#define DNS_RECORD_TYPE_A 0x0001
#define DNS_RECORD_CLASS_IN 0x0001

struct mdns_responder_name_t {
	struct slist_prefix_t slist_prefix;
	char *name;
};

struct mdns_responder_t {
	struct slist_t name_list;
	struct udp_socket *sock;
};

static struct mdns_responder_t mdns_responder;

static char *mdns_responder_parse_name_append_dot(char *out, char *out_end)
{
	if (out + 1 >= out_end) {
		return out;
	}

	*out++ = '.';
	return out;
}

static char *mdns_responder_parse_name_append_from_nb(char *out, char *out_end, struct netbuf *nb, uint8_t count)
{
	if (out + count < out_end) {
		netbuf_fwd_read(nb, out, count);
		return out + count;
	}

	while (count) {
		if (out + 1 >= out_end) {
			break;
		}

		*out++ = (char)netbuf_fwd_read_u8(nb);
		count--;
	}

	netbuf_advance_pos(nb, count);
	return out;
}

static bool mdns_responder_parse_name(struct netbuf *nb, char *out, char *out_end)
{
	uint16_t offset_limit = (uint16_t)netbuf_get_preceding(nb);
	addr_t restore_bookmark = 0;
	bool first = true;

	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			return false;
		}

		uint8_t count = netbuf_fwd_read_u8(nb);
		if (count == 0) {
			break;
		}

		if ((count & 0xc0) == 0xc0) {
			uint16_t offset = (uint16_t)(count & 0x3F) << 8;
			offset |= netbuf_fwd_read_u8(nb);

			if (offset < 12) {
				return false;
			}
			if (offset >= offset_limit) {
				return false;
			}

			if (restore_bookmark == 0) {
				restore_bookmark = netbuf_get_pos(nb);
			}

			offset_limit = offset;
			netbuf_set_pos(nb, netbuf_get_start(nb) + offset);
			continue;
		}

		if (!netbuf_fwd_check_space(nb, count)) {
			return false;
		}

		if (first) {
			first = false;
		} else {
			out = mdns_responder_parse_name_append_dot(out, out_end);
		}

		out = mdns_responder_parse_name_append_from_nb(out, out_end, nb, count);
	}

	if (restore_bookmark) {
		netbuf_set_pos(nb, restore_bookmark);
	}

	*out = 0;
	return true;
}

static bool mdns_responser_lookup_name(char *name)
{
	struct mdns_responder_name_t *entry = slist_get_head(struct mdns_responder_name_t, &mdns_responder.name_list);
	while (entry) {
		if (strcasecmp(entry->name, name) == 0) {
			return true;
		}

		entry = slist_get_next(struct mdns_responder_name_t, entry);
	}

	return false;
}

struct mdns_responder_output_state {
	struct netbuf *txnb;
	ipv4_addr_t local_ip;
	uint16_t answer_count;
};

static bool mdns_responder_output_answer(struct mdns_responder_output_state *state, ipv4_addr_t src_addr, char *name)
{
	if (!state->txnb) {
		state->txnb = netbuf_alloc();
		if (!state->txnb) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		state->local_ip = ip_get_local_ip_for_remote_ip(src_addr);
		if (!state->local_ip) {
			DEBUG_ERROR("no local ip");
			return false;
		}
	}

	size_t encoded_name_length = 1 + strlen(name) + 1;

	if (!netbuf_fwd_make_space(state->txnb, encoded_name_length + 14)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	while (1) {
		char *ptr = strchr(name, '.');
		if (!ptr) {
			ptr = strchr(name, 0);
		}

		size_t length = ptr - name;
		if ((length == 0) || (length > 63)) {
			DEBUG_ERROR("invalid name");
			return false;
		}

		netbuf_fwd_write_u8(state->txnb, (uint8_t)length);
		netbuf_fwd_write(state->txnb, name, length);

		if (*ptr == 0) {
			break;
		}

		name = ptr + 1;
	}

	netbuf_fwd_write_u8(state->txnb, 0);
	netbuf_fwd_write_u16(state->txnb, DNS_RECORD_TYPE_A);
	netbuf_fwd_write_u16(state->txnb, DNS_RECORD_CLASS_IN);
	netbuf_fwd_write_u32(state->txnb, 120); /* time to live */
	netbuf_fwd_write_u16(state->txnb, 4); /* data length */
	netbuf_fwd_write_u32(state->txnb, state->local_ip);

	state->answer_count++;
	return true;
}

static void mdns_responder_recv(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb)
{
	if (!netbuf_fwd_check_space(nb, 12)) {
		DEBUG_WARN("short packet");
		return;
	}

	uint16_t transaction_id = netbuf_fwd_read_u16(nb);
	uint16_t flags = netbuf_fwd_read_u16(nb);
	uint16_t question_count = netbuf_fwd_read_u16(nb);
	netbuf_advance_pos(nb, 6);

	if ((flags & 0xF800) != 0) { /* Query, Standard Query */
		return;
	}

	struct mdns_responder_output_state state;
	memset(&state, 0, sizeof(state));
	bool success = true;

	while (question_count--) {
		char name[128];
		if (!mdns_responder_parse_name(nb, name, name + sizeof(name))) {
			DEBUG_WARN("bad name data");
			success = false;
			break;
		}

		if (!netbuf_fwd_check_space(nb, 4)) {
			DEBUG_WARN("short packet");
			success = false;
			break;
		}

		uint16_t dns_type = netbuf_fwd_read_u16(nb);
		uint16_t dns_class = netbuf_fwd_read_u16(nb);
		if (dns_type != DNS_RECORD_TYPE_A) {
			continue;
		}
		if (dns_class != DNS_RECORD_CLASS_IN) {
			continue;
		}

		if (!mdns_responser_lookup_name(name)) {
			continue;
		}

		if (!mdns_responder_output_answer(&state, src_addr, name)) {
			success = false;
			break;
		}
	}

	if (!state.txnb) {
		return;
	}

	if (!success) {
		netbuf_free(state.txnb);
		return;
	}

	netbuf_set_pos_to_start(state.txnb);

	if (!netbuf_rev_make_space(state.txnb, 12)) {
		DEBUG_ERROR("out of memory");
		netbuf_free(state.txnb);
		return;
	}

	netbuf_rev_write_u16(state.txnb, 0); /* additional */
	netbuf_rev_write_u16(state.txnb, 0); /* authority */
	netbuf_rev_write_u16(state.txnb, state.answer_count);
	netbuf_rev_write_u16(state.txnb, 0); /* question count */
	netbuf_rev_write_u16(state.txnb, 0x8400); /* flags */
	netbuf_rev_write_u16(state.txnb, transaction_id);

	uint8_t ttl = 1;
	if (src_port == MDNS_PORT) {
		udp_socket_send_multipath(mdns_responder.sock, MDNS_MULTICAST_IP, MDNS_PORT, state.local_ip, ttl, UDP_TOS_DEFAULT, state.txnb);
	} else {
		udp_socket_send_multipath(mdns_responder.sock, src_addr, src_port, state.local_ip, ttl, UDP_TOS_DEFAULT, state.txnb);
	}

	netbuf_free(state.txnb);
}

bool mdns_responder_register_name(const char *name)
{
	size_t name_len = strlen(name);

	struct mdns_responder_name_t *mdns_name = (struct mdns_responder_name_t *)heap_alloc_and_zero(sizeof(struct mdns_responder_name_t) + name_len + 1, PKG_OS, MEM_TYPE_OS_MDNS_RESPONDER_NAME);
	if (!mdns_name) {
		return false;
	}

	mdns_name->name = (char *)(mdns_name + 1);
	memcpy(mdns_name->name, name, name_len);

	slist_attach_head(struct mdns_responder_name_t, &mdns_responder.name_list, mdns_name);
	return true;
}

void mdns_responder_init(void)
{
	mdns_responder.sock = udp_socket_alloc();
	udp_socket_listen(mdns_responder.sock, 0, MDNS_PORT, mdns_responder_recv, NULL, NULL);

	igmp_manager_join_group(MDNS_MULTICAST_IP);
}
