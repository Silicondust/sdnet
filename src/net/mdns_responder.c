/*
 * mdns_responder.c
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

THIS_FILE("mdns_responder");

#define MDNS_PORT 5353

#define DNS_RECORD_TYPE_A 0x0001
#define DNS_RECORD_TYPE_AAAA 0x001C
#define DNS_RECORD_CLASS_IN 0x0001

struct mdns_responder_name_t {
	struct slist_prefix_t slist_prefix;
	char *name;
};

struct mdns_respodnder_transport_t {
	struct udp_socket *sock;
	const ip_addr_t *multicast_ip;
};

struct mdns_responder_t {
	struct slist_t name_list;
	struct mdns_respodnder_transport_t ipv4;
	struct mdns_respodnder_transport_t ipv6;
};

static const ip_addr_t mdns_multicast_ipv4 = IP_ADDR_INIT_IPV4(0xE00000FB);
#if defined(IPV6_SUPPORT)
static const ip_addr_t mdns_multicast_ipv6 = IP_ADDR_INIT_IPV6(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);
#endif

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

#if defined(IPV6_SUPPORT)
static bool mdns_responser_lookup_name_ipv6_ip(struct ip_interface_t *idi, uint16_t dns_type, char *name, ip_addr_t *answer_ip)
{
	if (dns_type != DNS_RECORD_TYPE_AAAA) {
		return false;
	}

	if (strlen(name) != 32 + 6) {
		return false;
	}

	const char *ptr = name;

	uint8_t ipv6_addr_bytes[16];
	for (unsigned int i = 0; i < 16; i++) {
		char tmp[4];
		tmp[0] = *ptr++;
		tmp[1] = *ptr++;
		tmp[2] = 0;

		char *end;
		ipv6_addr_bytes[i] = (uint8_t)strtoul(tmp, &end, 16);
		if (end != tmp + 2) {
			return false;
		}
	}

	if (strcmp(ptr, ".local") != 0) {
		return false;
	}

	ip_addr_set_ipv6_bytes(answer_ip, ipv6_addr_bytes);
	if (!ip_addr_is_ipv6_linklocal(answer_ip)) {
		return false;
	}

	uint32_t ipv6_scope_id = ip_interface_get_ifindex(idi);
	return (ip_interface_manager_get_by_local_ip(answer_ip, ipv6_scope_id) != NULL);
}
#endif

static bool mdns_responser_lookup_name(struct ip_interface_t *idi, uint16_t dns_type, char *name, ip_addr_t *answer_ip)
{
#if defined(IPV6_SUPPORT)
	if (mdns_responser_lookup_name_ipv6_ip(idi, dns_type, name, answer_ip)) {
		return true;
	}
#endif

	struct mdns_responder_name_t *entry = slist_get_head(struct mdns_responder_name_t, &mdns_responder.name_list);
	while (1) {
		if (!entry) {
			return false;
		}

		if (strcasecmp(entry->name, name) == 0) {
			break;
		}

		entry = slist_get_next(struct mdns_responder_name_t, entry);
	}

#if defined(IPV6_SUPPORT)
	if (dns_type == DNS_RECORD_TYPE_AAAA) {
		if (ip_interface_is_ipv6(idi)) {
			ip_interface_get_local_ip(idi, answer_ip);
			return true;
		}

		uint32_t ifindex = ip_interface_get_ifindex(idi);
		struct ip_interface_t *ipv6_idi = ip_interface_manager_get_by_ifindex_best_ipv6(ifindex);
		if (!ipv6_idi) {
			return false;
		}

		ip_interface_get_local_ip(ipv6_idi, answer_ip);
		return true;
	}
#endif

	if (dns_type == DNS_RECORD_TYPE_A) {
		if (!ip_interface_is_ipv6(idi)) {
			ip_interface_get_local_ip(idi, answer_ip);
			return true;
		}

		uint32_t ifindex = ip_interface_get_ifindex(idi);
		struct ip_interface_t *ipv4_idi = ip_interface_manager_get_by_ifindex_best_ipv4(ifindex);
		if (!ipv4_idi) {
			return false;
		}

		ip_interface_get_local_ip(ipv4_idi, answer_ip);
		return true;
	}

	return false;
}

struct mdns_responder_output_state {
	struct netbuf *question_nb;
	struct netbuf *answer_nb;
	uint16_t question_count;
	uint16_t answer_count;
};

static bool mdns_responder_output_question(struct mdns_responder_output_state *state, uint16_t dns_type, char *name)
{
	if (!state->question_nb) {
		state->question_nb = netbuf_alloc();
		if (!state->question_nb) {
			DEBUG_ERROR("out of memory");
			return false;
		}
	}

	size_t encoded_name_length = 1 + strlen(name) + 1;

	if (!netbuf_fwd_make_space(state->question_nb, encoded_name_length + 4)) {
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

		netbuf_fwd_write_u8(state->question_nb, (uint8_t)length);
		netbuf_fwd_write(state->question_nb, name, length);

		if (*ptr == 0) {
			break;
		}

		name = ptr + 1;
	}

	netbuf_fwd_write_u8(state->question_nb, 0);
	netbuf_fwd_write_u16(state->question_nb, dns_type);
	netbuf_fwd_write_u16(state->question_nb, DNS_RECORD_CLASS_IN);

	state->question_count++;
	return true;
}

static bool mdns_responder_output_answer(struct mdns_responder_output_state *state, uint16_t dns_type, char *name, const ip_addr_t *answer_ip)
{
	if (!state->answer_nb) {
		state->answer_nb = netbuf_alloc();
		if (!state->answer_nb) {
			DEBUG_ERROR("out of memory");
			return false;
		}
	}

	size_t encoded_name_length = 1 + strlen(name) + 1;
	size_t ip_addr_len = (dns_type == DNS_RECORD_TYPE_AAAA) ? 16 : 4;

	if (!netbuf_fwd_make_space(state->answer_nb, encoded_name_length + 10 + ip_addr_len)) {
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

		netbuf_fwd_write_u8(state->answer_nb, (uint8_t)length);
		netbuf_fwd_write(state->answer_nb, name, length);

		if (*ptr == 0) {
			break;
		}

		name = ptr + 1;
	}

	netbuf_fwd_write_u8(state->answer_nb, 0);

	if (dns_type == DNS_RECORD_TYPE_AAAA) {
		uint8_t ip_addr_bytes[16];
		ip_addr_get_ipv6_bytes(answer_ip, ip_addr_bytes);
		netbuf_fwd_write_u16(state->answer_nb, DNS_RECORD_TYPE_AAAA);
		netbuf_fwd_write_u16(state->answer_nb, DNS_RECORD_CLASS_IN);
		netbuf_fwd_write_u32(state->answer_nb, 600); /* time to live */
		netbuf_fwd_write_u16(state->answer_nb, 16); /* data length */
		netbuf_fwd_write(state->answer_nb, ip_addr_bytes, 16);
	} else {
		netbuf_fwd_write_u16(state->answer_nb, DNS_RECORD_TYPE_A);
		netbuf_fwd_write_u16(state->answer_nb, DNS_RECORD_CLASS_IN);
		netbuf_fwd_write_u32(state->answer_nb, 600); /* time to live */
		netbuf_fwd_write_u16(state->answer_nb, 4); /* data length */
		netbuf_fwd_write_u32(state->answer_nb, ip_addr_get_ipv4(answer_ip));
	}

	state->answer_count++;
	return true;
}

static void mdns_responder_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	struct mdns_respodnder_transport_t *transport = (struct mdns_respodnder_transport_t *)inst;

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

	struct ip_interface_t *idi = ip_interface_manager_get_by_remote_ip(src_addr, ipv6_scope_id);
	if (!idi) {
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
		if ((dns_type != DNS_RECORD_TYPE_A) && (dns_type != DNS_RECORD_TYPE_AAAA)) {
			continue;
		}
		if (dns_class != DNS_RECORD_CLASS_IN) {
			continue;
		}

		if (!mdns_responder_output_question(&state, dns_type, name)) {
			success = false;
			break;
		}

		ip_addr_t answer_ip;
		if (!mdns_responser_lookup_name(idi, dns_type, name, &answer_ip)) {
			continue;
		}

		if (!mdns_responder_output_answer(&state, dns_type, name, &answer_ip)) {
			success = false;
			break;
		}
	}

	if (!success || !state.question_nb) {
		if (state.answer_nb) {
			netbuf_free(state.answer_nb);
		}
		if (state.question_nb) {
			netbuf_free(state.question_nb);
		}
		return;
	}

	netbuf_set_pos_to_start(state.question_nb);
	size_t question_length = netbuf_get_remaining(state.question_nb);

	size_t answer_length = 0;
	if (state.answer_nb) {
		netbuf_set_pos_to_start(state.answer_nb);
		answer_length = netbuf_get_remaining(state.answer_nb);
	}

	struct netbuf *txnb = netbuf_alloc_with_rev_space(12 + question_length + answer_length);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		if (state.answer_nb) {
			netbuf_free(state.answer_nb);
		}
		netbuf_free(state.question_nb);
		return;
	}

	if (answer_length > 0) {
		netbuf_rev_copy(txnb, state.answer_nb, answer_length);
	}
	netbuf_rev_copy(txnb, state.question_nb, question_length);
	netbuf_rev_write_u16(txnb, 0); /* additional */
	netbuf_rev_write_u16(txnb, 0); /* authority */
	netbuf_rev_write_u16(txnb, state.answer_count);
	netbuf_rev_write_u16(txnb, state.question_count);
	netbuf_rev_write_u16(txnb, 0x8400); /* flags */
	netbuf_rev_write_u16(txnb, transaction_id);

	if (src_port == MDNS_PORT) {
		udp_socket_send_multipath(transport->sock, transport->multicast_ip, MDNS_PORT, idi, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	} else {
		udp_socket_send_netbuf(transport->sock, src_addr, src_port, ipv6_scope_id, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	}

	netbuf_free(txnb);
	if (state.answer_nb) {
		netbuf_free(state.answer_nb);
	}
	netbuf_free(state.question_nb);
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
	mdns_responder.ipv4.multicast_ip = &mdns_multicast_ipv4;
	mdns_responder.ipv4.sock = udp_socket_alloc(IP_MODE_IPV4);
	udp_socket_listen(mdns_responder.ipv4.sock, MDNS_PORT, mdns_responder_recv, NULL, &mdns_responder.ipv4);
	igmp_manager_join_group(mdns_responder.ipv4.sock, &mdns_multicast_ipv4);

#if defined(IPV6_SUPPORT)
	mdns_responder.ipv6.multicast_ip = &mdns_multicast_ipv6;
	mdns_responder.ipv6.sock = udp_socket_alloc(IP_MODE_IPV6);
	udp_socket_listen(mdns_responder.ipv6.sock, MDNS_PORT, mdns_responder_recv, NULL, &mdns_responder.ipv6);
	igmp_manager_join_group(mdns_responder.ipv6.sock, &mdns_multicast_ipv6);
#endif
}
