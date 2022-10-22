/*
 * dns_responder.c
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("dns_responder");

#define DNS_PORT 53

#define DNS_RECORD_TYPE_A 0x0001
#define DNS_RECORD_TYPE_PTR 0x000C
#define DNS_RECORD_TYPE_AAAA 0x001C
#define DNS_RECORD_CLASS_IN 0x0001

struct dns_responder_name_t {
	struct slist_prefix_t slist_prefix;
	char *name;
	size_t suffix_match_length;
};

struct dns_respodnder_transport_t {
	struct udp_socket *sock;
};

struct dns_responder_t {
	struct slist_t name_list;
	struct dns_respodnder_transport_t ipv4;
	struct dns_respodnder_transport_t ipv6;
};

static struct dns_responder_t dns_responder;

static char *dns_responder_parse_name_append_dot(char *out, char *out_end)
{
	if (out + 1 >= out_end) {
		return out;
	}

	*out++ = '.';
	return out;
}

static char *dns_responder_parse_name_append_from_nb(char *out, char *out_end, struct netbuf *nb, uint8_t count)
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

static bool dns_responder_parse_name(struct netbuf *nb, char *out, char *out_end)
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
			out = dns_responder_parse_name_append_dot(out, out_end);
		}

		out = dns_responder_parse_name_append_from_nb(out, out_end, nb, count);
	}

	if (restore_bookmark) {
		netbuf_set_pos(nb, restore_bookmark);
	}

	*out = 0;
	return true;
}

static bool dns_responser_lookup_name(struct ip_interface_t *idi, uint16_t dns_type, char *name, ip_addr_t *answer_ip)
{
	size_t name_len = strlen(name);

	struct dns_responder_name_t *entry = slist_get_head(struct dns_responder_name_t, &dns_responder.name_list);
	while (1) {
		if (!entry) {
			return false;
		}

		if (entry->suffix_match_length) {
			if (name_len < entry->suffix_match_length) {
				entry = slist_get_next(struct dns_responder_name_t, entry);
				continue;
			}

			if ((strcasecmp(entry->name, name + name_len - entry->suffix_match_length) != 0)) {
				entry = slist_get_next(struct dns_responder_name_t, entry);
				continue;
			}

			break;
		}
		
		if (strcasecmp(entry->name, name) != 0) {
			entry = slist_get_next(struct dns_responder_name_t, entry);
			continue;
		}

		break;
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

struct dns_responder_output_state {
	struct netbuf *question_nb;
	struct netbuf *answer_nb;
	uint16_t question_count;
	uint16_t answer_count;
};

static bool dns_responder_output_question(struct dns_responder_output_state *state, uint16_t dns_type, char *name)
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

static bool dns_responder_output_answer(struct dns_responder_output_state *state, uint16_t dns_type, char *name, const ip_addr_t *answer_ip)
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

static void dns_responder_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	struct dns_respodnder_transport_t *transport = (struct dns_respodnder_transport_t *)inst;

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

	struct dns_responder_output_state state;
	memset(&state, 0, sizeof(state));
	bool success = true;

	while (question_count--) {
		char name[128];
		if (!dns_responder_parse_name(nb, name, name + sizeof(name))) {
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
		if (dns_class != DNS_RECORD_CLASS_IN) {
			continue;
		}

		if ((dns_type == DNS_RECORD_TYPE_A) || (dns_type == DNS_RECORD_TYPE_AAAA)) {
			if (!dns_responder_output_question(&state, dns_type, name)) {
				success = false;
				break;
			}

			ip_addr_t answer_ip;
			if (!dns_responser_lookup_name(idi, dns_type, name, &answer_ip)) {
				continue;
			}

			if (!dns_responder_output_answer(&state, dns_type, name, &answer_ip)) {
				success = false;
				break;
			}

			continue;
		}

		if (dns_type == DNS_RECORD_TYPE_PTR) {
			if (!dns_responder_output_question(&state, dns_type, name)) {
				success = false;
				break;
			}

			continue;
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

	udp_socket_send_netbuf(transport->sock, src_addr, src_port, ipv6_scope_id, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);

	netbuf_free(txnb);
	if (state.answer_nb) {
		netbuf_free(state.answer_nb);
	}
	netbuf_free(state.question_nb);
}

bool dns_responder_register_name(const char *name)
{
	bool suffix_match = (*name == '*');
	if (suffix_match) {
		name++;
	}

	size_t name_len = strlen(name);

	struct dns_responder_name_t *dns_name = (struct dns_responder_name_t *)heap_alloc_and_zero(sizeof(struct dns_responder_name_t) + name_len + 1, PKG_OS, MEM_TYPE_OS_DNS_RESPONDER_NAME);
	if (!dns_name) {
		return false;
	}

	dns_name->name = (char *)(dns_name + 1);
	memcpy(dns_name->name, name, name_len);

	if (suffix_match) {
		dns_name->suffix_match_length = name_len;
	}

	slist_attach_head(struct dns_responder_name_t, &dns_responder.name_list, dns_name);
	return true;
}

void dns_responder_init(void)
{
	dns_responder.ipv4.sock = udp_socket_alloc(IP_MODE_IPV4);
	udp_socket_listen(dns_responder.ipv4.sock, DNS_PORT, dns_responder_recv, NULL, &dns_responder.ipv4);

#if defined(IPV6_SUPPORT)
	dns_responder.ipv6.sock = udp_socket_alloc(IP_MODE_IPV6);
	udp_socket_listen(dns_responder.ipv6.sock, DNS_PORT, dns_responder_recv, NULL, &dns_responder.ipv6);
#endif
}
