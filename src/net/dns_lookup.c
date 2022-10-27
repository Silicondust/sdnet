/*
 * dns_lookup.c
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

THIS_FILE("dns_lookup");

#define DNS_SERVER_PORT 53

#define DNS_RECORD_CLASS_IN 0x0001

#define DNS_RESPONSE_CODE_NAME_ERROR 3

#define DNS_ENTRY_EXPIRE_TIME_SUCCESS_MIN_SEC 30
#define DNS_ENTRY_EXPIRE_TIME_SUCCESS_MAX_SEC (24*60*60)
#define DNS_ENTRY_EXPIRE_TIME_FAILED_SEC 30
#define DNS_ENTRY_EXPIRE_TIME_PENDING_SEC 2

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
	ip_addr_t ip_addr;
	char name[128];
	uint16_t record_type;
	uint16_t transaction_id;
	bool switched_to_secondary;
	bool report_result;
};

struct dns_manager_t {
	struct slist_t dns_list;
	struct oneshot timer;
	struct udp_socket *sock_ipv4;
	struct udp_socket *sock_ipv6;
	ip_addr_t server_a_primary;
	ip_addr_t server_a_secondary;
	ip_addr_t server_aaaa_primary;
	ip_addr_t server_aaaa_secondary;
};

static struct dns_manager_t dns_manager;

static void dns_manager_timer_callback(void *arg);

struct dns_lookup_t *dns_lookup_ref(struct dns_lookup_t *dns_lookup)
{
	dns_lookup->refs++;
	return dns_lookup;
}

int dns_lookup_deref(struct dns_lookup_t *dns_lookup)
{
	dns_lookup->refs--;
	if (dns_lookup->refs != 0) {
		return dns_lookup->refs;
	}

	heap_free(dns_lookup);
	return 0;
}

static struct dns_entry_t *dns_manager_find_entry_name_type(const char *name, uint16_t record_type)
{
	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		if ((strcmp(dns_entry->name, name) == 0) && (dns_entry->record_type == record_type)) {
			return dns_entry;
		}

		dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
	}

	return NULL;
}

static struct dns_entry_t *dns_manager_find_entry_name_id(const char *name, uint16_t transaction_id)
{
	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		if ((strcmp(dns_entry->name, name) == 0) && (dns_entry->transaction_id == transaction_id)) {
			return dns_entry;
		}

		dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
	}

	return NULL;
}

static void dns_manager_update_timer(void)
{
	oneshot_detach(&dns_manager.timer);
	oneshot_attach(&dns_manager.timer, 0, dns_manager_timer_callback, NULL);
}

static bool dns_manager_send_request(struct dns_entry_t *dns_entry, const ip_addr_t *server_ip)
{
	if (ip_addr_is_zero(server_ip)) {
		return false;
	}

	struct udp_socket *sock = ip_addr_is_ipv6(server_ip) ? dns_manager.sock_ipv6 : dns_manager.sock_ipv4;
	if (!sock) {
		return false;
	}

	DEBUG_INFO("sending DNS request for %s type 0x%x", dns_entry->name, dns_entry->record_type);
	char *ptr = strchr(dns_entry->name, 0);
	size_t encoded_name_length = 1 + (ptr - dns_entry->name) + 1;

	struct netbuf *txnb = netbuf_alloc_with_rev_space(12 + encoded_name_length + 4);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	netbuf_rev_write_u16(txnb, DNS_RECORD_CLASS_IN); /* Class = IN */
	netbuf_rev_write_u16(txnb, dns_entry->record_type); /* Type = A or AAAA record */

	netbuf_rev_write_u8(txnb, 0x00);
	char *end = ptr;
	while (1) {
		ptr--;
		if (ptr < dns_entry->name) {
			netbuf_rev_write_u8(txnb, (uint8_t)(end - ptr - 1));
			break;
		}
		
		if (*ptr == '.') {
			netbuf_rev_write_u8(txnb, (uint8_t)(end - ptr - 1));
			end = ptr;
			continue;
		}

		netbuf_rev_write_u8(txnb, *ptr);
	}

	dns_entry->transaction_id = (uint16_t)random_get32();

	netbuf_rev_write_u16(txnb, 0); /* Additional RRs */
	netbuf_rev_write_u16(txnb, 0); /* Authority RRs */
	netbuf_rev_write_u16(txnb, 0); /* Answers */
	netbuf_rev_write_u16(txnb, 1); /* Questions */
	netbuf_rev_write_u16(txnb, 0x0100); /* Flags */
	netbuf_rev_write_u16(txnb, dns_entry->transaction_id);

	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "not at start");

	if (udp_socket_send_netbuf(sock, server_ip, DNS_SERVER_PORT, 0, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb) != UDP_OK) {
		netbuf_free(txnb);
		return false;
	}

	netbuf_free(txnb);
	return true;
}

static void dns_manager_send_request_auto(struct dns_entry_t *dns_entry)
{
#if defined(IPV6_SUPPORT)
	const ip_addr_t *server_ip;
	if (dns_entry->record_type == DNS_RECORD_TYPE_AAAA) {
		server_ip = (dns_entry->switched_to_secondary) ? &dns_manager.server_aaaa_secondary : &dns_manager.server_aaaa_primary;
	} else {
		server_ip = (dns_entry->switched_to_secondary) ? &dns_manager.server_a_secondary : &dns_manager.server_a_primary;
	}
#else
	const ip_addr_t *server_ip = (dns_entry->switched_to_secondary) ? &dns_manager.server_a_secondary : &dns_manager.server_a_primary;
#endif

	if (!dns_manager_send_request(dns_entry, server_ip)) {
		dns_entry->expire_time = timer_get_ticks();
		return;
	}

	dns_entry->expire_time = timer_get_ticks() + (ticks_t)DNS_ENTRY_EXPIRE_TIME_PENDING_SEC * TICK_RATE;
}

/* Only first name (ie the question) is supported because back references are not supported. */
static bool dns_manager_recv_read_name(struct netbuf *nb, char *name, size_t name_buffer_length)
{
	char *ptr = name;
	char *end = name + name_buffer_length;

	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			DEBUG_WARN("short packet or bad name");
			return false;
		}

		uint8_t len = netbuf_fwd_read_u8(nb);
		if (len == 0) {
			*ptr = 0;
			break;
		}

		if (len >= 0xC0) {
			DEBUG_WARN("back reference in name");
			return false;
		}

		if (!netbuf_fwd_check_space(nb, len)) {
			DEBUG_WARN("short packet or bad name");
			return false;
		}

		if (ptr > name) {
			*ptr++ = '.';
		}

		if (ptr + len + 1 > end) {
			DEBUG_WARN("overlength name");
			return false;
		}

		netbuf_fwd_read(nb, ptr, len);
		ptr += len;
	}

	DEBUG_INFO("name = %s", name);
	return true;
}

static bool dns_manager_recv_skip_name(struct netbuf *nb)
{
	while (1) {
		if (!netbuf_fwd_check_space(nb, 1)) {
			DEBUG_WARN("short packet or bad name");
			return false;
		}

		uint8_t len = netbuf_fwd_read_u8(nb);
		if (len == 0) {
			break;
		}

		if (len >= 0xC0) {
			if (!netbuf_fwd_check_space(nb, 1)) {
				DEBUG_WARN("short packet or bad name");
				return false;
			}

			netbuf_advance_pos(nb, 1);
			break;
		}

		if (!netbuf_fwd_check_space(nb, len)) {
			DEBUG_WARN("short packet or bad name");
			return false;
		}

		netbuf_advance_pos(nb, len);
	}

	return true;
}

static void dns_manager_recv_record(struct dns_entry_t *dns_entry, uint32_t time_to_live)
{
	DEBUG_INFO("%s = %V", dns_entry->name, &dns_entry->ip_addr);

	if (time_to_live < DNS_ENTRY_EXPIRE_TIME_SUCCESS_MIN_SEC) {
		time_to_live = DNS_ENTRY_EXPIRE_TIME_SUCCESS_MIN_SEC;
	}
	if (time_to_live > DNS_ENTRY_EXPIRE_TIME_SUCCESS_MAX_SEC) {
		time_to_live = DNS_ENTRY_EXPIRE_TIME_SUCCESS_MAX_SEC;
	}

	dns_entry->report_result = true;
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)time_to_live * TICK_RATE;
	dns_manager_update_timer();
}

static void dns_manager_recv_error(struct dns_entry_t *dns_entry)
{
	if (!dns_entry->switched_to_secondary) {
		DEBUG_INFO("%s primary server failed trying secondary", dns_entry->name);
		dns_entry->switched_to_secondary = true;
		dns_manager_send_request_auto(dns_entry);
		dns_manager_update_timer();
		return;
	}

	DEBUG_INFO("%s failed", dns_entry->name);
	dns_entry->report_result = true;
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)DNS_ENTRY_EXPIRE_TIME_FAILED_SEC * TICK_RATE;
	dns_manager_update_timer();
}

static void dns_manager_recv_timeout(struct dns_entry_t *dns_entry)
{
	if (!dns_entry->switched_to_secondary) {
		DEBUG_INFO("%s primary server failed trying secondary", dns_entry->name);
		dns_entry->switched_to_secondary = true;
		dns_manager_send_request_auto(dns_entry);
		return;
	}

	DEBUG_INFO("%s failed", dns_entry->name);
	dns_entry->report_result = true;
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)DNS_ENTRY_EXPIRE_TIME_FAILED_SEC * TICK_RATE;
}

static void dns_manager_recv(void *inst, const ip_addr_t *src_addr, uint16_t src_port, uint32_t ipv6_scope_id, struct netbuf *nb)
{
	if (src_port != DNS_SERVER_PORT) {
		DEBUG_WARN("unexpected server port");
		return;
	}

	if (!netbuf_fwd_check_space(nb, 12)) {
		DEBUG_WARN("short packet");
		return;
	}

	uint16_t transaction_id = netbuf_fwd_read_u16(nb);
	uint16_t flags = netbuf_fwd_read_u16(nb);
	uint16_t question_count = netbuf_fwd_read_u16(nb);
	uint16_t answer_count = netbuf_fwd_read_u16(nb);
	netbuf_advance_pos(nb, 4);

	if ((flags & 0x8000) == 0) {
		DEBUG_WARN("response flag not set");
		return;
	}
	if (question_count != 1) {
		DEBUG_WARN("unexpected question count %u", question_count);
		return;
	}

	/*
	 * Parse question.
	 */
	char name[128];
	if (!dns_manager_recv_read_name(nb, name, sizeof(name))) {
		return;
	}

	struct dns_entry_t *dns_entry = dns_manager_find_entry_name_id(name, transaction_id);
	if (!dns_entry) {
		return;
	}

	if (!netbuf_fwd_check_space(nb, 4)) {
		DEBUG_WARN("short packet");
		return;
	}

	netbuf_advance_pos(nb, 4);

	/*
	 * Parse answers.
	 */
	uint8_t response_code = flags & 0x000F;
	if (response_code != 0) {
		dns_manager_recv_error(dns_entry);
		return;
	}

	while (answer_count--) {
		if (!dns_manager_recv_skip_name(nb)) {
			break;
		}

		if (!netbuf_fwd_check_space(nb, 10)) {
			DEBUG_WARN("short packet");
			break;
		}

		uint16_t record_type = netbuf_fwd_read_u16(nb);
		netbuf_advance_pos(nb, 2);
		uint32_t time_to_live = netbuf_fwd_read_u32(nb);

		uint16_t data_length = netbuf_fwd_read_u16(nb);
		if (data_length == 0) {
			continue;
		}
		if (!netbuf_fwd_check_space(nb, data_length)) {
			DEBUG_WARN("short packet");
			break;
		}

		addr_t end_bookmark = netbuf_get_pos(nb) + data_length;

		if (record_type != dns_entry->record_type) {
			netbuf_set_pos(nb, end_bookmark);
			continue;
		}

#if defined(IPV6_SUPPORT)
		if (record_type == DNS_RECORD_TYPE_AAAA) {
			if (data_length != 16) {
				netbuf_set_pos(nb, end_bookmark);
				continue;
			}

			ip_addr_t ip_addr;
			ip_addr_set_ipv6_bytes(&ip_addr, netbuf_get_ptr(nb));

			if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
				netbuf_set_pos(nb, end_bookmark);
				continue;
			}

			dns_entry->ip_addr = ip_addr;
			dns_manager_recv_record(dns_entry, time_to_live);
			return;
		}
#endif

		if (record_type == DNS_RECORD_TYPE_A) {
			if (data_length != 4) {
				netbuf_set_pos(nb, end_bookmark);
				continue;
			}

			ip_addr_t ip_addr;
			ip_addr_set_ipv4(&ip_addr, netbuf_fwd_read_u32(nb));

			if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
				netbuf_set_pos(nb, end_bookmark);
				continue;
			}

			dns_entry->ip_addr = ip_addr;
			dns_manager_recv_record(dns_entry, time_to_live);
			return;
		}

		netbuf_set_pos(nb, end_bookmark);
	}

	dns_manager_recv_error(dns_entry);
}

static void dns_manager_timer_callback(void *arg)
{
	ticks_t current_time = timer_get_ticks();
	ticks_t next_expire_time = 0xFFFFFFFFFFFFFFFFULL;
	struct dns_lookup_t *dns_lookup_to_signal = NULL;
	struct dns_entry_t *dns_entry_to_signal = NULL;

	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		if (!dns_entry->report_result && (current_time >= dns_entry->expire_time)) {
			dns_manager_recv_timeout(dns_entry);
		}

		if (!dns_lookup_to_signal && dns_entry->report_result) {
			dns_lookup_to_signal = slist_detach_head(struct dns_lookup_t, &dns_entry->dns_lookup_list); /* Might be null */
			dns_entry_to_signal = dns_entry;
		}

		if (current_time >= dns_entry->expire_time) {
			if (!slist_get_head(struct dns_lookup_t, &dns_entry->dns_lookup_list)) {
				struct dns_entry_t *dns_discard = dns_entry;
				dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
				(void)slist_detach_item(struct dns_entry_t, &dns_manager.dns_list, dns_discard);
				heap_free(dns_discard);
				continue;
			}
		}

		if (dns_entry->expire_time < next_expire_time) {
			next_expire_time = dns_entry->expire_time;
		}

		dns_entry = slist_get_next(struct dns_entry_t, dns_entry);
	}

	if (dns_lookup_to_signal || (next_expire_time <= current_time)) {
		oneshot_attach(&dns_manager.timer, 0, dns_manager_timer_callback, NULL);
	} else if (next_expire_time != 0xFFFFFFFFFFFFFFFFULL) {
		oneshot_attach(&dns_manager.timer, next_expire_time - current_time, dns_manager_timer_callback, NULL);
	}

	if (!dns_lookup_to_signal) {
		return;
	}

	if (dns_lookup_deref(dns_lookup_to_signal) <= 0) {
		return;
	}

	if (dns_lookup_to_signal->callback) {
		dns_lookup_to_signal->callback(dns_lookup_to_signal->callback_arg, dns_entry_to_signal->record_type, &dns_entry_to_signal->ip_addr, dns_entry_to_signal->expire_time);
	}
}

bool dns_lookup_gethostbyname(struct dns_lookup_t *dns_lookup, const char *name, uint16_t record_type, dns_lookup_gethostbyname_callback_t callback, void *callback_arg)
{
	dns_lookup->callback = callback;
	dns_lookup->callback_arg = callback_arg;

	struct dns_entry_t *dns_entry = dns_manager_find_entry_name_type(name, record_type);
	if (dns_entry) {
		dns_lookup_ref(dns_lookup);
		slist_attach_tail(struct dns_lookup_t, &dns_entry->dns_lookup_list, dns_lookup);

		if (!dns_entry->report_result) {
			DEBUG_INFO("dns request outstanding");
			return true;
		}

		DEBUG_INFO("dns cached result");
		dns_manager_update_timer();
		return true;
	}

	DEBUG_INFO("new dns request");
	dns_entry = (struct dns_entry_t *)heap_alloc_and_zero(sizeof(struct dns_entry_t), PKG_OS, MEM_TYPE_OS_DNS_ENTRY);
	if (!dns_entry) {
		return false;
	}

	strncpy(dns_entry->name, name, sizeof(dns_entry->name) - 1);
	dns_entry->record_type = record_type;

	dns_lookup_ref(dns_lookup);
	slist_attach_tail(struct dns_lookup_t, &dns_entry->dns_lookup_list, dns_lookup);
	slist_attach_tail(struct dns_entry_t, &dns_manager.dns_list, dns_entry);

	dns_manager_send_request_auto(dns_entry);
	dns_manager_update_timer();
	return true;
}

struct dns_lookup_t *dns_lookup_alloc(void)
{
	struct dns_lookup_t *dns_lookup = (struct dns_lookup_t *)heap_alloc_and_zero(sizeof(struct dns_lookup_t), PKG_OS, MEM_TYPE_OS_DNS_LOOKUP);
	if (!dns_lookup) {
		return NULL;
	}

	dns_lookup->refs = 1;
	return dns_lookup;
}

static void dns_manager_set_server_internal(ip_addr_t *server_primary, ip_addr_t *server_secondary)
{
	if (!ip_addr_is_unicast(server_primary)) {
		ip_addr_set_zero(server_primary);
	}
	if (!ip_addr_is_unicast(server_secondary)) {
		ip_addr_set_zero(server_secondary);
	}

	if (ip_addr_is_zero(server_primary)) {
		*server_primary = *server_secondary;
	}
	if (ip_addr_is_zero(server_secondary)) {
		*server_secondary = *server_primary;
	}
}

void dns_manager_set_server_a_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary)
{
	dns_manager.server_a_primary = *server_primary;
	dns_manager.server_a_secondary = *server_secondary;
	dns_manager_set_server_internal(&dns_manager.server_a_primary, &dns_manager.server_a_secondary);
}

#if defined(IPV6_SUPPORT)
void dns_manager_set_server_aaaa_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary)
{
	dns_manager.server_aaaa_primary = *server_primary;
	dns_manager.server_aaaa_secondary = *server_secondary;
	dns_manager_set_server_internal(&dns_manager.server_aaaa_primary, &dns_manager.server_aaaa_secondary);
}
#endif

void dns_manager_init(void)
{
	oneshot_init(&dns_manager.timer);

	dns_manager.sock_ipv4 = udp_socket_alloc(IP_MODE_IPV4);
	if (dns_manager.sock_ipv4) {
		udp_socket_listen(dns_manager.sock_ipv4, 0, dns_manager_recv, NULL, NULL);
	}

#if defined(IPV6_SUPPORT)
	dns_manager.sock_ipv6 = udp_socket_alloc(IP_MODE_IPV6);
	if (dns_manager.sock_ipv6) {
		udp_socket_listen(dns_manager.sock_ipv6, 0, dns_manager_recv, NULL, NULL);
	}
#endif
}
