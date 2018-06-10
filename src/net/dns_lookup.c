/*
 * dns_lookup.c
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

THIS_FILE("dns_lookup");

#define DNS_SERVER_PORT 53

#define DNS_RECORD_TYPE_A 0x0001
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
	ipv4_addr_t ip_addr;
	char name[128];
	bool retry_on_failure;
	bool report_result;
};

struct dns_manager_t {
	struct slist_t dns_list;
	struct oneshot timer;
	struct udp_socket *sock;
	ipv4_addr_t dns_ip_primary;
	ipv4_addr_t dns_ip_secondary;
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

static struct dns_entry_t *dns_manager_find_entry(const char *name)
{
	struct dns_entry_t *dns_entry = slist_get_head(struct dns_entry_t, &dns_manager.dns_list);
	while (dns_entry) {
		if (strcmp(dns_entry->name, name) == 0) {
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

static void dns_manager_send_request(struct dns_entry_t *dns_entry, ipv4_addr_t dns_server_ip)
{
	if (dns_server_ip == 0) {
		return;
	}

	DEBUG_INFO("sending DNS request for %s", dns_entry->name);
	char *ptr = strchr(dns_entry->name, 0);
	size_t encoded_name_length = 1 + (ptr - dns_entry->name) + 1;

	struct netbuf *txnb = netbuf_alloc_with_rev_space(12 + encoded_name_length + 4);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	netbuf_rev_write_u16(txnb, DNS_RECORD_CLASS_IN); /* Class = IN */
	netbuf_rev_write_u16(txnb, DNS_RECORD_TYPE_A); /* Type = A record */

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

	netbuf_rev_write_u16(txnb, 0); /* Additional RRs */
	netbuf_rev_write_u16(txnb, 0); /* Authority RRs */
	netbuf_rev_write_u16(txnb, 0); /* Answers */
	netbuf_rev_write_u16(txnb, 1); /* Questions */
	netbuf_rev_write_u16(txnb, 0x0100); /* Flags */
	netbuf_rev_write_u16(txnb, (uint16_t)random_get32());

	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "not at start");
	udp_socket_send_netbuf(dns_manager.sock, dns_server_ip, DNS_SERVER_PORT, UDP_TTL_DEFAULT, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
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

static void dns_manager_recv_record_a(struct dns_entry_t *dns_entry, ipv4_addr_t ip_addr, uint32_t time_to_live)
{
	DEBUG_INFO("%s = %v", dns_entry->name, ip_addr);

	if (time_to_live < DNS_ENTRY_EXPIRE_TIME_SUCCESS_MIN_SEC) {
		time_to_live = DNS_ENTRY_EXPIRE_TIME_SUCCESS_MIN_SEC;
	}
	if (time_to_live > DNS_ENTRY_EXPIRE_TIME_SUCCESS_MAX_SEC) {
		time_to_live = DNS_ENTRY_EXPIRE_TIME_SUCCESS_MAX_SEC;
	}

	dns_entry->ip_addr = ip_addr;
	dns_entry->report_result = true;
	dns_entry->retry_on_failure = false;
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)time_to_live * TICK_RATE;

	dns_manager_update_timer();
}

static void dns_manager_recv_name_error(struct dns_entry_t *dns_entry)
{
	DEBUG_INFO("%s = error", dns_entry->name);

	dns_entry->ip_addr = 0;
	dns_entry->report_result = true;
	dns_entry->retry_on_failure = false;
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)DNS_ENTRY_EXPIRE_TIME_FAILED_SEC * TICK_RATE;

	dns_manager_update_timer();
}

static void dns_manager_recv(void *inst, ipv4_addr_t src_addr, uint16_t src_port, struct netbuf *nb)
{
	if (src_port != DNS_SERVER_PORT) {
		DEBUG_WARN("unexpected server port");
		return;
	}

	if (!netbuf_fwd_check_space(nb, 12)) {
		DEBUG_WARN("short packet");
		return;
	}

	netbuf_advance_pos(nb, 2);
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

	struct dns_entry_t *dns_entry = dns_manager_find_entry(name);
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
	if (response_code == DNS_RESPONSE_CODE_NAME_ERROR) {
		dns_manager_recv_name_error(dns_entry);
		return;
	}
	if (response_code != 0) {
		DEBUG_INFO("response indicated error");
		return;
	}

	while (answer_count--) {
		if (!dns_manager_recv_skip_name(nb)) {
			return;
		}

		if (!netbuf_fwd_check_space(nb, 10)) {
			DEBUG_WARN("short packet");
			return;
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
			return;
		}

		addr_t end_bookmark = netbuf_get_pos(nb) + data_length;

		ipv4_addr_t ip_addr;
		switch(record_type) {
		case DNS_RECORD_TYPE_A:
			if (data_length != 4) {
				break;
			}

			ip_addr = netbuf_fwd_read_u32(nb);
			if (!ip_addr_is_unicast(ip_addr)) {
				DEBUG_WARN("invalid ip %v", ip_addr);
				break;
			}

			dns_manager_recv_record_a(dns_entry, ip_addr, time_to_live);
			return;

		default:
			break;
		}

		netbuf_set_pos(nb, end_bookmark);
	}
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
			if (dns_entry->retry_on_failure) {
				dns_entry->expire_time = current_time + (ticks_t)DNS_ENTRY_EXPIRE_TIME_PENDING_SEC * TICK_RATE;
				dns_entry->retry_on_failure = false;
				dns_manager_send_request(dns_entry, dns_manager.dns_ip_secondary);
			} else {
				dns_entry->expire_time = current_time + (ticks_t)DNS_ENTRY_EXPIRE_TIME_FAILED_SEC * TICK_RATE;
				dns_entry->report_result = true;
			}
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
		dns_lookup_to_signal->callback(dns_lookup_to_signal->callback_arg, dns_entry_to_signal->ip_addr, dns_entry_to_signal->expire_time);
	}
}

bool dns_lookup_gethostbyname(struct dns_lookup_t *dns_lookup, const char *name, dns_lookup_gethostbyname_callback_t callback, void *callback_arg)
{
	dns_lookup->callback = callback;
	dns_lookup->callback_arg = callback_arg;

	struct dns_entry_t *dns_entry = dns_manager_find_entry(name);
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
	dns_entry->expire_time = timer_get_ticks() + (ticks_t)DNS_ENTRY_EXPIRE_TIME_PENDING_SEC * TICK_RATE;
	dns_entry->retry_on_failure = true;

	dns_lookup_ref(dns_lookup);
	slist_attach_tail(struct dns_lookup_t, &dns_entry->dns_lookup_list, dns_lookup);
	slist_attach_tail(struct dns_entry_t, &dns_manager.dns_list, dns_entry);

	dns_manager_send_request(dns_entry, dns_manager.dns_ip_primary);
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

void dns_manager_set_server_ip(ipv4_addr_t dns_ip_primary, ipv4_addr_t dns_ip_secondary)
{
	if (!ip_addr_is_unicast(dns_ip_primary)) {
		dns_ip_primary = 0;
	}
	if (!ip_addr_is_unicast(dns_ip_secondary)) {
		dns_ip_secondary = 0;
	}

	if (dns_ip_primary == 0) {
		dns_ip_primary = dns_ip_secondary;
	}
	if (dns_ip_secondary == 0) {
		dns_ip_secondary = dns_ip_primary;
	}

	dns_manager.dns_ip_primary = dns_ip_primary;
	dns_manager.dns_ip_secondary = dns_ip_secondary;
}

void dns_manager_init(void)
{
	dns_manager.sock = udp_socket_alloc();
	if (!dns_manager.sock) {
		DEBUG_ASSERT(0, "out of memory");
		return;
	}

	oneshot_init(&dns_manager.timer);
	udp_socket_listen(dns_manager.sock, NULL, 0, 0, dns_manager_recv, NULL, NULL);
}
