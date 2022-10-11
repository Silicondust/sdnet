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

THIS_FILE("dns");

struct dns_lookup_t {
	int refs;
	char *name_to_lookup;
	uint16_t record_type;
	dns_lookup_gethostbyname_callback_t callback;
	void *callback_arg;
	ip_addr_t callback_result;
};

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

	if (dns_lookup->name_to_lookup) {
		heap_free(dns_lookup->name_to_lookup);
	}

	heap_free(dns_lookup);
	return 0;
}

static void dns_lookup_gethostbyname_complete(void *arg)
{
	struct dns_lookup_t *dns_lookup = (struct dns_lookup_t *)arg;
	if (dns_lookup_deref(dns_lookup) == 0) {
		return;
	}

	heap_free(dns_lookup->name_to_lookup);
	dns_lookup->name_to_lookup = NULL;

	if (dns_lookup->callback) {
		dns_lookup->callback(dns_lookup->callback_arg, dns_lookup->record_type, &dns_lookup->callback_result, TICK_RATE * 30);
	}
}

static bool dns_lookup_gethostbyname_execute(void *arg)
{
	struct dns_lookup_t *dns_lookup = (struct dns_lookup_t *)arg;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = (dns_lookup->record_type == DNS_RECORD_TYPE_AAAA) ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *sock_info;
	if (getaddrinfo(dns_lookup->name_to_lookup, 0, &hints, &sock_info) != 0) {
		DEBUG_WARN("dns_lookup_gethostbylabel: %s failed (%d)", dns_lookup->name_to_lookup, errno);
		ip_addr_set_zero(&dns_lookup->callback_result);
		return false;
	}

	struct addrinfo *current = sock_info;
	while (current) {
#if defined(IPV6_SUPPORT)
		if ((current->ai_family == AF_INET6) && (dns_lookup->record_type == DNS_RECORD_TYPE_AAAA)) {
			ip_addr_t ip_addr;
			struct sockaddr_in6 *sock_addr = (struct sockaddr_in6 *)current->ai_addr;
			ip_addr_set_ipv6_bytes(&ip_addr, sock_addr->sin6_addr.s6_addr);

			if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
				current = current->ai_next;
				continue;
			}

			DEBUG_TRACE("dns_lookup_gethostbylabel: %s = %V", dns_lookup->name_to_lookup, &ip_addr);
			dns_lookup->callback_result = ip_addr;
			freeaddrinfo(sock_info);
			return true;
		}
#endif

		if ((current->ai_family == AF_INET) && (dns_lookup->record_type == DNS_RECORD_TYPE_A)) {
			ip_addr_t ip_addr;
			struct sockaddr_in *sock_addr = (struct sockaddr_in *)current->ai_addr;
			ip_addr_set_ipv4(&ip_addr, ntohl(sock_addr->sin_addr.s_addr));

			if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
				current = current->ai_next;
				continue;
			}

			DEBUG_TRACE("dns_lookup_gethostbylabel: %s = %V", dns_lookup->name_to_lookup, &ip_addr);
			dns_lookup->callback_result = ip_addr;
			freeaddrinfo(sock_info);
			return true;
		}

		current = current->ai_next;
		continue;
	}

	ip_addr_set_zero(&dns_lookup->callback_result);
	DEBUG_WARN("dns_lookup_gethostbylabel: %s no useful entry", dns_lookup->name_to_lookup);
	freeaddrinfo(sock_info);
	return false;
}

bool dns_lookup_gethostbyname(struct dns_lookup_t *dns_lookup, const char *name, uint16_t record_type, dns_lookup_gethostbyname_callback_t callback, void *callback_arg)
{
	if (dns_lookup->name_to_lookup) {
		DEBUG_ERROR("lookup in progress");
		return false;
	}

	dns_lookup->name_to_lookup = heap_strdup(name, PKG_OS, MEM_TYPE_OS_DNS_LOOKUP_NAME);
	if (!dns_lookup->name_to_lookup) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	dns_lookup->record_type = record_type;
	dns_lookup->callback = callback;
	dns_lookup->callback_arg = callback_arg;

	dns_lookup_ref(dns_lookup);
	if (!long_task_enqueue(dns_lookup_gethostbyname_execute, dns_lookup_gethostbyname_complete, dns_lookup_gethostbyname_complete, dns_lookup)) {
		DEBUG_ERROR("long_task error");
		dns_lookup_deref(dns_lookup);
		return false;
	}

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

void dns_manager_set_server_a_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary)
{
}

void dns_manager_set_server_aaaa_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary)
{
}

void dns_manager_init(void)
{
}
