/*
 * ./src/net/libc/dns_lookup.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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
	dns_lookup_gethostbyname_callback_t callback;
	void *callback_arg;
	ipv4_addr_t callback_result;
};

struct dns_lookup_t *dns_lookup_ref(struct dns_lookup_t *dns)
{
	dns->refs++;
	return dns;
}

int dns_lookup_deref(struct dns_lookup_t *dns)
{
	dns->refs--;
	if (dns->refs != 0) {
		return dns->refs;
	}

	if (dns->name_to_lookup) {
		heap_free(dns->name_to_lookup);
	}

	heap_free(dns);
	return 0;
}

static void dns_lookup_gethostbyname_complete(void *arg)
{
	struct dns_lookup_t *dns = (struct dns_lookup_t *)arg;
	if (dns_lookup_deref(dns) == 0) {
		return;
	}

	heap_free(dns->name_to_lookup);
	dns->name_to_lookup = NULL;

	if (dns->callback) {
		dns->callback(dns->callback_arg, dns->callback_result, TICK_RATE * 30);
	}
}

static bool dns_lookup_gethostbyname_execute(void *arg)
{
	struct dns_lookup_t *dns = (struct dns_lookup_t *)arg;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *sock_info;
	if (getaddrinfo(dns->name_to_lookup, 0, &hints, &sock_info) != 0) {
		DEBUG_WARN("dns_lookup_gethostbylabel: %s failed (%d)", dns->name_to_lookup, errno);
		dns->callback_result = 0;
		return false;
	}

	struct sockaddr_in *sock_addr;
	sock_addr = (struct sockaddr_in *)sock_info->ai_addr;
	dns->callback_result = ntohl(sock_addr->sin_addr.s_addr);
	freeaddrinfo(sock_info);

	DEBUG_INFO("dns_lookup_gethostbylabel: %s = %v", dns->name_to_lookup, dns->callback_result);
	return true;
}

bool dns_lookup_gethostbyname(struct dns_lookup_t *dns, const char *name, dns_lookup_gethostbyname_callback_t callback, void *callback_arg)
{
	if (dns->name_to_lookup) {
		DEBUG_ERROR("lookup in progress");
		return false;
	}

	dns->name_to_lookup = heap_strdup(name, PKG_OS, MEM_TYPE_OS_DNS_LOOKUP_NAME);
	if (!dns->name_to_lookup) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	dns->callback = callback;
	dns->callback_arg = callback_arg;
	
	dns_lookup_ref(dns);
	if (!long_task_enqueue(dns_lookup_gethostbyname_execute, dns_lookup_gethostbyname_complete, dns_lookup_gethostbyname_complete, dns)) {
		DEBUG_ERROR("long_task error");
		dns_lookup_deref(dns);
		return false;
	}

	return true;
}

struct dns_lookup_t *dns_lookup_alloc(void)
{
	struct dns_lookup_t *dns = (struct dns_lookup_t *)heap_alloc_and_zero(sizeof(struct dns_lookup_t), PKG_OS, MEM_TYPE_OS_DNS_LOOKUP);
	if (!dns) {
		return NULL;
	}

	dns->refs = 1;
	return dns;
}

void dns_manager_init(void)
{
}

