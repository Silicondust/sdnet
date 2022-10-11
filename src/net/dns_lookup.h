/*
 * dns_lookup.h
 *
 * Copyright © 2012-2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DNS_RECORD_TYPE_A 0x0001
#define DNS_RECORD_TYPE_AAAA 0x001C

struct dns_lookup_t;

typedef void (*dns_lookup_gethostbyname_callback_t)(void *arg, uint16_t record_type, const ip_addr_t *ip, ticks_t expire_time);

extern struct dns_lookup_t *dns_lookup_alloc(void);
extern struct dns_lookup_t *dns_lookup_ref(struct dns_lookup_t *dns);
extern int dns_lookup_deref(struct dns_lookup_t *dns);
extern bool dns_lookup_gethostbyname(struct dns_lookup_t *dns_lookup, const char *name, uint16_t record_type, dns_lookup_gethostbyname_callback_t callback, void *callback_arg);

extern void dns_manager_init(void);
extern void dns_manager_set_server_a_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary);
extern void dns_manager_set_server_aaaa_type(const ip_addr_t *server_primary, const ip_addr_t *server_secondary);
