/*
 * ip_addr.h
 *
 * Copyright © 2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	IP_MODE_IPV4 = 0,
	IP_MODE_IPV6 = 1
} ip_mode_t;

typedef enum {
	IP_TYPE_ZERO = 0,
	IP_TYPE_INVALID = 1,
	IP_TYPE_IPV4_LOCALHOST = 2,
	IP_TYPE_IPV4_LINKLOCAL = 3,
	IP_TYPE_IPV4_SITELOCAL = 4,
	IP_TYPE_IPV4_PUBLIC = 5,
	IP_TYPE_IPV4_MULTICAST_LINKLOCAL = 6,
	IP_TYPE_IPV4_MULTICAST_SITELOCAL = 7,
	IP_TYPE_IPV4_MULTICAST_PUBLIC = 8,
	IP_TYPE_IPV4_BROADCAST = 9,
	IP_TYPE_IPV6_LOCALHOST = 10,
	IP_TYPE_IPV6_LINKLOCAL = 11,
	IP_TYPE_IPV6_SITELOCAL = 12,
	IP_TYPE_IPV6_PUBLIC = 13,
	IP_TYPE_IPV6_MULTICAST_LINKLOCAL = 14,
	IP_TYPE_IPV6_MULTICAST_SITELOCAL = 15,
	IP_TYPE_IPV6_MULTICAST_PUBLIC = 16,
} ip_type_t;

#if defined(IPV6_SUPPORT)

typedef struct {
	uint64_t high;
	uint64_t low;
} ip_addr_t;

#else

typedef struct {
	ipv4_addr_t ipv4;
} ip_addr_t;

#endif

extern const ip_addr_t ip_addr_zero;
extern const ip_addr_t ip_addr_ipv4_localhost;
extern const ip_addr_t ip_addr_ipv4_broadcast;

extern ip_type_t ip_addr_get_type(const ip_addr_t *ip);
extern uint8_t ip_addr_compute_score(const ip_addr_t *ip); /* lower is better */

extern bool ip_addr_is_zero(const ip_addr_t *ip);
extern bool ip_addr_is_non_zero(const ip_addr_t *ip);
extern bool ip_addr_is_ipv4(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6(const ip_addr_t *ip);
extern bool ip_addr_is_localhost(const ip_addr_t *ip);
extern bool ip_addr_is_unicast(const ip_addr_t *ip);
extern bool ip_addr_is_unicast_not_localhost(const ip_addr_t *ip);
extern bool ip_addr_is_sitelocal(const ip_addr_t *ip);
extern bool ip_addr_is_public(const ip_addr_t *ip);
extern bool ip_addr_is_multicast(const ip_addr_t *ip);
extern bool ip_addr_is_routable(const ip_addr_t *ip);
extern bool ip_addr_is_ipv4_linklocal(const ip_addr_t *ip);
extern bool ip_addr_is_ipv4_broadcast(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6_localhost(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6_linklocal(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6_public(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6_multicast_linklocal(const ip_addr_t *ip);
extern bool ip_addr_is_ipv6_linklocal_or_multicast_linklocal(const ip_addr_t *ip);

extern bool ip_addr_cmp(const ip_addr_t *ip1, const ip_addr_t *ip2);
extern bool ip_addr_cmp_less_than(const ip_addr_t *ip1, const ip_addr_t *ip2);
extern bool ip_addr_cmp_greater_than_or_equal(const ip_addr_t *ip1, const ip_addr_t *ip2);
extern bool ip_addr_cmp_subnet(const ip_addr_t *ip1, const ip_addr_t *ip2, const ip_addr_t *subnet_mask);

extern bool ip_addr_ipv6_scope_id_check(const ip_addr_t *ip, uint32_t ipv6_scope_id);

extern ipv4_addr_t ip_addr_get_ipv4(const ip_addr_t *ip);
extern void ip_addr_get_ipv6_bytes(const ip_addr_t *ip, uint8_t output[16]);
extern uint8_t ip_addr_get_cidr_from_subnet_mask(const ip_addr_t *subnet_mask);

extern void ip_addr_set_zero(ip_addr_t *ip);
extern void ip_addr_set_ipv4(ip_addr_t *ip, ipv4_addr_t ipv4);
extern void ip_addr_set_ipv6_bytes(ip_addr_t *ip, uint8_t input[16]);
extern void ip_addr_set_subnet_mask_from_cidr(ip_addr_t *subnet_mask, const ip_addr_t *reference_ip, uint8_t cidr);

static inline bool ipv4_addr_is_unicast(ipv4_addr_t addr)
{
	uint8_t v = (uint8_t)(addr >> 24);
	return ((v >= 1) && (v < 127)) || ((v >= 128) && (v < 224));
}

#if defined(IPV6_SUPPORT)

#define DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(ip, ipv6_scope_id) \
	if (RUNTIME_DEBUG && !ip_addr_ipv6_scope_id_check(ip, ipv6_scope_id)) { \
		DEBUG_ERROR("invalid ipv6 addr/scope_id state"); \
	}

#define IP_ADDR_INIT_IPV4(v) { \
	.high = 0, \
	.low = 0x0000FFFF00000000ULL | (uint64_t)(uint32_t)v \
}

#define IP_ADDR_INIT_IPV6(v0, v1, v2, v3, v4, v5, v6, v7) { \
	.high = ((uint64_t)(uint16_t)v0 << 48) | ((uint64_t)(uint16_t)v1 << 32) | ((uint64_t)(uint16_t)v2 << 16) | ((uint64_t)(uint16_t)v3 << 0), \
	.low = ((uint64_t)(uint16_t)v4 << 48) | ((uint64_t)(uint16_t)v5 << 32) | ((uint64_t)(uint16_t)v6 << 16) | ((uint64_t)(uint16_t)v7 << 0), \
}

extern const ip_addr_t ip_addr_ipv6_localhost;

extern inline bool ip_addr_is_zero(const ip_addr_t *ip)
{
	return (ip->low == 0) && (ip->high == 0);
}

extern inline bool ip_addr_is_non_zero(const ip_addr_t *ip)
{
	return (ip->low != 0) || (ip->high != 0);
}

extern inline bool ip_addr_is_ipv4(const ip_addr_t *ip)
{
	return (ip->high == 0) && ((uint32_t)(ip->low >> 32) == 0x0000FFFFUL);
}

extern inline bool ip_addr_is_ipv6(const ip_addr_t *ip)
{
	if (ip->high != 0) {
		return true;
	}
	return (ip->low != 0) && ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL);
}

extern inline bool ip_addr_cmp(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	return (ip1->low == ip2->low) && (ip1->high == ip2->high);
}

extern inline bool ip_addr_cmp_less_than(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	if (ip1->high == ip2->high) {
		return (ip1->low < ip2->low);
	}
	return (ip1->high < ip2->high);
}

extern inline bool ip_addr_cmp_greater_than_or_equal(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	if (ip1->high == ip2->high) {
		return (ip1->low >= ip2->low);
	}
	return (ip1->high >= ip2->high);
}

extern inline void ip_addr_set_zero(ip_addr_t *ip)
{
	ip->high = 0;
	ip->low = 0;
}

#else

#define DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(ip, ipv6_scope_id)

#define IP_ADDR_INIT_IPV4(v) { .ipv4 = v }
#define IP_ADDR_INIT_IPV6(v0, v1, v2, v3, v4, v5, v6, v7) { .ipv4 = 0 }

extern inline bool ip_addr_is_zero(const ip_addr_t *ip)
{
	return (ip->ipv4 == 0);
}

extern inline bool ip_addr_is_non_zero(const ip_addr_t *ip)
{
	return (ip->ipv4 != 0);
}

extern inline bool ip_addr_is_ipv4(const ip_addr_t *ip)
{
	return (ip->ipv4 != 0);
}

extern inline bool ip_addr_is_ipv6(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_is_ipv6_localhost(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_is_ipv6_linklocal(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_is_ipv6_public(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_is_ipv6_multicast_linklocal(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_is_ipv6_linklocal_or_multicast_linklocal(const ip_addr_t *ip)
{
	return false;
}

extern inline bool ip_addr_cmp(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	return (ip1->ipv4 == ip2->ipv4);
}

extern inline bool ip_addr_cmp_less_than(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	return (ip1->ipv4 < ip2->ipv4);
}

extern inline bool ip_addr_cmp_greater_than_or_equal(const ip_addr_t *ip1, const ip_addr_t *ip2)
{
	return (ip1->ipv4 >= ip2->ipv4);
}

extern inline bool ip_addr_ipv6_scope_id_check(const ip_addr_t *ip, uint32_t ipv6_scope_id)
{
	return true;
}

extern inline ipv4_addr_t ip_addr_get_ipv4(const ip_addr_t *ip)
{
	return ip->ipv4;
}

extern inline void ip_addr_set_zero(ip_addr_t *ip)
{
	ip->ipv4 = 0;
}

extern inline void ip_addr_set_ipv4(ip_addr_t *ip, ipv4_addr_t ipv4)
{
	ip->ipv4 = ipv4;
}

#endif
