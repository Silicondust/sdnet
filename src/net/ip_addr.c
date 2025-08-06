/*
 * ip_addr.c
 *
 * Copyright © 2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("ip_addr");

#if defined(IPV6_SUPPORT)

const ip_addr_t ip_addr_zero = { .high = 0x0000000000000000ULL, .low = 0x0000000000000000ULL };
const ip_addr_t ip_addr_ipv4_localhost = { .high = 0x0000000000000000ULL, .low = 0x0000FFFF7F000001ULL };
const ip_addr_t ip_addr_ipv4_broadcast = { .high = 0x0000000000000000ULL, .low = 0x0000FFFFFFFFFFFFULL };
const ip_addr_t ip_addr_ipv6_localhost = { .high = 0x0000000000000000ULL, .low = 0x0000000000000001ULL };

static inline ip_type_t ip_addr_get_type_ipv4(ipv4_addr_t ipv4)
{
	uint8_t byte0 = (uint8_t)(ipv4 >> 24);

	if (byte0 >= 224) {
		if (ipv4 == 0xFFFFFFFF) {
			return IP_TYPE_IPV4_BROADCAST;
		}
		if (byte0 < 239) {
			return (ipv4 <= 0xE00000FF) ? IP_TYPE_IPV4_MULTICAST_LINKLOCAL : IP_TYPE_IPV4_MULTICAST_PUBLIC;
		}
		if (byte0 == 239) {
			return IP_TYPE_IPV4_MULTICAST_SITELOCAL;
		}

		return IP_TYPE_INVALID;
	}

	if (byte0 == 0) {
		return IP_TYPE_INVALID;
	}
	if (byte0 == 10) {
		return IP_TYPE_IPV4_SITELOCAL;
	}
	if (byte0 == 127) {
		return IP_TYPE_IPV4_LOCALHOST;
	}
	if (byte0 == 169) {
		uint8_t byte1 = (uint8_t)(ipv4 >> 16);
		return (byte1 == 254) ? IP_TYPE_IPV4_LINKLOCAL : IP_TYPE_IPV4_PUBLIC;
	}
	if (byte0 == 172) {
		uint8_t byte1 = (uint8_t)(ipv4 >> 16);
		return ((byte1 & 0xF0) == 16) ? IP_TYPE_IPV4_SITELOCAL : IP_TYPE_IPV4_PUBLIC;
	}
	if (byte0 == 192) {
		uint8_t byte1 = (uint8_t)(ipv4 >> 16);
		return (byte1 == 168) ? IP_TYPE_IPV4_SITELOCAL : IP_TYPE_IPV4_PUBLIC;
	}

	return IP_TYPE_IPV4_PUBLIC;
}

ip_type_t ip_addr_get_type(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if (ip->low == 0) {
			return IP_TYPE_ZERO;
		}
		if (ip->low == 1) {
			return IP_TYPE_IPV6_LOCALHOST;
		}
		if ((uint32_t)(ip->low >> 32) == 0x0000FFFFUL) {
			return ip_addr_get_type_ipv4((ipv4_addr_t)ip->low);
		}
		return IP_TYPE_INVALID;
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	if ((word0 & 0xE000) == 0x2000) { /* 2000::/3 */
		return IP_TYPE_IPV6_PUBLIC;
	}
	if ((word0 & 0xFE00) == 0xFC00) { /* FC00::/7 */
		return IP_TYPE_IPV6_SITELOCAL;
	}
	if ((word0 & 0xFFC0) == 0xFE80) { /* FE80::/10 */
		return IP_TYPE_IPV6_LINKLOCAL;
	}

	if ((word0 & 0xFF00) == 0xFF00) {
		switch (word0 & 0x000F) {
		case 0x2:
			return IP_TYPE_IPV6_MULTICAST_LINKLOCAL;
		case 0x3:
		case 0x4:
		case 0x5:
		case 0x8:
			return IP_TYPE_IPV6_MULTICAST_SITELOCAL;
		case 0xE:
			return IP_TYPE_IPV6_MULTICAST_PUBLIC;
		default:
			return IP_TYPE_INVALID;
		}
	}

	return IP_TYPE_INVALID;
}

uint8_t ip_addr_compute_score(const ip_addr_t *ip)
{
	switch (ip_addr_get_type(ip)) {
	case IP_TYPE_IPV6_LOCALHOST:
		return 0; /* highest priority */
	case IP_TYPE_IPV4_LOCALHOST:
		return 1;
	case IP_TYPE_IPV4_PUBLIC:
		return 2;
	case IP_TYPE_IPV4_SITELOCAL:
		return 3;
	case IP_TYPE_IPV6_PUBLIC:
		return 4;
	case IP_TYPE_IPV6_SITELOCAL:
		return 5;
	case IP_TYPE_IPV6_LINKLOCAL:
		return 6;
	case IP_TYPE_IPV4_LINKLOCAL:
		return 7;
	default:
		return 255;
	}
}

bool ip_addr_is_localhost(const ip_addr_t *ip)
{
	if (ip->high != 0) {
		return false;
	}

	return (ip->low == 1) || ((ip->low >> 24) == 0x0000FFFF7FULL);
}

bool ip_addr_is_unicast(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
			return (ip->low == 1);
		}

		uint8_t byte0 = (uint8_t)(ip->low >> 24);
		return ((byte0 >= 1) && (byte0 < 224));
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	if ((word0 & 0xE000) == 0x2000) { /* 2000::/3 */
		return true;
	}
	if ((word0 & 0xFE00) == 0xFC00) { /* FC00::/7 */
		return true;
	}
	if ((word0 & 0xFFC0) == 0xFE80) { /* FE80::/10 */
		return true;
	}

	return false;
}

bool ip_addr_is_unicast_not_localhost(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
			return false;
		}

		uint8_t byte0 = (uint8_t)(ip->low >> 24);
		return ((byte0 >= 1) && (byte0 < 127)) || ((byte0 >= 128) && (byte0 < 224));
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	if ((word0 & 0xE000) == 0x2000) { /* 2000::/3 */
		return true;
	}
	if ((word0 & 0xFE00) == 0xFC00) { /* FC00::/7 */
		return true;
	}
	if ((word0 & 0xFFC0) == 0xFE80) { /* FE80::/10 */
		return true;
	}

	return false;
}

bool ip_addr_is_sitelocal(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
			return false;
		}

		uint8_t byte0 = (uint8_t)(ip->low >> 24);

		if (byte0 == 10) {
			return true;
		}
		if (byte0 == 172) {
			uint8_t byte1 = (uint8_t)(ip->low >> 16);
			return ((byte1 & 0xF0) == 16);
		}
		if (byte0 == 192) {
			uint8_t byte1 = (uint8_t)(ip->low >> 16);
			return (byte1 == 168);
		}

		return false;
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	if ((word0 & 0xFE00) == 0xFC00) { /* FC00::/7 */
		return true;
	}

	return false;
}

bool ip_addr_is_public(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
			return false;
		}

		uint8_t byte0 = (uint8_t)(ip->low >> 24);

		if (byte0 == 0) {
			return false;
		}
		if (byte0 == 10) {
			return false;
		}
		if (byte0 == 127) {
			return false;
		}
		if (byte0 == 169) {
			uint8_t byte1 = (uint8_t)(ip->low >> 16);
			return (byte1 != 254);
		}
		if (byte0 == 172) {
			uint8_t byte1 = (uint8_t)(ip->low >> 16);
			return ((byte1 & 0xF0) != 16);
		}
		if (byte0 == 192) {
			uint8_t byte1 = (uint8_t)(ip->low >> 16);
			return (byte1 != 168);
		}
		if (byte0 >= 224) {
			return false;
		}

		return true;
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	return ((word0 & 0xE000) == 0x2000); /* 2000::/3 */
}

bool ip_addr_is_multicast(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		return ((ip->low >> 28) == 0x0000FFFFEULL);
	}

	return ((uint32_t)(ip->high >> 56) == 0xFF);
}

bool ip_addr_is_routable(const ip_addr_t *ip)
{
	if (ip->high == 0) {
		if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
			return false;
		}

		uint16_t v = (uint16_t)(ip->low >> 16);
		return ((v >= 0x0100) && (v < 0x7F00)) || ((v >= 0x8000) && (v < 0xA9FE)) || ((v >= 0xA9FF) && (v < 0xE000));
	}

	uint16_t word0 = (uint16_t)(ip->high >> 48);
	if ((word0 & 0xE000) == 0x2000) { /* 2000::/3 */
		return true;
	}
	if ((word0 & 0xFE00) == 0xFC00) { /* FC00::/7 */
		return true;
	}

	return false;
}

bool ip_addr_is_ipv4_linklocal(const ip_addr_t *ip)
{
	if (ip->high != 0) {
		return false;
	}

	return ((ip->low >> 16) == 0x0000FFFFA9FEULL);
}

bool ip_addr_is_ipv4_multicast(const ip_addr_t *ip)
{
	if (ip->high != 0) {
		return false;
	}

	if ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL) {
		return false;
	}

	uint8_t byte0 = (uint8_t)(ip->low >> 24);
	return (byte0 >= 224) && (byte0 <= 239);
}

bool ip_addr_is_ipv4_broadcast(const ip_addr_t *ip)
{
	if (ip->high != 0) {
		return false;
	}

	return (ip->low == 0x0000FFFFFFFFFFFFULL);
}

bool ip_addr_is_ipv6_localhost(const ip_addr_t *ip)
{
	return (ip->high == 0) && (ip->low == 1);
}

bool ip_addr_is_ipv6_linklocal(const ip_addr_t *ip)
{
	uint16_t word0 = (uint16_t)(ip->high >> 48);
	return ((word0 & 0xFFC0) == 0xFE80); /* FE80::/10 */
}

bool ip_addr_is_ipv6_public(const ip_addr_t *ip)
{
	uint16_t word0 = (uint16_t)(ip->high >> 48);
	return ((word0 & 0xE000) == 0x2000); /* 2000::/3 */
}

bool ip_addr_is_ipv6_multicast_linklocal(const ip_addr_t *ip)
{
	uint16_t word0 = (uint16_t)(ip->high >> 48);
	return ((word0 & 0xFF0F) == 0xFF02);
}

bool ip_addr_is_ipv6_linklocal_or_multicast_linklocal(const ip_addr_t *ip)
{
	uint16_t word0 = (uint16_t)(ip->high >> 48);
	return ((word0 & 0xFFC0) == 0xFE80) || ((word0 & 0xFF0F) == 0xFF02);
}

bool ip_addr_cmp_subnet(const ip_addr_t *ip1, const ip_addr_t *ip2, const ip_addr_t *subnet_mask)
{
	if (subnet_mask->high == 0) {
		if (!ip_addr_is_ipv4(subnet_mask) || !ip_addr_is_ipv4(ip1) || !ip_addr_is_ipv4(ip2)) {
			return false;
		}

		if ((uint32_t)subnet_mask->low == 0) {
			return false;
		}

		return (((uint32_t)ip1->low ^ (uint32_t)ip2->low) & (uint32_t)subnet_mask->low) == 0;
	}

	if (ip_addr_is_ipv4(ip1) || ip_addr_is_ipv4(ip2)) {
		return false;
	}

	return (((ip1->high ^ ip2->high) & subnet_mask->high) == 0) && (((ip1->low ^ ip2->low) & subnet_mask->low) == 0);
}

bool ip_addr_ipv6_scope_id_check(const ip_addr_t *ip, uint32_t ipv6_scope_id)
{
	if (ip_addr_is_ipv6_linklocal(ip)) {
		return (ipv6_scope_id != 0);
	}

	if (ip_addr_is_ipv6_multicast_linklocal(ip)) {
		return true;
	}

	return (ipv6_scope_id == 0);
}

ipv4_addr_t ip_addr_get_ipv4(const ip_addr_t *ip)
{
	if ((ip->high != 0) || ((uint32_t)(ip->low >> 32) != 0x0000FFFFUL)) {
		return 0;
	}

	return (ipv4_addr_t)ip->low;
}

void ip_addr_get_ipv6_bytes(const ip_addr_t *ip, uint8_t output[16])
{
	output[0] = (uint8_t)(ip->high >> 56);
	output[1] = (uint8_t)(ip->high >> 48);
	output[2] = (uint8_t)(ip->high >> 40);
	output[3] = (uint8_t)(ip->high >> 32);
	output[4] = (uint8_t)(ip->high >> 24);
	output[5] = (uint8_t)(ip->high >> 16);
	output[6] = (uint8_t)(ip->high >> 8);
	output[7] = (uint8_t)(ip->high >> 0);
	output[8] = (uint8_t)(ip->low >> 56);
	output[9] = (uint8_t)(ip->low >> 48);
	output[10] = (uint8_t)(ip->low >> 40);
	output[11] = (uint8_t)(ip->low >> 32);
	output[12] = (uint8_t)(ip->low >> 24);
	output[13] = (uint8_t)(ip->low >> 16);
	output[14] = (uint8_t)(ip->low >> 8);
	output[15] = (uint8_t)(ip->low >> 0);
}

uint8_t ip_addr_get_cidr_from_subnet_mask(const ip_addr_t *subnet_mask)
{
	uint8_t result = 0;
	uint32_t v;

	if (subnet_mask->high == 0) {
		if ((uint32_t)(subnet_mask->low >> 32) != 0x0000FFFFUL) {
			return 0;
		}

		v = (uint32_t)subnet_mask->low;
	} else {
		v = (uint32_t)(subnet_mask->high >> 32);
		if (v == 0xFFFFFFFFUL) {
			result += 32;
			v = (uint32_t)subnet_mask->high;
			if (v == 0xFFFFFFFFUL) {
				result += 32;
				v = (uint32_t)(subnet_mask->low >> 32);
				if (v == 0xFFFFFFFFUL) {
					result += 32;
					v = (uint32_t)subnet_mask->low;
				}
			}
		}
	}
	
	while ((v & 0xFF000000UL) == 0xFF000000UL) {
		result += 8;
		v <<= 8;
	}

	while (v & 0x80000000UL) {
		result++;
		v <<= 1;
	}

	return result;
}

void ip_addr_set_ipv4(ip_addr_t *ip, ipv4_addr_t ipv4)
{
	ip->high = 0;

	if (ipv4 == 0) {
		ip->low = 0;
	} else {
		ip->low = 0x0000FFFF00000000ULL | (uint64_t)ipv4;
	}
}

void ip_addr_set_ipv6_bytes(ip_addr_t *ip, uint8_t input[16])
{
	ip->high = (uint64_t)input[0] << 56;
	ip->high |= (uint64_t)input[1] << 48;
	ip->high |= (uint64_t)input[2] << 40;
	ip->high |= (uint64_t)input[3] << 32;
	ip->high |= (uint64_t)input[4] << 24;
	ip->high |= (uint64_t)input[5] << 16;
	ip->high |= (uint64_t)input[6] << 8;
	ip->high |= (uint64_t)input[7] << 0;
	ip->low = (uint64_t)input[8] << 56;
	ip->low |= (uint64_t)input[9] << 48;
	ip->low |= (uint64_t)input[10] << 40;
	ip->low |= (uint64_t)input[11] << 32;
	ip->low |= (uint64_t)input[12] << 24;
	ip->low |= (uint64_t)input[13] << 16;
	ip->low |= (uint64_t)input[14] << 8;
	ip->low |= (uint64_t)input[15] << 0;
}

void ip_addr_set_subnet_mask_from_cidr(ip_addr_t *subnet_mask, const ip_addr_t *reference_ip, uint8_t cidr)
{
	if (reference_ip->high == 0) {
		if (reference_ip->low == 0) {
			ip_addr_set_zero(subnet_mask);
			return;
		}
		if (ip_addr_is_ipv4(reference_ip)) {
			if (cidr > 32) {
				ip_addr_set_zero(subnet_mask);
				return;
			}
			ip_addr_set_ipv4(subnet_mask, 0xFFFFFFFFUL << (32 - cidr));
			return;
		}
	}

	if (cidr <= 64) {
		subnet_mask->high = 0xFFFFFFFFFFFFFFFFULL << (64 - cidr);
		subnet_mask->low = 0;
		return;
	}

	if (cidr <= 128) {
		subnet_mask->high = 0xFFFFFFFFFFFFFFFFULL;
		subnet_mask->low = 0xFFFFFFFFFFFFFFFFULL << (128 - cidr);
		return;
	}

	ip_addr_set_zero(subnet_mask);
}

#else

const ip_addr_t ip_addr_zero = { .ipv4 = 0x00000000UL };
const ip_addr_t ip_addr_ipv4_localhost = { .ipv4 = 0x7F000001UL };
const ip_addr_t ip_addr_ipv4_broadcast = { .ipv4 = 0xFFFFFFFFUL };

ip_type_t ip_addr_get_type(const ip_addr_t *ip)
{
	if (ip->ipv4 == 0) {
		return IP_TYPE_ZERO;
	}

	uint8_t byte0 = (uint8_t)(ip->ipv4 >> 24);

	if (byte0 >= 224) {
		if (ip->ipv4 == 0xFFFFFFFF) {
			return IP_TYPE_IPV4_BROADCAST;
		}
		if (byte0 < 239) {
			return (ip->ipv4 <= 0xE00000FF) ? IP_TYPE_IPV4_MULTICAST_LINKLOCAL : IP_TYPE_IPV4_MULTICAST_PUBLIC;
		}
		if (byte0 == 239) {
			return IP_TYPE_IPV4_MULTICAST_SITELOCAL;
		}

		return IP_TYPE_INVALID;
	}

	if (byte0 == 0) {
		return IP_TYPE_INVALID;
	}
	if (byte0 == 10) {
		return IP_TYPE_IPV4_SITELOCAL;
	}
	if (byte0 == 127) {
		return IP_TYPE_IPV4_LOCALHOST;
	}
	if (byte0 == 169) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return (byte1 == 254) ? IP_TYPE_IPV4_LINKLOCAL : IP_TYPE_IPV4_PUBLIC;
	}
	if (byte0 == 172) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return ((byte1 & 0xF0) == 16) ? IP_TYPE_IPV4_SITELOCAL : IP_TYPE_IPV4_PUBLIC;
	}
	if (byte0 == 192) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return (byte1 == 168) ? IP_TYPE_IPV4_SITELOCAL : IP_TYPE_IPV4_PUBLIC;
	}

	return IP_TYPE_IPV4_PUBLIC;
}

uint8_t ip_addr_compute_score(const ip_addr_t *ip)
{
	switch (ip_addr_get_type(ip)) {
	case IP_TYPE_IPV4_LOCALHOST:
		return 0; /* highest priority */
	case IP_TYPE_IPV4_PUBLIC:
		return 1;
	case IP_TYPE_IPV4_SITELOCAL:
		return 2;
	case IP_TYPE_IPV4_LINKLOCAL:
		return 3;
	default:
		return 255;
	}
}

bool ip_addr_is_localhost(const ip_addr_t *ip)
{
	return ((ip->ipv4 >> 24) == 127);
}

bool ip_addr_is_unicast(const ip_addr_t *ip)
{
	uint8_t v = (uint8_t)(ip->ipv4 >> 24);
	return ((v >= 1) && (v < 224));
}

bool ip_addr_is_unicast_not_localhost(const ip_addr_t *ip)
{
	uint8_t v = (uint8_t)(ip->ipv4 >> 24);
	return ((v >= 1) && (v < 127)) || ((v >= 128) && (v < 224));
}

bool ip_addr_is_sitelocal(const ip_addr_t *ip)
{
	uint8_t byte0 = (uint8_t)(ip->ipv4 >> 24);

	if (byte0 == 10) {
		return true;
	}
	if (byte0 == 172) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return ((byte1 & 0xF0) == 16);
	}
	if (byte0 == 192) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return (byte1 == 168);
	}

	return false;
}

bool ip_addr_is_public(const ip_addr_t *ip)
{
	uint8_t byte0 = (uint8_t)(ip->ipv4 >> 24);

	if (byte0 == 0) {
		return false;
	}
	if (byte0 == 10) {
		return false;
	}
	if (byte0 == 127) {
		return false;
	}
	if (byte0 == 169) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return (byte1 != 254);
	}
	if (byte0 == 172) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return ((byte1 & 0xF0) != 16);
	}
	if (byte0 == 192) {
		uint8_t byte1 = (uint8_t)(ip->ipv4 >> 16);
		return (byte1 != 168);
	}
	if (byte0 >= 224) {
		return false;
	}

	return true;
}

bool ip_addr_is_multicast(const ip_addr_t *ip)
{
	return ((ip->ipv4 >> 28) == 0xE);
}

bool ip_addr_is_routable(const ip_addr_t *ip)
{
	uint16_t v = (uint16_t)(ip->ipv4 >> 16);
	return ((v >= 0x0100) && (v < 0x7F00)) || ((v >= 0x8000) && (v < 0xA9FE)) || ((v >= 0xA9FF) && (v < 0xE000));
}

bool ip_addr_is_ipv4_linklocal(const ip_addr_t *ip)
{
	return ((ip->ipv4 >> 16) == 0xA9FE);
}

bool ip_addr_is_ipv4_multicast(const ip_addr_t *ip)
{
	uint8_t byte0 = (uint8_t)(ip->ipv4 >> 24);
	return (byte0 >= 224) && (byte0 <= 239);
}

bool ip_addr_is_ipv4_broadcast(const ip_addr_t *ip)
{
	return (ip->ipv4 == 0xFFFFFFFFUL);
}

bool ip_addr_cmp_subnet(const ip_addr_t *ip1, const ip_addr_t *ip2, const ip_addr_t *subnet_mask)
{
	if (subnet_mask->ipv4 == 0) {
		return false;
	}

	return ((ip1->ipv4 ^ ip2->ipv4) & subnet_mask->ipv4) == 0;
}

void ip_addr_get_ipv6_bytes(const ip_addr_t *ip, uint8_t output[16])
{
	memset(output, 0, 10);
	output[10] = 0xFF;
	output[11] = 0xFF;
	output[12] = (uint8_t)(ip->ipv4 >> 24);
	output[13] = (uint8_t)(ip->ipv4 >> 16);
	output[14] = (uint8_t)(ip->ipv4 >> 8);
	output[15] = (uint8_t)(ip->ipv4 >> 0);
}

uint8_t ip_addr_get_cidr_from_subnet_mask(const ip_addr_t *subnet_mask)
{
	uint8_t result = 0;

	uint32_t v = subnet_mask->ipv4;
	while ((v & 0xFF000000UL) == 0xFF000000UL) {
		result += 8;
		v <<= 8;
	}

	while (v & 0x80000000UL) {
		result++;
		v <<= 1;
	}

	return result;
}

void ip_addr_set_ipv6_bytes(ip_addr_t *ip, uint8_t input[16])
{
	ip->ipv4 |= (uint64_t)input[12] << 24;
	ip->ipv4 |= (uint64_t)input[13] << 16;
	ip->ipv4 |= (uint64_t)input[14] << 8;
	ip->ipv4 |= (uint64_t)input[15] << 0;
}

void ip_addr_set_subnet_mask_from_cidr(ip_addr_t *subnet_mask, const ip_addr_t *reference_ip, uint8_t cidr)
{
	if (cidr > 32) {
		subnet_mask->ipv4 = 0;
		return;
	}

	subnet_mask->ipv4 = 0xFFFFFFFFUL << (32 - cidr);
}

#endif
