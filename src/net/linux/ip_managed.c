/*
 * ip_managed.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <linux/route.h>
#include <linux/sockios.h>
#include <linux/mii.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_managed");

struct ip_datalink_instance {
	struct slist_prefix_t slist_prefix;
	char interface_name[IFNAMSIZ];
	int ioctl_sock;
	ipv4_addr_t ip_addr;
	ipv4_addr_t subnet_mask;
	uint8_t mac_addr[6];
	uint8_t metric;
	bool secondary;
};

static struct slist_t ip_datalink_list;

ipv4_addr_t ip_datalink_get_ipaddr(struct ip_datalink_instance *idi)
{
	return idi->ip_addr;
}

ipv4_addr_t ip_datalink_get_subnet_mask(struct ip_datalink_instance *idi)
{
	return idi->subnet_mask;
}

ipv4_addr_t ip_datalink_get_subnet_broadcast(struct ip_datalink_instance *idi)
{
	ipv4_addr_t subnet_broadcast = idi->ip_addr | ~idi->subnet_mask;
	if (subnet_broadcast == idi->ip_addr) {
		return 0;
	}

	return subnet_broadcast;
}

void ip_datalink_get_hwaddr(struct ip_datalink_instance *idi, uint8_t *hwaddr, uint8_t hwaddr_len)
{
	DEBUG_ASSERT(hwaddr_len == 6, "invalid length");
	memcpy(hwaddr, idi->mac_addr, 6);
}

char *ip_datalink_get_interface_name(struct ip_datalink_instance *idi)
{
	return idi->interface_name;
}

int ip_datalink_get_ifindex(struct ip_datalink_instance *idi)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, idi->interface_name, IFNAMSIZ);
	if (ioctl(idi->ioctl_sock, SIOCGIFINDEX, &ifr) < 0) {
		 DEBUG_ERROR("ioctl failed %d", errno);
	}
	return ifr.ifr_ifindex;
}

static void ip_datalink_get_ifflags(struct ip_datalink_instance *idi, struct ifreq *ifr)
{
	memset(ifr, 0, sizeof(struct ifreq));
	strncpy(ifr->ifr_name, idi->interface_name, IFNAMSIZ);
	if (ioctl(idi->ioctl_sock, SIOCGIFFLAGS, ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

static void ip_datalink_set_ifflags(struct ip_datalink_instance *idi, struct ifreq *ifr)
{
	if (ioctl(idi->ioctl_sock, SIOCSIFFLAGS, ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

static void ip_datalink_add_route(struct ip_datalink_instance *idi, ipv4_addr_t dst_ip, ipv4_addr_t dst_mask, ipv4_addr_t gateway)
{
	struct rtentry rte;
	memset(&rte, 0, sizeof(struct rtentry));

	rte.rt_dev = idi->interface_name;
	rte.rt_flags = RTF_UP;
	rte.rt_metric = idi->metric;

	if (gateway != 0) {
		rte.rt_flags |= RTF_GATEWAY;
	}

	struct sockaddr_in *rt_dst = (struct sockaddr_in *)&rte.rt_dst;
	rt_dst->sin_family = AF_INET;
	rt_dst->sin_addr.s_addr = htonl(dst_ip);

	struct sockaddr_in *rt_genmask = (struct sockaddr_in *)&rte.rt_genmask;
	rt_genmask->sin_family = AF_INET;
	rt_genmask->sin_addr.s_addr = htonl(dst_mask);

	struct sockaddr_in *rt_gateway = (struct sockaddr_in *)&rte.rt_gateway;
	rt_gateway->sin_family = AF_INET;
	rt_gateway->sin_addr.s_addr = htonl(gateway);

	if (ioctl(idi->ioctl_sock, SIOCADDRT, &rte) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

void ip_datalink_set_hwaddr(struct ip_datalink_instance *idi, uint8_t *hwaddr, uint8_t hwaddr_len)
{
	DEBUG_INFO("set mac addr");
	DEBUG_PRINT_HEX_ARRAY(hwaddr, hwaddr_len);
	DEBUG_ASSERT(hwaddr_len == 6, "invalid hwaddr_len %u", hwaddr_len);
	memcpy(idi->mac_addr, hwaddr, 6);

	struct ifreq ifflags;
	ip_datalink_get_ifflags(idi, &ifflags);
	ifflags.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
	ip_datalink_set_ifflags(idi, &ifflags);

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, idi->interface_name, IFNAMSIZ);
	ifr.ifr_hwaddr.sa_family = 1;
	memcpy(ifr.ifr_hwaddr.sa_data, hwaddr, 6);
	if (ioctl(idi->ioctl_sock, SIOCSIFHWADDR, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ip_datalink_set_ifflags(idi, &ifflags);

	ip_datalink_set_ipaddr(idi, 0, 0, 0);
}

void ip_datalink_set_ipaddr(struct ip_datalink_instance *idi, ipv4_addr_t ip_addr, ipv4_addr_t subnet_mask, ipv4_addr_t gateway)
{
	idi->ip_addr = ip_addr;
	idi->subnet_mask = subnet_mask;

	if (idi->secondary && (ip_addr == 0)) {
		struct ifreq ifflags;
		ip_datalink_get_ifflags(idi, &ifflags);
		ifflags.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
		ip_datalink_set_ifflags(idi, &ifflags);
		return;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, idi->interface_name, IFNAMSIZ);

	struct sockaddr_in *ifraddr = (struct sockaddr_in *)&ifr.ifr_addr;
	ifraddr->sin_family = AF_INET;

	ifraddr->sin_addr.s_addr = htonl(ip_addr);
	if (ioctl(idi->ioctl_sock, SIOCSIFADDR, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	if (ip_addr != 0) {
		ifraddr->sin_addr.s_addr = htonl(subnet_mask);
		if (ioctl(idi->ioctl_sock, SIOCSIFNETMASK, &ifr)) {
			DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		}

		ifraddr->sin_addr.s_addr = htonl(ip_addr | ~subnet_mask);
		if (ioctl(idi->ioctl_sock, SIOCSIFBRDADDR, &ifr)) {
			DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		}
	}

	if (idi->secondary) {
		struct ifreq ifflags;
		ip_datalink_get_ifflags(idi, &ifflags);
		ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
		ip_datalink_set_ifflags(idi, &ifflags);
	}

	DEBUG_INFO("adding broadcast route");
	ip_datalink_add_route(idi, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000);

	if (ip_addr != 0) {
		DEBUG_INFO("adding multicast route");
		ip_datalink_add_route(idi, 0xE0000000, 0xF0000000, 0x00000000);
	}

	if (gateway != 0) {
		DEBUG_INFO("adding gateway route");
		ip_datalink_add_route(idi, 0x00000000, 0x00000000, gateway);
	}
}

void ip_datalink_set_loopback(struct ip_datalink_instance *idi)
{
	idi->ip_addr = LOCALHOST;
	idi->subnet_mask = 0xFF000000;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, idi->interface_name, IFNAMSIZ);

	struct sockaddr_in *ifraddr = (struct sockaddr_in *)&ifr.ifr_addr;
	ifraddr->sin_family = AF_INET;

	ifraddr->sin_addr.s_addr = htonl(idi->ip_addr);
	if (ioctl(idi->ioctl_sock, SIOCSIFADDR, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	ifraddr->sin_addr.s_addr = htonl(idi->subnet_mask);
	if (ioctl(idi->ioctl_sock, SIOCSIFNETMASK, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	struct ifreq ifflags;
	ip_datalink_get_ifflags(idi, &ifflags);
	ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ip_datalink_set_ifflags(idi, &ifflags);
}

bool ip_datalink_read_ethernet_mii_register(struct ip_datalink_instance *idi, uint8_t reg_addr, uint16_t *presult)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, idi->interface_name, IFNAMSIZ);

	struct mii_ioctl_data *mii = (struct mii_ioctl_data *)&ifr.ifr_data;
	mii->reg_num = reg_addr;

	if (ioctl(idi->ioctl_sock, SIOCGMIIPHY, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		*presult = 0;
		return false;
	}

	if (ioctl(idi->ioctl_sock, SIOCGMIIREG, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		*presult = 0;
		return false;
	}

	*presult = mii->val_out;
	return true;
}

struct ip_datalink_instance *ip_datalink_manager_get_head(void)
{
	return slist_get_head(struct ip_datalink_instance, &ip_datalink_list);
}

struct ip_datalink_instance *ip_datalink_manager_get_by_local_ip(ipv4_addr_t local_ip)
{
	struct ip_datalink_instance *idi = slist_get_head(struct ip_datalink_instance, &ip_datalink_list);
	while (idi) {
		if (idi->ip_addr == local_ip) {
			return idi;
		}

		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	return NULL;
}

struct ip_datalink_instance *ip_datalink_manager_get_by_remote_ip(ipv4_addr_t remote_ip)
{
	struct ip_datalink_instance *idi = slist_get_head(struct ip_datalink_instance, &ip_datalink_list);
	while (idi) {
		if (idi->subnet_mask == 0) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if ((idi->ip_addr & idi->subnet_mask) == (remote_ip & idi->subnet_mask)) {
			return idi;
		}

		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	return slist_get_head(struct ip_datalink_instance, &ip_datalink_list);
}

struct ip_datalink_instance *ip_datalink_manager_ip_datalink_alloc(const char *interface_name, uint8_t metric)
{
	struct ip_datalink_instance *idi = (struct ip_datalink_instance *)heap_alloc_and_zero(sizeof(struct ip_datalink_instance), PKG_OS, MEM_TYPE_OS_IP_DATALINK);
	if (!idi) {
		return NULL;
	}

	idi->ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	sprintf_custom(idi->interface_name, idi->interface_name + sizeof(idi->interface_name), "%s", interface_name);
	idi->metric = metric;
	idi->secondary = (strchr(interface_name, ':') != 0);

	slist_attach_tail(struct ip_datalink_instance, &ip_datalink_list, idi);
	return idi;
}

void ip_datalink_manager_init(void)
{
}
