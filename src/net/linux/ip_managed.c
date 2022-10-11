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
#include <linux/wireless.h>
#include <linux/mii.h>

/* net/if.net conflicts with linux headers */
extern unsigned int if_nametoindex(const char *ifname);

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_managed");

struct ip_managed_t {
	struct slist_prefix_t slist_prefix;
	char interface_name[IFNAMSIZ];
	int ioctl_sock;
	uint32_t ifindex;
	ip_addr_t ip_addr;
	ip_addr_t subnet_mask;
	uint8_t mac_addr[6];
	uint8_t metric;
	bool secondary;
};

char *ip_managed_get_interface_name(struct ip_managed_t *ipm)
{
	return ipm->interface_name;
}

uint32_t ip_managed_get_ifindex(struct ip_managed_t *ipm)
{
	return ipm->ifindex;
}

void ip_managed_get_mac_addr(struct ip_managed_t *ipm, uint8_t mac_addr[6])
{
	memcpy(mac_addr, ipm->mac_addr, 6);
}

void ip_managed_get_local_ip(struct ip_managed_t *ipm, ip_addr_t *result)
{
	*result = ipm->ip_addr;
}

void ip_managed_get_subnet_mask(struct ip_managed_t *ipm, ip_addr_t *result)
{
	*result = ipm->subnet_mask;
}

static void ip_managed_get_ifflags(struct ip_managed_t *ipm, struct ifreq *ifr)
{
	memset(ifr, 0, sizeof(struct ifreq));
	strncpy(ifr->ifr_name, ipm->interface_name, IFNAMSIZ);
	if (ioctl(ipm->ioctl_sock, SIOCGIFFLAGS, ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

static void ip_managed_set_ifflags(struct ip_managed_t *ipm, struct ifreq *ifr)
{
	if (ioctl(ipm->ioctl_sock, SIOCSIFFLAGS, ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

static void ip_managed_add_route(struct ip_managed_t *ipm, ipv4_addr_t dst_ip, ipv4_addr_t dst_mask, ipv4_addr_t gateway)
{
	struct rtentry rte;
	memset(&rte, 0, sizeof(struct rtentry));

	rte.rt_dev = ipm->interface_name;
	rte.rt_flags = RTF_UP;
	rte.rt_metric = ipm->metric;

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

	if (ioctl(ipm->ioctl_sock, SIOCADDRT, &rte) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}
}

void ip_managed_set_mac_addr(struct ip_managed_t *ipm, uint8_t mac_addr[6])
{
	DEBUG_INFO("set mac addr");
	DEBUG_PRINT_HEX_ARRAY(mac_addr, 6);
	memcpy(ipm->mac_addr, mac_addr, 6);

	struct ifreq ifflags;
	ip_managed_get_ifflags(ipm, &ifflags);
	ifflags.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
	ip_managed_set_ifflags(ipm, &ifflags);

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ipm->interface_name, IFNAMSIZ);
	ifr.ifr_hwaddr.sa_family = 1;
	memcpy(ifr.ifr_hwaddr.sa_data, mac_addr, 6);
	if (ioctl(ipm->ioctl_sock, SIOCSIFHWADDR, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ip_managed_set_ifflags(ipm, &ifflags);

	ip_managed_set_ipv4_addr(ipm, 0, 0, 0);
}

void ip_managed_set_ipv4_addr(struct ip_managed_t *ipm, ipv4_addr_t ip_addr, ipv4_addr_t subnet_mask, ipv4_addr_t gateway)
{
	ip_addr_set_ipv4(&ipm->ip_addr, ip_addr);
	ip_addr_set_ipv4(&ipm->subnet_mask, subnet_mask);

	if (ipm->secondary && (ip_addr == 0)) {
		struct ifreq ifflags;
		ip_managed_get_ifflags(ipm, &ifflags);
		ifflags.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
		ip_managed_set_ifflags(ipm, &ifflags);

		ip_interface_manager_redetect_required();
		igmp_manager_local_ip_changed();
		return;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ipm->interface_name, IFNAMSIZ);

	struct sockaddr_in *ifraddr = (struct sockaddr_in *)&ifr.ifr_addr;
	ifraddr->sin_family = AF_INET;

	ifraddr->sin_addr.s_addr = htonl(ip_addr);
	if (ioctl(ipm->ioctl_sock, SIOCSIFADDR, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	if (ip_addr != 0) {
		ifraddr->sin_addr.s_addr = htonl(subnet_mask);
		if (ioctl(ipm->ioctl_sock, SIOCSIFNETMASK, &ifr)) {
			DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		}

		ifraddr->sin_addr.s_addr = htonl(ip_addr | ~subnet_mask);
		if (ioctl(ipm->ioctl_sock, SIOCSIFBRDADDR, &ifr)) {
			DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		}
	}

	if (ipm->secondary) {
		struct ifreq ifflags;
		ip_managed_get_ifflags(ipm, &ifflags);
		ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
		ip_managed_set_ifflags(ipm, &ifflags);
	}

	DEBUG_INFO("adding broadcast route");
	ip_managed_add_route(ipm, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000);

	if (ip_addr != 0) {
		DEBUG_INFO("adding multicast route");
		ip_managed_add_route(ipm, 0xE0000000, 0xF0000000, 0x00000000);
	}

	if (gateway != 0) {
		DEBUG_INFO("adding gateway route");
		ip_managed_add_route(ipm, 0x00000000, 0x00000000, gateway);
	}

	ip_interface_manager_redetect_required();
	igmp_manager_local_ip_changed();
}

void ip_managed_set_wifi_ap(struct ip_managed_t *ipm)
{
	struct ifreq ifflags;
	ip_managed_get_ifflags(ipm, &ifflags);
	ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ip_managed_set_ifflags(ipm, &ifflags);

	struct iwreq iwr;
	memset(&iwr, 0, sizeof(struct iwreq));
	strncpy(iwr.ifr_name, ipm->interface_name, IFNAMSIZ);

	iwr.u.mode = IW_MODE_MASTER;
	if (ioctl(ipm->ioctl_sock, SIOCSIWMODE, &iwr)) {
		DEBUG_ERROR("ioctl SIOCSIWMODE failed %d %s", errno, strerror(errno));
	}

	ip_interface_manager_redetect_required();
}

void ip_managed_set_loopback(struct ip_managed_t *ipm)
{
	ip_addr_set_ipv4(&ipm->ip_addr, 0x7F000001UL);
	ip_addr_set_ipv4(&ipm->subnet_mask, 0xFF000000UL);

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ipm->interface_name, IFNAMSIZ);

	struct sockaddr_in *ifraddr = (struct sockaddr_in *)&ifr.ifr_addr;
	ifraddr->sin_family = AF_INET;

	ifraddr->sin_addr.s_addr = htonl(ip_addr_get_ipv4(&ipm->ip_addr));
	if (ioctl(ipm->ioctl_sock, SIOCSIFADDR, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	ifraddr->sin_addr.s_addr = htonl(ip_addr_get_ipv4(&ipm->subnet_mask));
	if (ioctl(ipm->ioctl_sock, SIOCSIFNETMASK, &ifr)) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
	}

	struct ifreq ifflags;
	ip_managed_get_ifflags(ipm, &ifflags);
	ifflags.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ip_managed_set_ifflags(ipm, &ifflags);

	ip_interface_manager_redetect_required();
}

bool ip_managed_read_ethernet_mii_register(struct ip_managed_t *ipm, uint8_t reg_addr, uint16_t *presult)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ipm->interface_name, IFNAMSIZ);

	struct mii_ioctl_data *mii = (struct mii_ioctl_data *)&ifr.ifr_data;
	mii->reg_num = reg_addr;

	if (ioctl(ipm->ioctl_sock, SIOCGMIIPHY, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		*presult = 0;
		return false;
	}

	if (ioctl(ipm->ioctl_sock, SIOCGMIIREG, &ifr) < 0) {
		DEBUG_ERROR("ioctl failed %d %s", errno, strerror(errno));
		*presult = 0;
		return false;
	}

	*presult = mii->val_out;
	return true;
}

struct ip_managed_t *ip_managed_alloc(const char *interface_name, uint8_t metric)
{
	struct ip_managed_t *ipm = (struct ip_managed_t *)heap_alloc_and_zero(sizeof(struct ip_managed_t), PKG_OS, MEM_TYPE_OS_IP_MANAGED);
	if (!ipm) {
		return NULL;
	}

	sprintf_custom(ipm->interface_name, ipm->interface_name + sizeof(ipm->interface_name), "%s", interface_name);
	ipm->ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	ipm->ifindex = if_nametoindex(interface_name);
	ipm->metric = metric;
	ipm->secondary = (strchr(interface_name, ':') != 0);

	return ipm;
}
