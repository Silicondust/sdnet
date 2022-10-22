/*
 * ip_interface_netlink.c
 *
 * Copyright © 2022 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_interface_netlink");

#if defined(IPV6_SUPPORT)
#define AF_MODE AF_UNSPEC
#else
#define AF_MODE AF_INET
#endif

#define IP_INTERFACE_NETLINK_BUFFER_SIZE 32768

struct nlmsghdr_ifaddrmsg {
	struct nlmsghdr nlh;
	struct ifaddrmsg msg;
};

static void ip_interface_manager_detect_execute_newaddr(int af_sock, struct nlmsghdr *hdr)
{
	struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

#if defined(IPV6_SUPPORT)
	if ((addrmsg->ifa_family != AF_INET) && (addrmsg->ifa_family != AF_INET6)) {
		DEBUG_INFO("entry not ipv4/ipv6");
		return;
	}

	if ((addrmsg->ifa_family == AF_INET6) && (addrmsg->ifa_flags & IFA_F_TEMPORARY)) {
		return; /* skip temporary IPv6 addresses */
	}
#else
	if (addrmsg->ifa_family != AF_INET) {
		return;
	}
#endif

	/*
	 * ifindex
	 */
	uint32_t ifindex = addrmsg->ifa_index;
	if (ifindex == 0) {
		return;
	}

	/*
	 * interface flags
	 */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if (!if_indextoname(ifindex, ifr.ifr_name)) {
		DEBUG_ERROR("if_indextoname failed");
		return;
	}

	if (ioctl(af_sock, SIOCGIFFLAGS, &ifr) < 0) {
		DEBUG_ERROR("ioctl SIOCGIFFLAGS failed");
		return;
	}

	uint32_t flags = ifr.ifr_flags;
	flags &= (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING | IFF_MULTICAST);
	if (flags != (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) {
		return;
	}

	/*
	 * addresses
	 */
	size_t ifa_payload_length = IFA_PAYLOAD(hdr);
	struct rtattr *rta = IFA_RTA(addrmsg);
	while (1) {
		if (!RTA_OK(rta, ifa_payload_length)) {
			break;
		}

		if (rta->rta_type != IFA_ADDRESS) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		/*
		 * ip address
		 */
		ip_addr_t ip_addr;
#if defined(IPV6_SUPPORT)
		if (addrmsg->ifa_family == AF_INET6) {
			ip_addr_set_ipv6_bytes(&ip_addr, RTA_DATA(rta));
		}
#endif
		if (addrmsg->ifa_family == AF_INET) {
			ip_addr_set_ipv4(&ip_addr, ntohl(*(uint32_t *)RTA_DATA(rta)));
		}
	
		if (!ip_addr_is_unicast_not_localhost(&ip_addr)) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		/*
		 * subnet mask
		 */
		uint8_t cidr_fail = (addrmsg->ifa_family == AF_INET6) ? 128 : 32;
		if ((addrmsg->ifa_prefixlen == 0) || (addrmsg->ifa_prefixlen >= cidr_fail)) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		ip_addr_t subnet_mask;
		ip_addr_set_subnet_mask_from_cidr(&subnet_mask, &ip_addr, (uint8_t)addrmsg->ifa_prefixlen);
		if (ip_addr_is_zero(&subnet_mask)) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		/*
		 * record
		 */
		DEBUG_TRACE("local ip %V / %V", &ip_addr, &subnet_mask);
		rta = RTA_NEXT(rta, ifa_payload_length);

		uint32_t detect_hash = hash32_create(&ifindex, sizeof(ifindex));
		detect_hash = hash32_append(detect_hash, &ip_addr, sizeof(ip_addr_t));
		detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(ip_addr_t));

		if (ip_interface_manager_detect_reactivate(detect_hash)) {
			continue;
		}

		struct ip_interface_t *idi = (struct ip_interface_t *)heap_alloc_and_zero(sizeof(struct ip_interface_t), PKG_OS, MEM_TYPE_OS_IP_INTERFACE);
		if (!idi) {
			continue;
		}

		idi->detect_hash = detect_hash;
		idi->ifindex = ifindex;
		idi->ip_addr = ip_addr;
		idi->subnet_mask = subnet_mask;
		idi->ip_score = ip_addr_compute_score(&ip_addr);
		ip_interface_manager_detect_add(idi);
	}
}

void ip_interface_manager_detect_execute(void)
{
	uint8_t *nl_buffer = (uint8_t *)heap_alloc(IP_INTERFACE_NETLINK_BUFFER_SIZE, PKG_OS, MEM_TYPE_OS_IP_INTERFACE_DETECT);
	if (!nl_buffer) {
		return;
	}

	int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int af_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if ((nl_sock == -1) || (af_sock == -1)) {
		DEBUG_ERROR("netlink socket failed");
		close(af_sock);
		close(nl_sock);
		heap_free(nl_buffer);
		return;
	}

	struct nlmsghdr_ifaddrmsg req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req)));
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
	req.msg.ifa_family = AF_MODE;

	if (send(nl_sock, &req, req.nlh.nlmsg_len, 0) != (ssize_t)req.nlh.nlmsg_len) {
		DEBUG_ERROR("netlink send failed");
		close(af_sock);
		close(nl_sock);
		heap_free(nl_buffer);
		return;
	}

	bool again = true;
	while (1) {
		struct pollfd poll_fds[1];
		poll_fds[0].fd = nl_sock;
		poll_fds[0].events = POLLIN;
		poll_fds[0].revents = 0;

		int ret = poll(poll_fds, 1, 25);
		if (ret <= 0) {
			break;
		}
		if ((poll_fds[0].revents & POLLIN) == 0) {
			break;
		}

		int length = (int)recv(nl_sock, nl_buffer, IP_INTERFACE_NETLINK_BUFFER_SIZE, 0);
		if (length <= 0) {
			break;
		}

		struct nlmsghdr *hdr = (struct nlmsghdr *)nl_buffer;
		while (1) {
			if (!NLMSG_OK(hdr, length)) {
				break;
			}

			if (hdr->nlmsg_type == NLMSG_DONE) {
				again = false;
				break;
			}

			if (hdr->nlmsg_type == NLMSG_ERROR) {
				again = false;
				break;
			}

			if (hdr->nlmsg_type == RTM_NEWADDR) {
				ip_interface_manager_detect_execute_newaddr(af_sock, hdr);
			}

			hdr = NLMSG_NEXT(hdr, length);
		}

		if (!again) {
			break;
		}
	}

	close(af_sock);
	close(nl_sock);
	heap_free(nl_buffer);
}
