/*
 * net/android/ip_passive.c
 *
 * Copyright © 2012-2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 */

#include <os.h>
#include <net/ip_passive_common.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("ip_passive");

void ip_datalink_manager_detect_execute(void)
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		return;
	}

	int ifreq_buffer_size = 128 * sizeof(struct ifreq);
	char *ifreq_buffer = (char *)calloc(ifreq_buffer_size, 1);
	if (!ifreq_buffer) {
		close(sock);
		return;
	}

	struct ifconf ifc;
	ifc.ifc_len = ifreq_buffer_size;
	ifc.ifc_buf = ifreq_buffer;

	if (ioctl(sock, SIOCGIFCONF, &ifc) != 0) {
		free(ifreq_buffer);
		close(sock);
		return;
	}

	if (ifc.ifc_len > ifreq_buffer_size) {
		ifc.ifc_len = ifreq_buffer_size;
	}

	char *ptr = ifc.ifc_buf;
	char *end = ifc.ifc_buf + ifc.ifc_len;

	while (ptr + sizeof(struct ifreq) <= end) {
		struct ifreq *ifr = (struct ifreq *)ptr;
		ptr += sizeof(struct ifreq);

		/* Local IP address. */
		struct sockaddr_in *ip_addr_in = (struct sockaddr_in *)&ifr->ifr_addr;
		uint32_t ip_addr = ntohl(ip_addr_in->sin_addr.s_addr);
		if (ip_addr == 0) {
			continue;
		}

		/* Flags. */
		if (ioctl(sock, SIOCGIFFLAGS, ifr) != 0) {
			continue;
		}

		unsigned int flags = ifr->ifr_flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING);
		if (flags != (IFF_UP | IFF_RUNNING)) {
			continue;
		}

		/* Subnet mask. */
		if (ioctl(sock, SIOCGIFNETMASK, ifr) != 0) {
			continue;
		}

		struct sockaddr_in *subnet_mask_in = (struct sockaddr_in *)&ifr->ifr_addr;
		uint32_t subnet_mask = ntohl(subnet_mask_in->sin_addr.s_addr);

		/* Detect hash. */
		uint32_t detect_hash = hash32_create(&ip_addr, sizeof(ip_addr));
		detect_hash = hash32_append(detect_hash, &subnet_mask, sizeof(subnet_mask));

		if (ip_datalink_manager_detect_reactivate(detect_hash)) {
			continue;
		}

		/* Create idi. */
		struct ip_datalink_instance *idi = (struct ip_datalink_instance *)heap_alloc_and_zero(sizeof(struct ip_datalink_instance), PKG_OS, MEM_TYPE_OS_IP_DATALINK);
		if (!idi) {
			continue;
		}

		idi->detect_hash = detect_hash;
		idi->ip_addr = ip_addr;
		idi->subnet_mask = subnet_mask;
		ip_datalink_manager_detect_add(idi);
	}

	free(ifreq_buffer);
	close(sock);
}
