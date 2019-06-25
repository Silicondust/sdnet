/*
 * udp.c
 *
 * Copyright © 2007-2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("udp");

/*
 * Threading:
 *	udp_socket_send_netbuf may be called from any thread, but always the same thread for any one socket.
 *  callbacks sent from main thread.
 */

#define UDP_DEFAULT_RECV_NETBUF_SIZE 1460

struct udp_multipath_t {
	struct slist_prefix_t slist_prefix;
	struct udp_socket *us;
	ipv4_addr_t addr;
};

struct udp_socket {
	struct slist_prefix_t slist_prefix;
	struct slist_t multipath_list;
	ipv4_addr_t addr;
	uint16_t port;
	int sock;
	HANDLE event_handle;
	size_t recv_netbuf_size;
	udp_recv_callback_t recv_callback;
	volatile udp_recv_icmp_callback_t recv_icmp_callback;
	void *callback_inst;
};

struct udp_manager_t {
	struct slist_t socket_active_list;
	struct slist_t socket_new_list;
	struct spinlock socket_new_lock;
	HANDLE *socket_poll_handles;
	size_t socket_poll_count;
	HANDLE socket_poll_signal;
	struct netbuf *socket_rxnb;
};

static struct udp_manager_t udp_manager;

uint16_t udp_socket_get_port(struct udp_socket *us)
{
	return us->port;
}

udp_error_t udp_socket_send_netbuf(struct udp_socket *us, ipv4_addr_t dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(dest_addr);
	sock_addr.sin_port = htons(dest_port);

	uint8_t *buffer = netbuf_get_ptr(nb);
	int length = (int)netbuf_get_remaining(nb);
	int ret = sendto(us->sock, (char *)buffer, length, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	if (ret != length) {
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK) {
			DEBUG_INFO("udp send failed (%d)", err);
		}
		return UDP_ERROR_FAILED;
	}

	return UDP_OK;
}

static struct udp_multipath_t *udp_socket_multipath_find_create(struct udp_socket *us, struct ip_datalink_instance *idi, ipv4_addr_t addr)
{
	struct udp_multipath_t *ump = slist_get_head(struct udp_multipath_t, &us->multipath_list);
	while (ump) {
		if (ump->addr == addr) {
			return ump;
		}

		ump = slist_get_next(struct udp_multipath_t, ump);
	}

	ump = heap_alloc_and_zero(sizeof(struct udp_multipath_t), PKG_OS, MEM_TYPE_OS_UDP_MULTIPATH);
	if (!ump) {
		return NULL;
	}

	ump->us = udp_socket_alloc();
	if (!ump->us) {
		heap_free(ump);
		return NULL;
	}

	udp_socket_listen(ump->us, idi, addr, us->port, us->recv_callback, us->recv_icmp_callback, us->callback_inst);
	slist_attach_head(struct udp_multipath_t, &us->multipath_list, ump);
	return ump;
}

udp_error_t udp_socket_send_multipath(struct udp_socket *us, ipv4_addr_t dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	bool global_broadcast = (dest_addr == 0xFFFFFFFF);
	bool filter = !global_broadcast && !ip_addr_is_multicast(dest_addr);

	udp_error_t result = UDP_ERROR_FAILED;

	struct ip_datalink_instance *idi = ip_datalink_manager_get_head();
	while (idi) {
		ipv4_addr_t addr = ip_datalink_get_ipaddr(idi);
		if (addr == 0) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if (filter) {
			ipv4_addr_t subnet_mask = ip_datalink_get_subnet_mask(idi);
			if (subnet_mask == 0) {
				idi = slist_get_next(struct ip_datalink_instance, idi);
				continue;
			}
			if ((dest_addr & subnet_mask) != (addr & subnet_mask)) {
				idi = slist_get_next(struct ip_datalink_instance, idi);
				continue;
			}
		}

		struct udp_multipath_t *ump = udp_socket_multipath_find_create(us, idi, addr);
		if (!ump) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		if (udp_socket_send_netbuf(ump->us, dest_addr, dest_port, ttl, tos, nb) != UDP_OK) {
			idi = slist_get_next(struct ip_datalink_instance, idi);
			continue;
		}

		result = UDP_OK;
		idi = slist_get_next(struct ip_datalink_instance, idi);
	}

	if (result != UDP_OK) {
		result = udp_socket_send_netbuf(us, dest_addr, dest_port, ttl, tos, nb);
	}

	return result;
}

static void udp_socket_thread_recv(struct udp_socket *us)
{
	if (!udp_manager.socket_rxnb) {
		udp_manager.socket_rxnb = netbuf_alloc_with_fwd_space(us->recv_netbuf_size);
		if (!udp_manager.socket_rxnb) {
			return;
		}
	}

	uint8_t *buffer = netbuf_get_ptr(udp_manager.socket_rxnb);
	size_t buffer_length = netbuf_get_remaining(udp_manager.socket_rxnb);

	struct sockaddr_in sock_addr;
	socklen_t sockaddr_size = sizeof(sock_addr);

	int rx_length = recvfrom(us->sock, (char *)buffer, (int)buffer_length, 0, (struct sockaddr *)&sock_addr, &sockaddr_size);
	if (rx_length <= 0) {
		return;
	}

	struct netbuf *nb = udp_manager.socket_rxnb;
	udp_manager.socket_rxnb = NULL;

	ipv4_addr_t src_addr = ntohl(sock_addr.sin_addr.s_addr);
	uint16_t src_port = ntohs(sock_addr.sin_port);
	netbuf_set_end(nb, netbuf_get_pos(nb) + rx_length);

	thread_main_enter();
	us->recv_callback(us->callback_inst, src_addr, src_port, nb);
	thread_main_exit();

	netbuf_free(nb);
}

udp_error_t udp_socket_listen(struct udp_socket *us, struct ip_datalink_instance *link, ipv4_addr_t addr, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst)
{
	DEBUG_ASSERT(recv, "no recv callback specified");

	us->recv_callback = recv;
	us->recv_icmp_callback = recv_icmp;
	us->callback_inst = inst;
	us->addr = addr;
	us->port = port;

	/* Bind. */
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(addr);
	sock_addr.sin_port = htons(port);
	if (bind(us->sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
		DEBUG_WARN("failed to bind socket to %08X:%u", addr, port);
		return UDP_ERROR_SOCKET_BUSY;
	}

	if (port == 0) {
		memset(&sock_addr, 0, sizeof(sock_addr));
		socklen_t addr_len = sizeof(sock_addr);
		getsockname(us->sock, (struct sockaddr *)&sock_addr, &addr_len);
		us->port = ntohs(sock_addr.sin_port);
	}

	spinlock_lock(&udp_manager.socket_new_lock);
	slist_attach_head(struct udp_socket, &udp_manager.socket_new_list, us);
	spinlock_unlock(&udp_manager.socket_new_lock);
	SetEvent(udp_manager.socket_poll_signal);

	return UDP_OK;
}

void udp_socket_set_icmp_callback(struct udp_socket *us, udp_recv_icmp_callback_t recv_icmp)
{
	us->recv_icmp_callback = recv_icmp;
}

void udp_socket_set_recv_netbuf_size(struct udp_socket *us, size_t recv_netbuf_size)
{
	us->recv_netbuf_size = recv_netbuf_size;
}

struct udp_socket *udp_socket_alloc(void)
{
	struct udp_socket *us = (struct udp_socket *)heap_alloc_and_zero(sizeof(struct udp_socket), PKG_OS, MEM_TYPE_OS_UDP_SOCKET);
	if (!us) {
		return NULL;
	}

	us->recv_netbuf_size = UDP_DEFAULT_RECV_NETBUF_SIZE;

	/* Create socket. */
	us->sock = (int)socket(AF_INET, SOCK_DGRAM, 0);
	if (us->sock == -1) {
		DEBUG_ERROR("failed to allocate socket");
		heap_free(us);
		return NULL;
	}

	/* Set non-blocking. */
	unsigned long mode = 1;
	if (ioctlsocket(us->sock, FIONBIO, &mode) != 0) {
		DEBUG_ERROR("failed set socket to non-blocking");
		closesocket(us->sock);
		heap_free(us);
		return NULL;
	}

	/* Set send buffer size. */
	int send_buffer_size_set = 128 * 1024;
	int send_buffer_size_tmp = send_buffer_size_set;
	setsockopt(us->sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size_tmp, (int)sizeof(send_buffer_size_tmp));

	if (RUNTIME_DEBUG) {
		int send_buffer_size = 0;
		int send_buffer_size_sizeof = sizeof(send_buffer_size);
		getsockopt(us->sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size, &send_buffer_size_sizeof);
		if (send_buffer_size != send_buffer_size_set) {
			DEBUG_ERROR("failed to set send buffer size to %d", send_buffer_size_set);
		}
	}

	/* Allow broadcast. */
	int sock_opt = 1;
	setsockopt(us->sock, SOL_SOCKET, SO_BROADCAST, (char *)&sock_opt, sizeof(sock_opt));

	/* Allow port reuse - required for SSDP. */
	sock_opt = 1;
	setsockopt(us->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt, sizeof(sock_opt));

	return us;
}

static inline void udp_manager_thread_new_sockets(void)
{
	size_t add_count = slist_get_count(&udp_manager.socket_new_list);
	size_t total_count = udp_manager.socket_poll_count + add_count;

	HANDLE *poll_handles = (HANDLE *)heap_realloc(udp_manager.socket_poll_handles, sizeof(HANDLE) * total_count, PKG_OS, MEM_TYPE_OS_UDP_POLL);
	if (!poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	udp_manager.socket_poll_handles = poll_handles;
	poll_handles += udp_manager.socket_poll_count;

	struct udp_socket **pprev = slist_get_phead(struct udp_socket, &udp_manager.socket_active_list);
	struct udp_socket *p = slist_get_head(struct udp_socket, &udp_manager.socket_active_list);
	while (p) {
		pprev = slist_get_pnext(struct udp_socket, p);
		p = slist_get_next(struct udp_socket, p);
	}

	while (1) {
		struct udp_socket *us = slist_get_head(struct udp_socket, &udp_manager.socket_new_list);
		if (!us) {
			break;
		}

		HANDLE event_handle = CreateEvent(NULL, false, false, NULL);
		if (!event_handle) {
			break;
		}

		if (WSAEventSelect(us->sock, event_handle, FD_READ) == SOCKET_ERROR) {
			CloseHandle(event_handle);
			break;
		}

		us->event_handle = event_handle;
		*poll_handles++ = event_handle;
		udp_manager.socket_poll_count++;

		slist_detach_head(struct udp_socket, &udp_manager.socket_new_list);
		slist_insert_pprev(struct udp_socket, pprev, us);

		pprev = slist_get_pnext(struct udp_socket, us);
	}
}

static void udp_manager_thread_execute(void *arg)
{
	while (1) {
		struct udp_socket *us = slist_get_head(struct udp_socket, &udp_manager.socket_active_list);
		HANDLE *poll_handles = udp_manager.socket_poll_handles + 1;
		while (us) {
			DEBUG_ASSERT(us->event_handle == *poll_handles, "list error");
			udp_socket_thread_recv(us);
			us = slist_get_next(struct udp_socket, us);
			poll_handles++;
		}

		if (slist_get_head(struct udp_socket, &udp_manager.socket_new_list)) {
			spinlock_lock(&udp_manager.socket_new_lock);
			udp_manager_thread_new_sockets();
			spinlock_unlock(&udp_manager.socket_new_lock);
		}

		DWORD socket_poll_count = (DWORD)udp_manager.socket_poll_count;
		if (socket_poll_count > WSA_MAXIMUM_WAIT_EVENTS) {
			socket_poll_count = WSA_MAXIMUM_WAIT_EVENTS;
		}

		DWORD ret = WSAWaitForMultipleEvents(socket_poll_count, udp_manager.socket_poll_handles, false, WSA_INFINITE, false);
		if (ret == WAIT_FAILED) {
			DEBUG_ERROR("poll error %u", WSAGetLastError());
			timer_sleep_fast(FAST_TICK_RATE_MS * 100);
		}
	}
}

void udp_manager_start(void)
{
	thread_start(udp_manager_thread_execute, NULL);
}

void udp_manager_init(void)
{
	spinlock_init(&udp_manager.socket_new_lock, 0);

	udp_manager.socket_poll_signal = CreateEvent(NULL, false, false, NULL);
	udp_manager.socket_poll_handles = (HANDLE *)heap_alloc(sizeof(HANDLE), PKG_OS, MEM_TYPE_OS_UDP_POLL);
	if (!udp_manager.socket_poll_signal || !udp_manager.socket_poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	*udp_manager.socket_poll_handles = udp_manager.socket_poll_signal;
	udp_manager.socket_poll_count = 1;
}
