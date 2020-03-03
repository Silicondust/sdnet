/*
 * udp.c
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

struct udp_manager_t {
	struct slist_t socket_active_list;
	struct slist_t socket_new_list;
	struct spinlock socket_new_lock;
	struct pollfd *socket_poll_fds;
	size_t socket_poll_count;
	int socket_poll_trigger_fd;
};

static struct udp_manager_t udp_manager;

static void udp_socket_trigger_poll(void)
{
	uint8_t v = 0;
	if (write(udp_manager.socket_poll_trigger_fd, &v, 1) != 1) {
		DEBUG_WARN("udp trigger failed");
	}
}

uint16_t udp_socket_get_port(struct udp_socket *us)
{
	return us->port;
}

udp_error_t udp_socket_send_netbuf(struct udp_socket *us, ipv4_addr_t dest_addr, uint16_t dest_port, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	if (ttl != us->ttl_set) {
		int sock_opt = (int)(unsigned int)ttl;
		if (setsockopt(us->sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
			DEBUG_WARN("setsockopt IP_TTL error %d", errno);
		}
		if (setsockopt(us->sock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
			DEBUG_WARN("setsockopt IP_MULTICAST_TTL error %d", errno);
		}
		us->ttl_set = ttl;
	}

	if (tos != us->tos_set) {
		int sock_opt = (int)(unsigned int)tos;
		if (setsockopt(us->sock, IPPROTO_IP, IP_TOS, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
			DEBUG_WARN("setsockopt IP_TOS error %d", errno);
		}
		us->tos_set = tos;
	}

	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(dest_addr);
	sock_addr.sin_port = htons(dest_port);

	uint8_t *buffer = netbuf_get_ptr(nb);
	size_t length = netbuf_get_remaining(nb);

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t ret = sendto(us->sock, (char *)buffer, length, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	if (ret != (ssize_t)length) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
			DEBUG_INFO("udp send failed (%d)", errno);
		}
		return UDP_ERROR_FAILED;
	}

	return UDP_OK;
}

static void udp_socket_thread_icmp(struct udp_socket *us)
{
#if defined(MSG_ERRQUEUE)
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	msg.msg_name = (void *)&sock_addr;
	msg.msg_namelen = sizeof(sock_addr);

	int length = recvmsg(us->sock, &msg, MSG_ERRQUEUE);
	if (length < 0) {
		DEBUG_ERROR("recvmsg returned %d errno %d", length, errno);
		return;
	}

	udp_recv_icmp_callback_t recv_icmp_callback = us->recv_icmp_callback;
	if (recv_icmp_callback) {
		ipv4_addr_t src_addr = ntohl(sock_addr.sin_addr.s_addr);
		uint16_t src_port = ntohs(sock_addr.sin_port);

		thread_main_enter();
		recv_icmp_callback(us->callback_inst, src_addr, ICMP_TYPE_ERR_DEST_UNREACHABLE, src_addr, src_port);
		thread_main_exit();
	}
#endif
}

static void udp_socket_thread_recv(struct udp_socket *us)
{
	struct netbuf *nb = netbuf_alloc_with_fwd_space(us->recv_netbuf_size);
	while (!nb) {
		DEBUG_WARN("retry netbuf alloc");
		timer_sleep_fast(FAST_TICK_RATE_MS * 10);
		nb = netbuf_alloc_with_fwd_space(us->recv_netbuf_size);
	}

	uint8_t *buffer = netbuf_get_ptr(nb);
	size_t buffer_length = netbuf_get_remaining(nb);

	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sockaddr_size = sizeof(sock_addr);

	ssize_t length = recvfrom(us->sock, (char *)buffer, buffer_length, 0, (struct sockaddr *)&sock_addr, &sockaddr_size);
	if (length <= 0) {
		DEBUG_ERROR("recvfrom returned %d errno %d", (int)length, errno);
		netbuf_free(nb);
		udp_socket_thread_icmp(us);
		return;
	}

	ipv4_addr_t src_addr = ntohl(sock_addr.sin_addr.s_addr);
	uint16_t src_port = ntohs(sock_addr.sin_port);
	netbuf_set_end(nb, netbuf_get_pos(nb) + (size_t)length);

	thread_main_enter();
	us->recv_callback(us->callback_inst, src_addr, src_port, nb);
	thread_main_exit();

	netbuf_free(nb);
}

udp_error_t udp_socket_listen(struct udp_socket *us, ipv4_addr_t addr, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst)
{
	DEBUG_ASSERT(recv, "no recv callback specified");

	us->recv_callback = recv;
	us->recv_icmp_callback = recv_icmp;
	us->callback_inst = inst;
	us->addr = addr;
	us->port = port;

	/* Listen for ICMP messages. */
#if defined(IP_RECVERR)
	int sock_opt = 1;
	if (setsockopt(us->sock, IPPROTO_IP, IP_RECVERR, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_RECVERR error %d", errno);
	}
#endif

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

	udp_socket_trigger_poll();
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
		DEBUG_ERROR("failed to allocate socket (%d)", errno);
		heap_free(us);
		return NULL;
	}

	/* Set non-blocking. */
	if (fcntl(us->sock, F_SETFL, O_NONBLOCK) != 0) {
		DEBUG_ASSERT(0, "failed set socket to non-blocking");
		close(us->sock);
		heap_free(us);
		return NULL;
	}

	/* Set send buffer size. */
	udp_set_sock_send_buffer_size(us->sock, 128 * 1024);

	/* Allow broadcast. */
	int sock_opt = 1;
	if (setsockopt(us->sock, SOL_SOCKET, SO_BROADCAST, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt SO_BROADCAST error %d", errno);
	}

	/* Allow port reuse - required for SSDP. */
	sock_opt = 1;
	if (setsockopt(us->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt SO_REUSEADDR error %d", errno);
	}

	return us;
}

static void udp_manager_thread_new_sockets(void)
{
	size_t add_count = slist_get_count(&udp_manager.socket_new_list);
	size_t total_count = udp_manager.socket_poll_count + add_count;

	struct pollfd *poll_fds = (struct pollfd *)heap_realloc(udp_manager.socket_poll_fds, sizeof(struct pollfd) * total_count, PKG_OS, MEM_TYPE_OS_UDP_POLL);
	if (!poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	udp_manager.socket_poll_fds = poll_fds;
	poll_fds += udp_manager.socket_poll_count;

	struct udp_socket **pprev = slist_get_phead(struct udp_socket, &udp_manager.socket_active_list);
	struct udp_socket *p = slist_get_head(struct udp_socket, &udp_manager.socket_active_list);
	while (p) {
		pprev = slist_get_pnext(struct udp_socket, p);
		p = slist_get_next(struct udp_socket, p);
	}

	while (1) {
		struct udp_socket *us = slist_detach_head(struct udp_socket, &udp_manager.socket_new_list);
		if (!us) {
			break;
		}

		poll_fds->fd = us->sock;
		poll_fds->events = POLLIN;
		poll_fds->revents = 0;
		poll_fds++;

		slist_insert_pprev(struct udp_socket, pprev, us);
		pprev = slist_get_pnext(struct udp_socket, us);
	}

	udp_manager.socket_poll_count = total_count;
}

static void udp_manager_thread_execute_sock(struct udp_socket *us, struct pollfd *poll_fds)
{
	DEBUG_ASSERT((poll_fds->revents & ~(POLLIN | POLLERR)) == 0, "unexpected event %x", poll_fds->revents);

	if (poll_fds->revents & POLLIN) {
		udp_socket_thread_recv(us);
	}

	if (poll_fds->revents & POLLERR) {
		udp_socket_thread_icmp(us);
	}
}

static void udp_manager_thread_execute(void *arg)
{
	while (1) {
		if (slist_get_head(struct udp_socket, &udp_manager.socket_new_list)) {
			spinlock_lock(&udp_manager.socket_new_lock);
			udp_manager_thread_new_sockets();
			spinlock_unlock(&udp_manager.socket_new_lock);
		}

		int ret = poll(udp_manager.socket_poll_fds, (nfds_t)udp_manager.socket_poll_count, -1);
		if (ret <= 0) {
			DEBUG_ASSERT(ret == 0, "poll returned error");
			continue;
		}

		struct pollfd *poll_fds = udp_manager.socket_poll_fds;
		if (poll_fds->revents) {
			uint8_t dummy[32];
			if (read(poll_fds->fd, dummy, sizeof(dummy)) < 0) {
				/* Nothing needs to be done on error */
			}
		}

		poll_fds++;

		struct udp_socket *us = slist_get_head(struct udp_socket, &udp_manager.socket_active_list);
		while (us) {
			DEBUG_ASSERT(us->sock == poll_fds->fd, "list error");

			if (poll_fds->revents) {
				udp_manager_thread_execute_sock(us, poll_fds);
			}

			us = slist_get_next(struct udp_socket, us);
			poll_fds++;
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

	udp_manager.socket_poll_fds = (struct pollfd *)heap_alloc(sizeof(struct pollfd), PKG_OS, MEM_TYPE_OS_UDP_POLL);
	if (!udp_manager.socket_poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	int socket_poll_trigger_fds[2];
	if (pipe(socket_poll_trigger_fds) < 0) {
		DEBUG_ERROR("pipe create failed");
		return;
	}
	
	fcntl(socket_poll_trigger_fds[0], F_SETFL, O_NONBLOCK);
	fcntl(socket_poll_trigger_fds[1], F_SETFL, O_NONBLOCK);

	struct pollfd *poll_fds = udp_manager.socket_poll_fds;
	poll_fds->fd = socket_poll_trigger_fds[0];
	poll_fds->events = POLLIN;
	poll_fds->revents = 0;

	udp_manager.socket_poll_count = 1;
	udp_manager.socket_poll_trigger_fd = socket_poll_trigger_fds[1];
}
