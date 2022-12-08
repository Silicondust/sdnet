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

static void udp_socket_set_ttl_internal(int sock, ip_mode_t ip_mode, uint8_t ttl)
{
#if defined(IPV6_SUPPORT)
	if (ip_mode == IP_MODE_IPV6) {
		int sock_opt_ttl = (int)(unsigned int)ttl;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&sock_opt_ttl, sizeof(sock_opt_ttl)) < 0) {
			DEBUG_WARN("setsockopt IPV6_UNICAST_HOPS error %d", errno);
		}
		return;
	}
#endif

	int sock_opt_ttl = (int)(unsigned int)ttl;
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt_ttl, sizeof(sock_opt_ttl)) < 0) {
		DEBUG_WARN("setsockopt IP_TTL error %d", errno);
	}
}

static void udp_socket_set_tos_internal(int sock, ip_mode_t ip_mode, uint8_t tos)
{
#if defined(IPV6_SUPPORT)
	if (ip_mode == IP_MODE_IPV6) {
		int sock_opt_tos = (int)(unsigned int)tos;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (char *)&sock_opt_tos, sizeof(sock_opt_tos)) < 0) {
			DEBUG_WARN("setsockopt IPV6_TCLASS error %d", errno);
		}
		return;
	}
#endif

	int sock_opt_tos = (int)(unsigned int)tos;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&sock_opt_tos, sizeof(sock_opt_tos)) < 0) {
		DEBUG_WARN("setsockopt IP_TOS error %d", errno);
	}
}

udp_error_t udp_socket_send_netbuf(struct udp_socket *us, const ip_addr_t *dest_addr, uint16_t dest_port, uint32_t ipv6_scope_id, uint8_t ttl, uint8_t tos, struct netbuf *nb)
{
	DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(dest_addr, ipv6_scope_id);

	if (ttl != us->ttl_set) {
		udp_socket_set_ttl_internal(us->sock, us->ip_mode, ttl);
		us->ttl_set = ttl;
	}

	if (tos != us->tos_set) {
		udp_socket_set_tos_internal(us->sock, us->ip_mode, tos);
		us->tos_set = tos;
	}

#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size;
	if (us->ip_mode == IP_MODE_IPV6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		sock_addr_in->sin6_family = AF_INET6;
		ip_addr_get_ipv6_bytes(dest_addr, sock_addr_in->sin6_addr.s6_addr);
		sock_addr_in->sin6_port = htons(dest_port);
		sock_addr_in->sin6_scope_id = ipv6_scope_id;
		sock_addr_size = sizeof(struct sockaddr_in6);
	} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		sock_addr_in->sin_family = AF_INET;
		sock_addr_in->sin_addr.s_addr = htonl(ip_addr_get_ipv4(dest_addr));
		sock_addr_in->sin_port = htons(dest_port);
		sock_addr_size = sizeof(struct sockaddr_in);
	}
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(ip_addr_get_ipv4(dest_addr));
	sock_addr.sin_port = htons(dest_port);
	socklen_t sock_addr_size = sizeof(struct sockaddr_in);
#endif

	uint8_t *buffer = netbuf_get_ptr(nb);
	size_t length = netbuf_get_remaining(nb);

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t ret = sendto(us->sock, (char *)buffer, length, 0, (struct sockaddr *)&sock_addr, sock_addr_size);
	if (ret != (ssize_t)length) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
			DEBUG_INFO("udp send to %V failed error %d", dest_addr, errno);
		}
		return UDP_ERROR_FAILED;
	}

	return UDP_OK;
}

struct udp_socket_notify_recv_icmp_t {
	struct udp_socket *us;
	ip_addr_t src_addr;
	uint16_t src_port;
	uint32_t ipv6_scope_id;
};

static void udp_socket_notify_recv_icmp(struct udp_socket_notify_recv_icmp_t *arg)
{
	struct udp_socket *us = arg->us;
	us->recv_icmp_callback(us->callback_inst, ICMP_TYPE_ERR_DEST_UNREACHABLE, &arg->src_addr, arg->src_port, arg->ipv6_scope_id);
}

static void udp_socket_thread_icmp(struct udp_socket *us)
{
#if defined(MSG_ERRQUEUE)
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
#endif

	msg.msg_name = (void *)&sock_addr;
	msg.msg_namelen = sizeof(sock_addr);

	int length = recvmsg(us->sock, &msg, MSG_ERRQUEUE);
	if (length < 0) {
		DEBUG_ERROR("recvmsg returned %d errno %d", length, errno);
		return;
	}

	if (us->recv_icmp_callback) {
		struct udp_socket_notify_recv_icmp_t arg;
		arg.us = us;

#if defined(IPV6_SUPPORT)
		if (sock_addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
			ip_addr_set_ipv6_bytes(&arg.src_addr, sock_addr_in->sin6_addr.s6_addr);
			arg.src_port = ntohs(sock_addr_in->sin6_port);
			arg.ipv6_scope_id = sock_addr_in->sin6_scope_id;
		} else {
			struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
			ip_addr_set_ipv4(&arg.src_addr, ntohl(sock_addr_in->sin_addr.s_addr));
			arg.src_port = ntohs(sock_addr_in->sin_port);
			arg.ipv6_scope_id = 0;
		}
#else
		ip_addr_set_ipv4(&arg.src_addr, ntohl(sock_addr.sin_addr.s_addr));
		arg.src_port = ntohs(sock_addr.sin_port);
		arg.ipv6_scope_id = 0;
#endif

		DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(&arg.src_addr, arg.ipv6_scope_id);
		thread_main_execute((thread_execute_func_t)udp_socket_notify_recv_icmp, &arg);
	}
#endif
}

struct udp_socket_notify_recv_t {
	struct udp_socket *us;
	ip_addr_t src_addr;
	uint16_t src_port;
	uint32_t ipv6_scope_id;
	struct netbuf *nb;
};

static void udp_socket_notify_recv(struct udp_socket_notify_recv_t *arg)
{
	struct udp_socket *us = arg->us;
	us->recv_callback(us->callback_inst, &arg->src_addr, arg->src_port, arg->ipv6_scope_id, arg->nb);
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

#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#endif

	ssize_t length = recvfrom(us->sock, (char *)buffer, buffer_length, 0, (struct sockaddr *)&sock_addr, &sock_addr_size);
	if (length <= 0) {
		DEBUG_ERROR("recvfrom returned %d errno %d", (int)length, errno);
		netbuf_free(nb);
		udp_socket_thread_icmp(us);
		return;
	}

	struct udp_socket_notify_recv_t arg;
	arg.us = us;
	arg.nb = nb;

#if defined(IPV6_SUPPORT)
	if (sock_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		ip_addr_set_ipv6_bytes(&arg.src_addr, sock_addr_in->sin6_addr.s6_addr);
		arg.src_port = ntohs(sock_addr_in->sin6_port);
		arg.ipv6_scope_id = sock_addr_in->sin6_scope_id;
	} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		ip_addr_set_ipv4(&arg.src_addr, ntohl(sock_addr_in->sin_addr.s_addr));
		arg.src_port = ntohs(sock_addr_in->sin_port);
		arg.ipv6_scope_id = 0;
}
#else
	ip_addr_set_ipv4(&arg.src_addr, ntohl(sock_addr.sin_addr.s_addr));
	arg.src_port = ntohs(sock_addr.sin_port);
	arg.ipv6_scope_id = 0;
#endif

	DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(&arg.src_addr, arg.ipv6_scope_id);

	if (!ip_addr_is_zero(&arg.src_addr) && !ip_addr_is_unicast(&arg.src_addr)) {
		netbuf_free(nb);
		return;
	}

	netbuf_set_end(nb, netbuf_get_pos(nb) + (size_t)length);
	thread_main_execute((thread_execute_func_t)udp_socket_notify_recv, &arg);
	netbuf_free(nb);
}

udp_error_t udp_socket_listen_idi(struct udp_socket *us, struct ip_interface_t *idi, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst)
{
	DEBUG_ASSERT(recv, "no recv callback specified");

	us->recv_callback = recv;
	us->recv_icmp_callback = recv_icmp;
	us->callback_inst = inst;
	us->port = port;

	/* Listen for ICMP messages. */
#if defined(IP_RECVERR)
	int sock_opt_ip_recverr = 1;
	if (setsockopt(us->sock, IPPROTO_IP, IP_RECVERR, (char *)&sock_opt_ip_recverr, sizeof(sock_opt_ip_recverr)) < 0) {
		DEBUG_WARN("setsockopt IP_RECVERR error %d", errno);
	}
#endif

	/* Bind. */
	ip_addr_t local_ip;
	uint32_t ifindex;
	uint32_t ipv6_scope_id __unused;
	if (idi) {
		ip_interface_get_local_ip(idi, &local_ip);
		ifindex = ip_interface_get_ifindex(idi);
		ipv6_scope_id = ip_interface_get_ipv6_scope_id(idi);
	} else {
		ip_addr_set_zero(&local_ip);
		ifindex = 0;
		ipv6_scope_id = 0;
	}

#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size;
	if (us->ip_mode == IP_MODE_IPV6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		sock_addr_in->sin6_family = AF_INET6;
		ip_addr_get_ipv6_bytes(&local_ip, sock_addr_in->sin6_addr.s6_addr);
		sock_addr_in->sin6_port = htons(port);
		sock_addr_in->sin6_scope_id = ipv6_scope_id;
		sock_addr_size = sizeof(struct sockaddr_in6);
	} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		sock_addr_in->sin_family = AF_INET;
		sock_addr_in->sin_addr.s_addr = htonl(ip_addr_get_ipv4(&local_ip));
		sock_addr_in->sin_port = htons(port);
		sock_addr_size = sizeof(struct sockaddr_in);
	}
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(ip_addr_get_ipv4(&local_ip));
	sock_addr.sin_port = htons(port);
	socklen_t sock_addr_size = sizeof(struct sockaddr_in);
#endif

	if (bind(us->sock, (struct sockaddr *)&sock_addr, sock_addr_size) != 0) {
		DEBUG_WARN("failed to bind socket to %V:%u error %d", &local_ip, port, errno);
		return UDP_ERROR_SOCKET_BUSY;
	}

	if (idi) {
#if defined(IPV6_SUPPORT)
		if (us->ip_mode == IP_MODE_IPV6) {
			setsockopt(us->sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&ifindex, sizeof(ifindex));
		} else {
			setsockopt(us->sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ifindex, sizeof(ifindex));
		}
#else
		setsockopt(us->sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ifindex, sizeof(ifindex));
#endif
	}

	if (port == 0) {
		memset(&sock_addr, 0, sizeof(sock_addr));
		socklen_t addr_len = sizeof(sock_addr);
		getsockname(us->sock, (struct sockaddr *)&sock_addr, &addr_len);

#if defined(IPV6_SUPPORT)
		if (sock_addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
			us->port = ntohs(sock_addr_in->sin6_port);
		} else {
			struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
			us->port = ntohs(sock_addr_in->sin_port);
		}
#else
		us->port = ntohs(sock_addr.sin_port);
#endif
	}

	spinlock_lock(&udp_manager.socket_new_lock);
	slist_attach_head(struct udp_socket, &udp_manager.socket_new_list, us);
	spinlock_unlock(&udp_manager.socket_new_lock);

	udp_socket_trigger_poll();
	return UDP_OK;
}

udp_error_t udp_socket_listen(struct udp_socket *us, uint16_t port, udp_recv_callback_t recv, udp_recv_icmp_callback_t recv_icmp, void *inst)
{
	return udp_socket_listen_idi(us, NULL, port, recv, recv_icmp, inst);
}

void udp_socket_set_icmp_callback(struct udp_socket *us, udp_recv_icmp_callback_t recv_icmp)
{
	us->recv_icmp_callback = recv_icmp;
}

void udp_socket_set_recv_netbuf_size(struct udp_socket *us, size_t recv_netbuf_size)
{
	us->recv_netbuf_size = recv_netbuf_size;
}

struct udp_socket *udp_socket_alloc(ip_mode_t ip_mode)
{
	struct udp_socket *us = (struct udp_socket *)heap_alloc_and_zero(sizeof(struct udp_socket), PKG_OS, MEM_TYPE_OS_UDP_SOCKET);
	if (!us) {
		return NULL;
	}

	us->ip_mode = ip_mode;
	us->recv_netbuf_size = UDP_DEFAULT_RECV_NETBUF_SIZE;

	/* Create socket. */
	int af_inet = (ip_mode == IP_MODE_IPV6) ? AF_INET6 : AF_INET;
	us->sock = (int)socket(af_inet, SOCK_DGRAM, 0);
	if (us->sock == -1) {
		DEBUG_ERROR("failed to allocate socket error %d", errno);
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
	int sock_opt_broadcast = 1;
	if (setsockopt(us->sock, SOL_SOCKET, SO_BROADCAST, (char *)&sock_opt_broadcast, sizeof(sock_opt_broadcast)) < 0) {
		DEBUG_WARN("setsockopt SO_BROADCAST error %d", errno);
	}

	/* Allow port reuse - required for SSDP. */
	int sock_opt_reuseaddr = 1;
	if (setsockopt(us->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt_reuseaddr, sizeof(sock_opt_reuseaddr)) < 0) {
		DEBUG_WARN("setsockopt SO_REUSEADDR error %d", errno);
	}

#if defined(SO_REUSEPORT)
	int sock_opt_reuseport = 1;
	if (setsockopt(us->sock, SOL_SOCKET, SO_REUSEPORT, (char *)&sock_opt_reuseport, sizeof(sock_opt_reuseport)) < 0) {
		DEBUG_WARN("setsockopt SO_REUSEPORT error %d", errno);
	}
#endif

	/* Set IPV6 only */
#if defined(IPV6_SUPPORT)
	if (ip_mode == IP_MODE_IPV6) {
		int sock_opt_ipv6only = 1;
		setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&sock_opt_ipv6only, sizeof(sock_opt_ipv6only));
	}
#endif

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
