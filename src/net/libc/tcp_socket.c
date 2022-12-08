/*
 * tcp_socket.c
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

THIS_FILE("tcp_socket");

struct tcp_socket {
	struct slist_prefix_t slist_prefix;
	ip_mode_t ip_mode;
	int sock;
	int accept_connection_sock;
	tcp_accept_callback_t accept_callback;
	void *callback_inst;
};

static void tcp_socket_trigger_poll(void)
{
	uint8_t v = 0;
	if (write(tcp_manager.socket_poll_trigger_fd, &v, 1) != 1) {
		DEBUG_WARN("tcp manager trigger failed");
	}
}

static uint32_t tcp_socket_get_remote_addr_internal(int connection_sock, ip_addr_t *result)
{
#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#endif

	if (getpeername(connection_sock, (struct sockaddr *)&sock_addr, &sock_addr_size) != 0) {
		ip_addr_set_zero(result);
		return 0;
	}

#if defined(IPV6_SUPPORT)
	uint32_t ipv6_scope_id = 0;
	if (sock_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		ip_addr_set_ipv6_bytes(result, sock_addr_in->sin6_addr.s6_addr);
		ipv6_scope_id = sock_addr_in->sin6_scope_id;
	} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		ip_addr_set_ipv4(result, ntohl(sock_addr_in->sin_addr.s_addr));
		ipv6_scope_id = 0;
	}
#else
	ip_addr_set_ipv4(result, ntohl(sock_addr.sin_addr.s_addr));
	uint32_t ipv6_scope_id = 0;
#endif

	DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(result, ipv6_scope_id);
	return ipv6_scope_id;
}

uint16_t tcp_socket_get_port(struct tcp_socket *ts)
{
#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size = sizeof(sock_addr);
#endif

	if (getsockname(ts->sock, (struct sockaddr *)&sock_addr, &sock_addr_size) != 0) {
		return 0;
	}

#if defined(IPV6_SUPPORT)
	if (sock_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		return ntohs(sock_addr_in->sin6_port);
} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		return ntohs(sock_addr_in->sin_port);
	}
#else
	return ntohs(sock_addr.sin_port);
#endif
}

void tcp_socket_accept(struct tcp_socket *ts, struct tcp_connection *tc, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp accept called without connection pending");

	tcp_connection_accept(tc, ts->accept_connection_sock, ts->ip_mode, est, recv, close, inst);
	ts->accept_connection_sock = -1;
}

void tcp_socket_reject(struct tcp_socket *ts)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp reject called without connection pending");

	close(ts->accept_connection_sock);
	ts->accept_connection_sock = -1;
}

struct tcp_socket_notify_accept_t {
	struct tcp_socket *ts;
	ip_addr_t remote_addr;
	uint32_t ipv6_scope_id;
};

static void tcp_socket_notify_accept(struct tcp_socket_notify_accept_t *arg)
{
	struct tcp_socket *ts = arg->ts;
	ts->accept_callback(ts->callback_inst, &arg->remote_addr, arg->ipv6_scope_id);
}

static void tcp_socket_thread_accept(struct tcp_socket *ts)
{
	/* Accept connecton. */
	int connection_sock = (int)accept(ts->sock, 0, 0);
	if (connection_sock == -1) {
		return;
	}

	/* Set non-blocking. */
	if (fcntl(connection_sock, F_SETFL, O_NONBLOCK) != 0) {
		DEBUG_ASSERT(0, "failed to set connection non-blocking");
		close(connection_sock);
		return;
	}

	/* Santiy check */
	struct tcp_socket_notify_accept_t arg;
	arg.ts = ts;
	arg.ipv6_scope_id = tcp_socket_get_remote_addr_internal(connection_sock, &arg.remote_addr);
	DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(&arg.remote_addr, arg.ipv6_scope_id);

	if (!ip_addr_is_unicast(&arg.remote_addr)) {
		close(connection_sock);
		return;
	}

	/* Set no-delay. */
	int flag = 1;
	if (setsockopt(connection_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag)) < 0) {
		DEBUG_WARN("setsockopt TCP_NODELAY error %d", errno);
	}

	/* Configure socket not to generate pipe-error signal (BSD/OSX). */
	tcp_set_sock_nosigpipe(connection_sock);

	/* Notify connect. */
	ts->accept_connection_sock = connection_sock;
	thread_main_execute((thread_execute_func_t)tcp_socket_notify_accept, &arg);
	DEBUG_ASSERT(ts->accept_connection_sock == -1, "tcp accept/reject not called");
}

tcp_error_t tcp_socket_listen(struct tcp_socket *ts, uint16_t port, tcp_accept_callback_t accept_callback, void *inst)
{
	DEBUG_ASSERT(accept_callback, "no accept callback specified");

	ts->accept_callback = accept_callback;
	ts->callback_inst = inst;

	/* Bind socket. */
#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size;
	if (ts->ip_mode == IP_MODE_IPV6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		sock_addr_in->sin6_family = AF_INET6;
		sock_addr_in->sin6_port = htons(port);
		sock_addr_size = sizeof(struct sockaddr_in6);
	} else {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		sock_addr_in->sin_family = AF_INET;
		sock_addr_in->sin_port = htons(port);
		sock_addr_size = sizeof(struct sockaddr_in);
	}
#else
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	socklen_t sock_addr_size = sizeof(struct sockaddr_in);
#endif

	if (bind(ts->sock, (struct sockaddr *)&sock_addr, sock_addr_size) != 0) {
		DEBUG_WARN("failed to bind socket to %u", port);
		return TCP_ERROR_SOCKET_BUSY;
	}

	/* Listen. */
	if (listen(ts->sock, 10) != 0) {
		DEBUG_WARN("listen failed on %u", port);
		return TCP_ERROR_SOCKET_BUSY;
	}

	spinlock_lock(&tcp_manager.socket_new_lock);
	slist_attach_head(struct tcp_socket, &tcp_manager.socket_new_list, ts);
	spinlock_unlock(&tcp_manager.socket_new_lock);

	tcp_socket_trigger_poll();
	return TCP_OK;
}

struct tcp_socket *tcp_socket_alloc(ip_mode_t ip_mode)
{
	struct tcp_socket *ts = (struct tcp_socket *)heap_alloc_and_zero(sizeof(struct tcp_socket), PKG_OS, MEM_TYPE_OS_TCP_SOCKET);
	if (!ts) {
		return NULL;
	}

	ts->ip_mode = ip_mode;

	/* Create socket. */
	int af_inet = (ip_mode == IP_MODE_IPV6) ? AF_INET6 : AF_INET;
	ts->sock = (int)socket(af_inet, SOCK_STREAM, 0);
	if (ts->sock == -1) {
		DEBUG_ERROR("failed to allocate socket");
		heap_free(ts);
		return NULL;
	}

	/* Set non-blocking. */
	if (fcntl(ts->sock, F_SETFL, O_NONBLOCK) != 0) {
		DEBUG_ERROR("failed set socket to non-blocking");
		close(ts->sock);
		heap_free(ts);
		return NULL;
	}

	/* Allow port reuse. */
	int sock_opt_reuseaddr = 1;
	if (setsockopt(ts->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt_reuseaddr, sizeof(sock_opt_reuseaddr)) < 0) {
		DEBUG_WARN("setsockopt SO_REUSEADDR error %d", errno);
	}

	/* Set IPV6 only */
#if defined(IPV6_SUPPORT)
	if (ip_mode == IP_MODE_IPV6) {
		int sock_opt_ipv6only = 1;
		setsockopt(ts->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&sock_opt_ipv6only, sizeof(sock_opt_ipv6only));
	}
#endif

	return ts;
}

static inline void tcp_socket_thread_new_sockets(void)
{
	size_t add_count = slist_get_count(&tcp_manager.socket_new_list);
	size_t total_count = tcp_manager.socket_poll_count + add_count;

	struct pollfd *poll_fds = (struct pollfd *)heap_realloc(tcp_manager.socket_poll_fds, sizeof(struct pollfd) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.socket_poll_fds = poll_fds;
	poll_fds += tcp_manager.socket_poll_count;

	struct tcp_socket **pprev = slist_get_phead(struct tcp_socket, &tcp_manager.socket_active_list);
	struct tcp_socket *p = slist_get_head(struct tcp_socket, &tcp_manager.socket_active_list);
	while (p) {
		pprev = slist_get_pnext(struct tcp_socket, p);
		p = slist_get_next(struct tcp_socket, p);
	}

	while (1) {
		struct tcp_socket *ts = slist_detach_head(struct tcp_socket, &tcp_manager.socket_new_list);
		if (!ts) {
			break;
		}

		poll_fds->fd = ts->sock;
		poll_fds->events = POLLIN;
		poll_fds->revents = 0;
		poll_fds++;

		slist_insert_pprev(struct tcp_socket, pprev, ts);
		pprev = slist_get_pnext(struct tcp_socket, ts);
	}

	tcp_manager.socket_poll_count = total_count;
}

static void tcp_socket_thread_execute_sock(struct tcp_socket *ts, struct pollfd *poll_fds)
{
	DEBUG_ASSERT((poll_fds->revents & ~POLLIN) == 0, "unexpected event %x", poll_fds->revents);

	if (poll_fds->revents & POLLIN) {
		tcp_socket_thread_accept(ts);
	}
}

void tcp_socket_thread_execute(void *arg)
{
	while (1) {
		if (slist_get_head(struct tcp_socket, &tcp_manager.socket_new_list)) {
			spinlock_lock(&tcp_manager.socket_new_lock);
			tcp_socket_thread_new_sockets();
			spinlock_unlock(&tcp_manager.socket_new_lock);
		}

		int ret = poll(tcp_manager.socket_poll_fds, (nfds_t)tcp_manager.socket_poll_count, 100);
		if (ret < 0) {
			DEBUG_ASSERT(ret == 0, "poll returned error");
			continue;
		}

		struct pollfd *poll_fds = tcp_manager.socket_poll_fds;
		if (poll_fds->revents) {
			uint8_t dummy[32];
			if (read(poll_fds->fd, dummy, sizeof(dummy)) < 0) {
				/* Nothing needs to be done on error */
			}
		}

		poll_fds++;

		struct tcp_socket *ts = slist_get_head(struct tcp_socket, &tcp_manager.socket_active_list);
		while (ts) {
			DEBUG_ASSERT(ts->sock == poll_fds->fd, "list error");

			if (poll_fds->revents) {
				tcp_socket_thread_execute_sock(ts, poll_fds);
			}

			ts = slist_get_next(struct tcp_socket, ts);
			poll_fds++;
		}
	}
}
