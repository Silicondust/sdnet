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
	struct tcp_socket *next;
	int sock;
	int accept_connection_sock;
	tcp_connect_callback_t connect_callback;
	void *callback_inst;
};

static void tcp_socket_trigger_poll(void)
{
	uint8_t v = 0;
	if (write(tcp_manager.socket_poll_trigger_fd, &v, 1) != 1) {
		DEBUG_WARN("tcp manager trigger failed");
	}
}

uint16_t tcp_socket_get_port(struct tcp_socket *ts)
{
	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	socklen_t addr_len = sizeof(local_addr);
	getsockname(ts->sock, (struct sockaddr *)&local_addr, &addr_len);
	return ntohs(local_addr.sin_port);
}

void tcp_socket_accept(struct tcp_socket *ts, struct tcp_connection *tc, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp accept called without connection pending");

	tcp_connection_accept(tc, ts->accept_connection_sock, est, recv, send_resume, close, inst);
	ts->accept_connection_sock = -1;
}

void tcp_socket_reject(struct tcp_socket *ts)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp reject called without connection pending");

	close(ts->accept_connection_sock);
	ts->accept_connection_sock = -1;
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

	/* Set no-delay. */
	int flag = 1;
	if (setsockopt(connection_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag)) < 0) {
		DEBUG_WARN("setsockopt TCP_NODELAY error %d", errno);
	}

	/* Configure socket not to generate pipe-error signal (BSD/OSX). */
	tcp_set_sock_nosigpipe(connection_sock);

	/* Notify connect. */
	ts->accept_connection_sock = connection_sock;

	thread_main_enter();
	ts->connect_callback(ts->callback_inst);
	thread_main_exit();

	DEBUG_ASSERT(ts->accept_connection_sock == -1, "tcp accept/reject not called");
}

tcp_error_t tcp_socket_listen(struct tcp_socket *ts, struct ip_datalink_instance *link, ipv4_addr_t addr, uint16_t port, tcp_connect_callback_t connect, void *inst)
{
	DEBUG_ASSERT(connect, "no connect callback specified");

	ts->connect_callback = connect;
	ts->callback_inst = inst;

	/* Bind socket. */
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(addr);
	sock_addr.sin_port = htons(port);
	if (bind(ts->sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
		DEBUG_WARN("failed to bind socket to %08X:%u", addr, port);
		return TCP_ERROR_SOCKET_BUSY;
	}

	/* Listen. */
	if (listen(ts->sock, 10) != 0) {
		DEBUG_WARN("listen failed on %08X:%u", addr, port);
		return TCP_ERROR_SOCKET_BUSY;
	}

	spinlock_lock(&tcp_manager.socket_new_lock);
	ts->next = tcp_manager.socket_new_list;
	tcp_manager.socket_new_list = ts;
	spinlock_unlock(&tcp_manager.socket_new_lock);

	tcp_socket_trigger_poll();
	return TCP_OK;
}

struct tcp_socket *tcp_socket_alloc(void)
{
	struct tcp_socket *ts = (struct tcp_socket *)heap_alloc_and_zero(sizeof(struct tcp_socket), PKG_OS, MEM_TYPE_OS_TCP_SOCKET);
	if (!ts) {
		return NULL;
	}

	/* Create socket. */
	ts->sock = (int)socket(AF_INET, SOCK_STREAM, 0);
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
	int sock_opt = 1;
	if (setsockopt(ts->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt SO_REUSEADDR error %d", errno);
	}

	return ts;
}

static inline void tcp_socket_thread_new_sockets(void)
{
	size_t add_count = 0;
	struct tcp_socket *ts = tcp_manager.socket_new_list;
	while (ts) {
		add_count++;
		ts = ts->next;
	}

	size_t total_count = tcp_manager.socket_poll_count + add_count;
	struct pollfd *poll_fds = (struct pollfd *)heap_realloc(tcp_manager.socket_poll_fds, sizeof(struct pollfd) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.socket_poll_fds = poll_fds;
	poll_fds += tcp_manager.socket_poll_count;

	struct tcp_socket **pprev = &tcp_manager.socket_active_list;
	struct tcp_socket *p = tcp_manager.socket_active_list;
	while (p) {
		pprev = &p->next;
		p = p->next;
	}

	while (tcp_manager.socket_new_list) {
		struct tcp_socket *ts = tcp_manager.socket_new_list;
		tcp_manager.socket_new_list = ts->next;
		ts->next = NULL;

		poll_fds->fd = ts->sock;
		poll_fds->events = POLLIN;
		poll_fds->revents = 0;
		poll_fds++;

		*pprev = ts;
		pprev = &ts->next;
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
		if (tcp_manager.socket_new_list) {
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

		struct tcp_socket *ts = tcp_manager.socket_active_list;
		while (ts) {
			DEBUG_ASSERT(ts->sock == poll_fds->fd, "list error");

			if (poll_fds->revents) {
				tcp_socket_thread_execute_sock(ts, poll_fds);
			}

			ts = ts->next;
			poll_fds++;
		}
	}
}
