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
	int sock;
	int accept_connection_sock;
	HANDLE event_handle;
	tcp_connect_callback_t connect_callback;
	void *callback_inst;
};

uint16_t tcp_socket_get_port(struct tcp_socket *ts)
{
	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	socklen_t addr_len = sizeof(local_addr);
	getsockname(ts->sock, (struct sockaddr *)&local_addr, &addr_len);
	return ntohs(local_addr.sin_port);
}

void tcp_socket_accept(struct tcp_socket *ts, struct tcp_connection *tc, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp accept called without connection pending");

	tcp_connection_accept(tc, ts->accept_connection_sock, est, recv, close, inst);
	ts->accept_connection_sock = -1;
}

void tcp_socket_reject(struct tcp_socket *ts)
{
	DEBUG_ASSERT(ts->accept_connection_sock != -1, "tcp reject called without connection pending");

	closesocket(ts->accept_connection_sock);
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
	unsigned long mode = 1;
	if (ioctlsocket(connection_sock, FIONBIO, &mode) != 0) {
		closesocket(connection_sock);
		return;
	}

	/* Notify connect. */
	ts->accept_connection_sock = connection_sock;

	thread_main_enter();
	ts->connect_callback(ts->callback_inst);
	thread_main_exit();

	DEBUG_ASSERT(ts->accept_connection_sock == -1, "tcp accept/reject not called");
}

tcp_error_t tcp_socket_listen(struct tcp_socket *ts, ipv4_addr_t addr, uint16_t port, tcp_connect_callback_t connect, void *inst)
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
		int err = WSAGetLastError();
		DEBUG_WARN("listen failed on %08X:%u (error %u)", addr, port, err);
		return TCP_ERROR_SOCKET_BUSY;
	}

	spinlock_lock(&tcp_manager.socket_new_lock);
	slist_attach_head(struct tcp_socket, &tcp_manager.socket_new_list, ts);
	spinlock_unlock(&tcp_manager.socket_new_lock);
	SetEvent(tcp_manager.socket_poll_signal);

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
	unsigned long mode = 1;
	if (ioctlsocket(ts->sock, FIONBIO, &mode) != 0) {
		DEBUG_ERROR("failed set socket to non-blocking");
		closesocket(ts->sock);
		heap_free(ts);
		return NULL;
	}

	return ts;
}

static inline void tcp_socket_thread_new_sockets(void)
{
	size_t add_count = slist_get_count(&tcp_manager.socket_new_list);
	size_t total_count = tcp_manager.socket_poll_count + add_count;

	HANDLE *poll_handles = (HANDLE *)heap_realloc(tcp_manager.socket_poll_handles, sizeof(HANDLE) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.socket_poll_handles = poll_handles;
	poll_handles += tcp_manager.socket_poll_count;

	struct tcp_socket **pprev = slist_get_phead(struct tcp_socket, &tcp_manager.socket_active_list);
	struct tcp_socket *p = slist_get_head(struct tcp_socket, &tcp_manager.socket_active_list);
	while (p) {
		pprev = slist_get_pnext(struct tcp_socket, p);
		p = slist_get_next(struct tcp_socket, p);
	}

	while (1) {
		struct tcp_socket *ts = slist_get_head(struct tcp_socket, &tcp_manager.socket_new_list);
		if (!ts) {
			break;
		}

		HANDLE event_handle = CreateEvent(NULL, false, false, NULL);
		if (!event_handle) {
			break;
		}

		if (WSAEventSelect(ts->sock, event_handle, FD_ACCEPT) == SOCKET_ERROR) {
			CloseHandle(event_handle);
			break;
		}

		ts->event_handle = event_handle;
		*poll_handles++ = event_handle;
		tcp_manager.socket_poll_count++;

		slist_detach_head(struct tcp_socket, &tcp_manager.socket_new_list);
		slist_insert_pprev(struct tcp_socket, pprev, ts);

		pprev = slist_get_pnext(struct tcp_socket, ts);
	}
}

void tcp_socket_thread_execute(void *arg)
{
	while (1) {
		struct tcp_socket *ts = slist_get_head(struct tcp_socket, &tcp_manager.socket_active_list);
		HANDLE *poll_handles = tcp_manager.socket_poll_handles + 1;
		while (ts) {
			DEBUG_ASSERT(ts->event_handle == *poll_handles, "list error");
			tcp_socket_thread_accept(ts);
			ts = slist_get_next(struct tcp_socket, ts);
			poll_handles++;
		}

		if (slist_get_head(struct tcp_socket, &tcp_manager.socket_new_list)) {
			spinlock_lock(&tcp_manager.socket_new_lock);
			tcp_socket_thread_new_sockets();
			spinlock_unlock(&tcp_manager.socket_new_lock);
		}

		DWORD socket_poll_count = (DWORD)tcp_manager.socket_poll_count;
		if (socket_poll_count > WSA_MAXIMUM_WAIT_EVENTS) {
			socket_poll_count = WSA_MAXIMUM_WAIT_EVENTS;
		}

		DWORD ret = WSAWaitForMultipleEvents(socket_poll_count, tcp_manager.socket_poll_handles, false, WSA_INFINITE, false);
		if (ret == WAIT_FAILED) {
			DEBUG_ERROR("poll error %u", WSAGetLastError());
			timer_sleep_fast(FAST_TICK_RATE_MS * 100);
		}
	}
}
