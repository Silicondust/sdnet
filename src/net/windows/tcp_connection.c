/*
 * tcp_connection.c
 *
 * Copyright © 2007-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("tcp_connection");

/*
 * Threading:
 *	tcp_connection_send_netbuf may be called from any thread, but always the same thread for any one connection.
 *  callbacks sent from main thread.
 */

#define TCP_RX_NETBUF_SIZE 1460
#define TCP_TX_BUFFER_SIZE (128 * 1024)
#define TCP_ESTABLISHED_TIMEOUT (TICK_RATE * 5)

struct tcp_connection {
	struct tcp_connection *next;
	int refs;
	int sock;
	HANDLE event_handle;
	uint8_t ttl;
	uint8_t tos;
	bool recv_event_received_while_paused;
	bool close_event_received;
	bool close_after_sending;
	bool app_closed;
	volatile bool dead;
	volatile bool recv_paused;
	volatile struct netbuf *send_nb;
	size_t max_recv_nb_size;
	size_t send_buffer_size;
	ticks_t established_timeout;

	tcp_establish_callback_t est_callback;
	tcp_recv_callback_t recv_callback;
	tcp_send_resume_callback_t send_resume_callback;
	tcp_close_callback_t close_callback;
	void *callback_inst;
};

struct tcp_connection *tcp_connection_ref(struct tcp_connection *tc)
{
	tc->refs++;
	return tc;
}

int tcp_connection_deref(struct tcp_connection *tc)
{
	tc->refs--;
	if (tc->refs != 0) {
		return tc->refs;
	}

	struct netbuf *send_nb = (struct netbuf *)tc->send_nb;
	if (send_nb) {
		netbuf_free(send_nb);
	}

	closesocket(tc->sock);

	heap_free(tc);
	return 0;
}

void tcp_connection_close(struct tcp_connection *tc)
{
	tc->app_closed = true;
	tc->close_after_sending = true;

	if (!tc->send_nb) {
		tc->dead = true;
	}
}

void tcp_connection_reset(struct tcp_connection *tc)
{
	tc->app_closed = true;
	tc->dead = true;
}

static void tcp_set_sock_send_buffer_size(int sock, size_t size)
{
	int send_buffer_size_set = (int)size;
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size_set, (int)sizeof(send_buffer_size_set));

	if (RUNTIME_DEBUG) {
		int send_buffer_size = 0;
		int send_buffer_size_sizeof = sizeof(send_buffer_size);
		getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size, &send_buffer_size_sizeof);
		if (send_buffer_size != (int)size) {
			DEBUG_ERROR("failed to set send buffer size to %u", size);
		}
	}
}

void tcp_connection_set_max_recv_nb_size(struct tcp_connection *tc, size_t max_recv_nb_size)
{
	tc->max_recv_nb_size = max_recv_nb_size;
}

void tcp_connection_set_ttl(struct tcp_connection *tc, uint8_t ttl)
{
	tc->ttl = ttl;

	if (tc->sock == -1) {
		return;
	}

	int sock_opt = (int)(unsigned int)ttl;
	if (setsockopt(tc->sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TTL error %d", errno);
	}
}

void tcp_connection_set_tos(struct tcp_connection *tc, uint8_t tos)
{
	tc->tos = tos;

	if (tc->sock == -1) {
		return;
	}

	int sock_opt = (int)(unsigned int)tos;
	if (setsockopt(tc->sock, IPPROTO_IP, IP_TOS, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TOS error %d", errno);
	}
}

ipv4_addr_t tcp_connection_get_local_addr(struct tcp_connection *tc)
{
	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	socklen_t addr_len = sizeof(local_addr);
	getsockname(tc->sock, (struct sockaddr *)&local_addr, &addr_len);
	return ntohl(local_addr.sin_addr.s_addr);
}

ipv4_addr_t tcp_connection_get_remote_addr(struct tcp_connection *tc)
{
	struct sockaddr_in remote_addr;
	memset(&remote_addr, 0, sizeof(remote_addr));
	socklen_t addr_len = sizeof(remote_addr);
	getpeername(tc->sock, (struct sockaddr *)&remote_addr, &addr_len);
	return ntohl(remote_addr.sin_addr.s_addr);
}

uint16_t tcp_connection_get_remote_port(struct tcp_connection *tc)
{
	struct sockaddr_in remote_addr;
	memset(&remote_addr, 0, sizeof(remote_addr));
	socklen_t addr_len = sizeof(remote_addr);
	getpeername(tc->sock, (struct sockaddr *)&remote_addr, &addr_len);
	return ntohs(remote_addr.sin_port);
}

void tcp_connection_pause_recv(struct tcp_connection *tc)
{
	tc->recv_paused = true;
}

void tcp_connection_resume_recv(struct tcp_connection *tc)
{
	if (!tc->recv_paused || tc->app_closed) {
		return;
	}

	tc->recv_paused = false;
	SetEvent(tcp_manager.connection_poll_signal);
}

tcp_error_t tcp_connection_can_send(struct tcp_connection *tc)
{
	if (tc->app_closed) {
		return TCP_ERROR_FAILED;
	}
	if (tc->send_nb) {
		return TCP_ERROR_SOCKET_BUSY;
	}
	return TCP_OK;
}

tcp_error_t tcp_connection_send_netbuf(struct tcp_connection *tc, struct netbuf *nb)
{
	if (tc->app_closed) {
		return TCP_ERROR_FAILED;
	}
	if (tc->send_nb) {
		return TCP_ERROR_SOCKET_BUSY;
	}

	uint8_t *buffer = netbuf_get_ptr(nb);
	size_t length = netbuf_get_remaining(nb);
	if (length >= tc->send_buffer_size) {
		tc->send_buffer_size = TCP_TX_BUFFER_SIZE + length;
		DEBUG_INFO("tcp send buffer size set %u", tc->send_buffer_size);
		tcp_set_sock_send_buffer_size(tc->sock, tc->send_buffer_size);
	}

	int actual = send(tc->sock, (char *)buffer, (int)length, 0);
	if (actual < (int)length) {
		if (actual <= 0) {
			int err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK) {
				DEBUG_INFO("tcp send failed (%d)", err);
				return TCP_ERROR_FAILED;
			}
			actual = 0;
		}

		struct netbuf *send_nb = netbuf_alloc_and_steal(nb);
		if (!send_nb) {
			DEBUG_ERROR("out of memory");
			return TCP_ERROR_FAILED;
		}

		netbuf_advance_pos(send_nb, actual);
		netbuf_set_start_to_pos(send_nb);

		tc->send_nb = send_nb; /* Atomic update of volatile variable. */
	}

	return TCP_OK;
}

tcp_error_t tcp_connection_send_file(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual)
{
	if (tc->app_closed) {
		return TCP_ERROR_FAILED;
	}
	if (tc->send_nb) {
		return TCP_ERROR_SOCKET_BUSY;
	}

	if (length >= tc->send_buffer_size) {
		tc->send_buffer_size = TCP_TX_BUFFER_SIZE + length;
		DEBUG_INFO("tcp send buffer size set %u", tc->send_buffer_size);
		tcp_set_sock_send_buffer_size(tc->sock, tc->send_buffer_size);
	}

	struct netbuf *txnb = netbuf_alloc_with_fwd_space(length);
	if (!txnb) {
		return TCP_ERROR_FAILED;
	}

	uint8_t *buffer = netbuf_get_ptr(txnb);
	size_t read_actual = file_read(file, buffer, length);
	if (read_actual == 0) {
		netbuf_free(txnb);
		return TCP_ERROR_FILE;
	}

	int send_actual = send(tc->sock, (char *)buffer, (int)read_actual, 0);
	if (send_actual < (int)read_actual) {
		if (send_actual <= 0) {
			int err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK) {
				DEBUG_INFO("tcp send failed (%d)", err);
				return TCP_ERROR_FAILED;
			}
			send_actual = 0;
		}

		netbuf_set_end(txnb, netbuf_get_pos(txnb) + read_actual);
		netbuf_advance_pos(txnb, send_actual);
		netbuf_set_start_to_pos(txnb);

		tc->send_nb = txnb; /* Atomic update of volatile variable. */

		*pactual = read_actual;
		return TCP_OK;
	}

	netbuf_free(txnb);
	*pactual = read_actual;
	return TCP_OK;
}

static void tcp_connection_notify_send_resume(struct tcp_connection *tc)
{
	if (tc->app_closed) {
		return;
	}

	tc->send_resume_callback(tc->callback_inst);
}

static void tcp_connection_thread_send(struct tcp_connection *tc)
{
	struct netbuf *send_nb = (struct netbuf *)tc->send_nb;
	DEBUG_ASSERT(send_nb, "tcp_connection_thread_send called without packet to send");

	uint8_t *buffer = netbuf_get_ptr(send_nb);
	int length = (int)netbuf_get_remaining(send_nb);
	int actual = send(tc->sock, (char *)buffer, length, 0);
	if (actual < length) {
		if (actual <= 0) {
			int err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK) {
				DEBUG_INFO("tcp send failed (%d)", err);
			}
			return;
		}
		
		netbuf_advance_pos(send_nb, actual);
		netbuf_set_start_to_pos(send_nb);
		return;
	}

	netbuf_free(send_nb);
	tc->send_nb = NULL;

	if (tc->close_after_sending) {
		tc->dead = true;
		return;
	}

	if (tc->send_resume_callback && !tc->app_closed) {
		thread_main_enter();
		tcp_connection_notify_send_resume(tc);
		thread_main_exit();
	}
}

static void tcp_connection_notify_recv(struct tcp_connection *tc, struct netbuf *nb)
{
	if (tc->app_closed) {
		return;
	}

	tc->recv_callback(tc->callback_inst, nb);
}

static void tcp_connection_thread_recv(struct tcp_connection *tc)
{
	struct netbuf *nb = netbuf_alloc_with_fwd_space(tc->max_recv_nb_size);
	while (!nb) {
		timer_sleep_fast(FAST_TICK_RATE_MS * 16);
		nb = netbuf_alloc_with_fwd_space(tc->max_recv_nb_size);
	}

	uint8_t *buffer = netbuf_get_ptr(nb);
	int length = recv(tc->sock, (char *)buffer, (int)tc->max_recv_nb_size, 0);
	if (length <= 0) {
		netbuf_free(nb);
		tc->dead = true;
		return;
	}

	netbuf_set_end(nb, netbuf_get_pos(nb) + length);

	if (!tc->app_closed) {
		thread_main_enter();
		tcp_connection_notify_recv(tc, nb);
		thread_main_exit();
	}

	netbuf_free(nb);
}

static void tcp_connection_notify_established(struct tcp_connection *tc)
{
	if (tc->app_closed) {
		return;
	}

	tc->est_callback(tc->callback_inst);
}

static void tcp_connection_thread_est(struct tcp_connection *tc, WSANETWORKEVENTS *network_events)
{
	if (network_events->lNetworkEvents & FD_CLOSE) {
		DEBUG_INFO("connection failed");
		tc->dead = true;
		return;
	}

	if (network_events->lNetworkEvents & FD_WRITE) {
		DEBUG_TRACE("connection established");
		tcp_manager.network_ok_indication = true;
		tc->established_timeout = 0;

		if (tc->est_callback && !tc->app_closed) {
			thread_main_enter();
			tcp_connection_notify_established(tc);
			thread_main_exit();
		}

		if (network_events->lNetworkEvents & FD_READ) {
			tcp_connection_thread_recv(tc);
		}

		return;
	}

	if (timer_get_ticks() >= tc->established_timeout) {
		DEBUG_INFO("connection timeout");
		tc->dead = true;
		return;
	}
}

static void tcp_connection_thread_normal(struct tcp_connection *tc, WSANETWORKEVENTS *network_events)
{
	if (tc->send_nb) {
		tcp_connection_thread_send(tc);
	}

	if (network_events->lNetworkEvents & FD_CLOSE) {
		tc->close_event_received = true;
	}

	if ((network_events->lNetworkEvents & FD_READ) || tc->recv_event_received_while_paused) {
		if (tc->recv_paused) {
			tc->recv_event_received_while_paused = true;
			return;
		}

		tc->recv_event_received_while_paused = false;
		tcp_connection_thread_recv(tc);
		return;
	}

	if (tc->close_event_received) {
		tc->dead = true;
		return;
	}
}

tcp_error_t tcp_connection_connect(struct tcp_connection *tc, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint16_t src_port, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst)
{
	DEBUG_ASSERT(tc->sock == -1, "already connected");
	DEBUG_ASSERT(recv, "no recv callback specified");

	tc->est_callback = est;
	tc->recv_callback = recv;
	tc->send_resume_callback = send_resume;
	tc->close_callback = close;
	tc->callback_inst = inst;

	int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		DEBUG_ERROR("failed to allocate socket");
		return TCP_ERROR_FAILED;
	}

	/* Set non-blocking. */
	unsigned long mode = 1;
	if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
		DEBUG_ERROR("failed set socket to non-blocking");
		closesocket(sock);
		return TCP_ERROR_FAILED;
	}

	/* Set send buffer size. */
	tcp_set_sock_send_buffer_size(sock, tc->send_buffer_size);

	/* Set ttl */
	int sock_opt = (int)(unsigned int)tc->ttl;
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TTL error %d", errno);
	}

	/* Set tos */
	sock_opt = (int)(unsigned int)tc->tos;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TOS error %d", errno);
	}

	/* Connect. */
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(dest_addr);
	sock_addr.sin_port = htons(dest_port);
	if (connect(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK) {
			DEBUG_WARN("connect failed (%d)", err);
			closesocket(sock);
			return TCP_ERROR_FAILED;
		}
	}

	tc->sock = sock;
	tc->established_timeout = timer_get_ticks() + TCP_ESTABLISHED_TIMEOUT;

	tcp_connection_ref(tc);

	spinlock_lock(&tcp_manager.connection_new_lock);
	tc->next = tcp_manager.connection_new_list;
	tcp_manager.connection_new_list = tc;
	spinlock_unlock(&tcp_manager.connection_new_lock);
	SetEvent(tcp_manager.connection_poll_signal);

	return TCP_OK;
}

void tcp_connection_accept(struct tcp_connection *tc, int sock, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst)
{
	DEBUG_INFO("accept");

	/* Set send buffer size. */
	tcp_set_sock_send_buffer_size(sock, tc->send_buffer_size);

	/* Set ttl */
	int sock_opt = (int)(unsigned int)tc->ttl;
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TTL error %d", errno);
	}

	/* Set tos */
	sock_opt = (int)(unsigned int)tc->tos;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&sock_opt, sizeof(sock_opt)) < 0) {
		DEBUG_WARN("setsockopt IP_TOS error %d", errno);
	}

	tc->sock = sock;
	tc->est_callback = est;
	tc->recv_callback = recv;
	tc->send_resume_callback = send_resume;
	tc->close_callback = close;
	tc->callback_inst = inst;

	tc->established_timeout = timer_get_ticks() + TCP_ESTABLISHED_TIMEOUT;

	tcp_connection_ref(tc);

	spinlock_lock(&tcp_manager.connection_new_lock);
	tc->next = tcp_manager.connection_new_list;
	tcp_manager.connection_new_list = tc;
	spinlock_unlock(&tcp_manager.connection_new_lock);
	SetEvent(tcp_manager.connection_poll_signal);
}

struct tcp_connection *tcp_connection_alloc(void)
{
	struct tcp_connection *tc = (struct tcp_connection *)heap_alloc_and_zero(sizeof(struct tcp_connection), PKG_OS, MEM_TYPE_OS_TCP_CONNECTION);
	if (!tc) {
		return NULL;
	}

	tc->refs = 1;
	tc->sock = -1;
	tc->ttl = 64;
	tc->max_recv_nb_size = TCP_RX_NETBUF_SIZE;
	tc->send_buffer_size = TCP_TX_BUFFER_SIZE;

	return tc;
}

static void tcp_connection_notify_close(struct tcp_connection *tc)
{
	if (tc->app_closed) {
		return;
	}

	tc->app_closed = true;
	tc->close_callback(tc->callback_inst, 0);
}

static inline void tcp_connection_thread_new_connections(void)
{
	size_t add_count = 0;
	struct tcp_connection *tc = tcp_manager.connection_new_list;
	while (tc) {
		add_count++;
		tc = tc->next;
	}

	size_t total_count = tcp_manager.connection_poll_count + add_count;
	HANDLE *poll_handles = (HANDLE *)heap_realloc(tcp_manager.connection_poll_handles, sizeof(HANDLE) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.connection_poll_handles = poll_handles;
	poll_handles += tcp_manager.connection_poll_count;

	struct tcp_connection **pprev = &tcp_manager.connection_active_list;
	struct tcp_connection *p = tcp_manager.connection_active_list;
	while (p) {
		pprev = &p->next;
		p = p->next;
	}

	while (tcp_manager.connection_new_list) {
		tc = tcp_manager.connection_new_list;

		HANDLE event_handle = CreateEvent(NULL, false, false, NULL);
		if (!event_handle) {
			break;
		}

		if (WSAEventSelect(tc->sock, event_handle,  FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
			CloseHandle(event_handle);
			break;
		}

		tc->event_handle = event_handle;
		*poll_handles++ = event_handle;
		tcp_manager.connection_poll_count++;

		tcp_manager.connection_new_list = tc->next;
		tc->next = NULL;

		*pprev = tc;
		pprev = &tc->next;
	}
}

static void tcp_connection_thread_delete_connection_from_poll_handles(HANDLE *poll_handles)
{
	HANDLE *poll_handles_end = tcp_manager.connection_poll_handles + tcp_manager.connection_poll_count;
	tcp_manager.connection_poll_count--;

	size_t move_count = poll_handles_end - (poll_handles + 1);
	if (move_count == 0) {
		return;
	}

	memmove(poll_handles, poll_handles + 1, move_count * sizeof(HANDLE));
}

void tcp_connection_thread_execute(void *arg)
{
	while (1) {
		struct tcp_connection **pprev = &tcp_manager.connection_active_list;
		struct tcp_connection *tc = tcp_manager.connection_active_list;
		HANDLE *poll_handles = tcp_manager.connection_poll_handles + 1;
		while (tc) {
			DEBUG_ASSERT(tc->event_handle == *poll_handles, "list error");

			WSANETWORKEVENTS network_events;
			if (WSAEnumNetworkEvents(tc->sock, tc->event_handle, &network_events) == SOCKET_ERROR) {
				tc->dead = true;
			}

			if (tc->dead) {
				if (!tc->close_callback) {
					tc->app_closed = true;
				}

				if (!tc->app_closed) {
					thread_main_enter();
					tcp_connection_notify_close(tc);
					thread_main_exit();
				}

				tcp_connection_thread_delete_connection_from_poll_handles(poll_handles);
				*pprev = tc->next;
				tcp_connection_deref(tc);
				tc = *pprev;
				continue;
			}

			if (tc->established_timeout > 0) {
				tcp_connection_thread_est(tc, &network_events);
			} else {
				tcp_connection_thread_normal(tc, &network_events);
			}

			pprev = &tc->next;
			tc = tc->next;
			poll_handles++;
		}

		if (tcp_manager.connection_new_list) {
			spinlock_lock(&tcp_manager.connection_new_lock);
			tcp_connection_thread_new_connections();
			spinlock_unlock(&tcp_manager.connection_new_lock);
		}

		DWORD connection_poll_count = (DWORD)tcp_manager.connection_poll_count;
		if (connection_poll_count > WSA_MAXIMUM_WAIT_EVENTS) {
			connection_poll_count = WSA_MAXIMUM_WAIT_EVENTS;
		}

		DWORD ret = WSAWaitForMultipleEvents(connection_poll_count, tcp_manager.connection_poll_handles, false, 16, false);
		if (ret == WAIT_FAILED) {
			DEBUG_ERROR("poll error %u", WSAGetLastError());
			timer_sleep_fast(FAST_TICK_RATE_MS * 16);
		}
	}
}
