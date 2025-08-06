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

#define TCP_MAX_RECV_NB_SIZE_DEFAULT (3 * 1024)
#define TCP_SEND_BUFFER_SIZE_DEFAULT (128 * 1024)
#define TCP_ESTABLISHED_TIMEOUT (TICK_RATE * 5)

struct tcp_connection {
	struct slist_prefix_t slist_prefix;
	int refs;
	int sock;
	HANDLE event_handle;
	ip_mode_t ip_mode;
	uint8_t ttl;
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
	uint8_t *sendfile_buffer;
	size_t sendfile_buffer_size;

	tcp_establish_callback_t est_callback;
	tcp_recv_callback_t recv_callback;
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

	closesocket(tc->sock);

	struct netbuf *send_nb = (struct netbuf *)tc->send_nb;
	if (send_nb) {
		netbuf_free(send_nb);
	}

	if (tc->sendfile_buffer) {
		heap_free(tc->sendfile_buffer);
	}

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
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size_set, (int)sizeof(send_buffer_size_set)) < 0) {
		DEBUG_WARN("setsockopt SO_SNDBUF error %d", WSAGetLastError());
	}

	if (RUNTIME_DEBUG) {
		int send_buffer_size = 0;
		int send_buffer_size_sizeof = sizeof(send_buffer_size);
		getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size, &send_buffer_size_sizeof);
		if (send_buffer_size != (int)size) {
			DEBUG_ERROR("failed to set send buffer size to %u", size);
		}
	}
}

void tcp_connection_set_send_buffer_size(struct tcp_connection *tc, size_t send_buffer_size)
{
	tc->send_buffer_size = send_buffer_size;

	if (tc->sock == -1) {
		return;
	}

	tcp_set_sock_send_buffer_size(tc->sock, send_buffer_size);
}

void tcp_connection_set_max_recv_nb_size(struct tcp_connection *tc, size_t max_recv_nb_size)
{
	tc->max_recv_nb_size = max_recv_nb_size;
}

static void tcp_connection_set_ttl_internal(int sock, ip_mode_t ip_mode, uint8_t ttl)
{
#if defined(IPV6_SUPPORT)
	if (ip_mode == IP_MODE_IPV6) {
		int sock_opt_ttl = (int)(unsigned int)ttl;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&sock_opt_ttl, sizeof(sock_opt_ttl)) < 0) {
			DEBUG_WARN("setsockopt IPV6_UNICAST_HOPS error %d", WSAGetLastError());
		}
		return;
	}
#endif

	int sock_opt_ttl = (int)(unsigned int)ttl;
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt_ttl, sizeof(sock_opt_ttl)) < 0) {
		DEBUG_WARN("setsockopt IP_TTL error %d", WSAGetLastError());
	}
}

void tcp_connection_set_ttl(struct tcp_connection *tc, uint8_t ttl)
{
	tc->ttl = ttl;

	if (tc->sock == -1) {
		return;
	}

	tcp_connection_set_ttl_internal(tc->sock, tc->ip_mode, ttl);
}

void tcp_connection_set_tos(struct tcp_connection *tc, uint8_t tos)
{
}

uint32_t tcp_connection_get_local_addr(struct tcp_connection *tc, ip_addr_t *result)
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

	if (getsockname(tc->sock, (struct sockaddr *)&sock_addr, &sock_addr_size) != 0) {
		ip_addr_set_zero(result);
		return 0;
	}

#if defined(IPV6_SUPPORT)
	uint32_t ipv6_scope_id;
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

uint32_t tcp_connection_get_remote_addr(struct tcp_connection *tc, ip_addr_t *result)
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

	if (getpeername(tc->sock, (struct sockaddr *)&sock_addr, &sock_addr_size) != 0) {
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

uint16_t tcp_connection_get_remote_port(struct tcp_connection *tc)
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

	if (getpeername(tc->sock, (struct sockaddr *)&sock_addr, &sock_addr_size) != 0) {
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

		netbuf_advance_pos(send_nb, (size_t)actual);
		netbuf_set_start_to_pos(send_nb);

		tc->send_nb = send_nb; /* Atomic update of volatile variable. */
		SetEvent(tcp_manager.connection_poll_signal);
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

	if (length > tc->sendfile_buffer_size) {
		if (tc->sendfile_buffer) {
			heap_free(tc->sendfile_buffer);
		}

		tc->sendfile_buffer_size = length;
		tc->sendfile_buffer = heap_alloc(length, PKG_OS, MEM_TYPE_OS_TCP_SENDFILE);
		if (!tc->sendfile_buffer) {
			DEBUG_ERROR("out of memory");
			tc->sendfile_buffer_size = 0;
			return TCP_ERROR_FAILED;
		}
	}

	size_t read_actual = file_read(file, tc->sendfile_buffer, length);
	if (read_actual == 0) {
		return TCP_ERROR_FILE;
	}

	int send_actual = send(tc->sock, (char *)tc->sendfile_buffer, (int)read_actual, 0);
	if (send_actual <= 0) {
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK) {
			DEBUG_INFO("tcp send failed (%d)", err);
			return TCP_ERROR_FAILED;
		}

		if (!file_seek_retreat(file, read_actual)) {
			DEBUG_ERROR("file_seek_retreat failed");
			return TCP_ERROR_FAILED;
		}

		return TCP_ERROR_SOCKET_BUSY;
	}

	if (send_actual < (int)read_actual) {
		if (!file_seek_retreat(file, read_actual - (size_t)send_actual)) {
			DEBUG_ERROR("file_seek_retreat failed");
			return TCP_ERROR_FAILED;
		}
	}

	*pactual = (size_t)send_actual;
	return TCP_OK;
}

static void tcp_connection_thread_send(struct tcp_connection *tc)
{
	struct netbuf *send_nb = (struct netbuf *)tc->send_nb;
	DEBUG_ASSERT(send_nb, "tcp_connection_thread_send called without packet to send");

	uint8_t *buffer = netbuf_get_ptr(send_nb);
	size_t length = netbuf_get_remaining(send_nb);

	int actual = send(tc->sock, (char *)buffer, (int)length, 0);
	if (actual < (int)length) {
		if (actual <= 0) {
			int err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK) {
				DEBUG_INFO("tcp send failed (%d)", err);
			}
			return;
		}
		
		netbuf_advance_pos(send_nb, (size_t)actual);
		netbuf_set_start_to_pos(send_nb);
		return;
	}

	netbuf_free(send_nb);
	tc->send_nb = NULL;

	if (tc->close_after_sending) {
		tc->dead = true;
		return;
	}
}

struct tcp_connection_notify_recv_t {
	struct tcp_connection *tc;
	struct netbuf *nb;
};

static void tcp_connection_notify_recv(struct tcp_connection_notify_recv_t *arg)
{
	struct tcp_connection *tc = arg->tc;
	if (tc->app_closed) {
		return;
	}

	tc->recv_callback(tc->callback_inst, arg->nb);
}

static void tcp_connection_thread_recv(struct tcp_connection *tc)
{
	unsigned long available = 0;
	if (ioctlsocket(tc->sock, FIONREAD, &available) < 0) {
		tc->dead = true;
		return;
	}

	if (available == 0) {
		tc->dead = true;
		return;
	}

	size_t recv_nb_size = min((size_t)available, tc->max_recv_nb_size);

	struct netbuf *nb = netbuf_alloc_with_fwd_space(recv_nb_size);
	while (!nb) {
		timer_sleep_fast(FAST_TICK_RATE_MS * 16);
		nb = netbuf_alloc_with_fwd_space(recv_nb_size);
	}

	uint8_t *buffer = netbuf_get_ptr(nb);
	int length = recv(tc->sock, (char *)buffer, (int)recv_nb_size, 0);
	if (length <= 0) {
		netbuf_free(nb);
		tc->dead = true;
		return;
	}

	netbuf_set_end(nb, netbuf_get_pos(nb) + (size_t)length);

	if (!tc->app_closed) {
		struct tcp_connection_notify_recv_t arg;
		arg.tc = tc;
		arg.nb = nb;
		thread_main_execute((thread_execute_func_t)tcp_connection_notify_recv, &arg);
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

static void tcp_connection_thread_est(struct tcp_connection *tc, WSANETWORKEVENTS *network_events)
{
	if (network_events->lNetworkEvents & FD_WRITE) {
		DEBUG_TRACE("connection established");
		tcp_manager.network_ok_indication = true;
		tc->established_timeout = 0;

		if (tc->est_callback && !tc->app_closed) {
			thread_main_execute((thread_execute_func_t)tcp_connection_notify_established, tc);
		}

		tcp_connection_thread_normal(tc, network_events);
		return;
	}

	if (network_events->lNetworkEvents & FD_CLOSE) {
		DEBUG_INFO("connection failed");
		tc->dead = true;
		return;
	}

	if (timer_get_ticks() >= tc->established_timeout) {
		DEBUG_INFO("connection timeout");
		tc->dead = true;
		return;
	}
}

tcp_error_t tcp_connection_connect(struct tcp_connection *tc, const ip_addr_t *dest_addr, uint16_t dest_port, uint32_t ipv6_scope_id, tcp_establish_callback_t est_callback, tcp_recv_callback_t recv_callback, tcp_close_callback_t close_callback, void *inst)
{
	DEBUG_ASSERT(tc->sock == -1, "already connected");
	DEBUG_ASSERT(recv_callback, "no recv callback specified");
	DEBUG_CHECK_IP_ADDR_IPV6_SCOPE_ID(dest_addr, ipv6_scope_id);

	tc->est_callback = est_callback;
	tc->recv_callback = recv_callback;
	tc->close_callback = close_callback;
	tc->callback_inst = inst;

	tc->ip_mode = ip_addr_is_ipv6(dest_addr) ? IP_MODE_IPV6 : IP_MODE_IPV4;

	int af_inet = (tc->ip_mode == IP_MODE_IPV6) ? AF_INET6 : AF_INET;
	int sock = (int)socket(af_inet, SOCK_STREAM, IPPROTO_TCP);
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
	tcp_connection_set_ttl_internal(sock, tc->ip_mode, tc->ttl);

	/* Connect. */
#if defined(IPV6_SUPPORT)
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	socklen_t sock_addr_size;
	if (tc->ip_mode == IP_MODE_IPV6) {
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

	if (connect(sock, (struct sockaddr *)&sock_addr, sock_addr_size) != 0) {
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
	slist_attach_head(struct tcp_connection, &tcp_manager.connection_new_list, tc);
	spinlock_unlock(&tcp_manager.connection_new_lock);
	SetEvent(tcp_manager.connection_poll_signal);

	return TCP_OK;
}

void tcp_connection_accept(struct tcp_connection *tc, int sock, ip_mode_t ip_mode, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst)
{
	/* Set send buffer size. */
	tcp_set_sock_send_buffer_size(sock, tc->send_buffer_size);

	/* Set ttl */
	tcp_connection_set_ttl_internal(sock, ip_mode, tc->ttl);

	tc->sock = sock;
	tc->ip_mode = ip_mode;
	tc->est_callback = est;
	tc->recv_callback = recv;
	tc->close_callback = close;
	tc->callback_inst = inst;

	tc->established_timeout = timer_get_ticks() + TCP_ESTABLISHED_TIMEOUT;

	tcp_connection_ref(tc);

	spinlock_lock(&tcp_manager.connection_new_lock);
	slist_attach_head(struct tcp_connection, &tcp_manager.connection_new_list, tc);
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
	tc->max_recv_nb_size = TCP_MAX_RECV_NB_SIZE_DEFAULT;
	tc->send_buffer_size = TCP_SEND_BUFFER_SIZE_DEFAULT;

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
	size_t add_count = slist_get_count(&tcp_manager.connection_new_list);
	size_t total_count = tcp_manager.connection_poll_count + add_count;

	HANDLE *poll_handles = (HANDLE *)heap_realloc(tcp_manager.connection_poll_handles, sizeof(HANDLE) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.connection_poll_handles = poll_handles;
	poll_handles += tcp_manager.connection_poll_count;

	struct tcp_connection **pprev = slist_get_phead(struct tcp_connection, &tcp_manager.connection_active_list);
	struct tcp_connection *p = slist_get_head(struct tcp_connection, &tcp_manager.connection_active_list);
	while (p) {
		pprev = slist_get_pnext(struct tcp_connection, p);
		p = slist_get_next(struct tcp_connection, p);
	}

	while (1) {
		struct tcp_connection *tc = slist_get_head(struct tcp_connection, &tcp_manager.connection_new_list);
		if (!tc) {
			break;
		}

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

		slist_detach_head(struct tcp_connection, &tcp_manager.connection_new_list);
		slist_insert_pprev(struct tcp_connection, pprev, tc);

		pprev = slist_get_pnext(struct tcp_connection, tc);
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
		struct tcp_connection **pprev = slist_get_phead(struct tcp_connection, &tcp_manager.connection_active_list);
		struct tcp_connection *tc = slist_get_head(struct tcp_connection, &tcp_manager.connection_active_list);
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
					thread_main_execute((thread_execute_func_t)tcp_connection_notify_close, tc);
				}

				struct tcp_connection *discard = tc;
				tc = slist_get_next(struct tcp_connection, tc);

				tcp_connection_thread_delete_connection_from_poll_handles(poll_handles);
				(void)slist_detach_pprev(struct tcp_connection, pprev, discard);
				tcp_connection_deref(discard);
				continue;
			}

			if (tc->established_timeout > 0) {
				tcp_connection_thread_est(tc, &network_events);
			} else {
				tcp_connection_thread_normal(tc, &network_events);
			}

			pprev = slist_get_pnext(struct tcp_connection, tc);
			tc = slist_get_next(struct tcp_connection, tc);
			poll_handles++;
		}

		if (slist_get_head(struct tcp_connection, &tcp_manager.connection_new_list)) {
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
