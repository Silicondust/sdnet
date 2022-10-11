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

#if !defined(TCP_CONNECTION_KEEPALIVE_SECONDS)
#define TCP_CONNECTION_KEEPALIVE_SECONDS 60
#endif

void tcp_connection_trigger_poll(void)
{
	uint8_t v = 0;
	if (write(tcp_manager.connection_poll_trigger_fd, &v, 1) != 1) {
		DEBUG_WARN("tcp connection trigger failed");
	}
}

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

	close(tc->sock);

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

static void tcp_connection_set_tos_internal(int sock, ip_mode_t ip_mode, uint8_t tos)
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
	tc->tos = tos;

	if (tc->sock == -1) {
		return;
	}

	tcp_connection_set_tos_internal(tc->sock, tc->ip_mode, tos);
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
	tcp_connection_trigger_poll();
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

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t actual = send(tc->sock, (char *)buffer, length, MSG_NOSIGNAL);
	if (actual < (ssize_t)length) {
		if (actual <= 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
				DEBUG_INFO("tcp send failed (%d %d)", (int)actual, errno);
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
		tcp_connection_trigger_poll();
	}

	return TCP_OK;
}

tcp_error_t tcp_connection_send_file_fallback(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual)
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

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t send_actual = send(tc->sock, (char *)tc->sendfile_buffer, read_actual, MSG_NOSIGNAL);
	if (send_actual <= 0) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
			DEBUG_INFO("tcp send failed (%d %d)", (int)send_actual, errno);
			return TCP_ERROR_FAILED;
		}

		if (!file_seek_retreat(file, read_actual)) {
			DEBUG_ERROR("file_seek_retreat failed");
			return TCP_ERROR_FAILED;
		}

		return TCP_ERROR_SOCKET_BUSY;
	}

	if (send_actual < (ssize_t)read_actual) {
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

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t actual = send(tc->sock, (char *)buffer, length, MSG_NOSIGNAL);
	if (actual < (ssize_t)length) {
		if (actual <= 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
				DEBUG_INFO("tcp send failed (%d)", errno);
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

static void tcp_connection_notify_recv(struct tcp_connection *tc, struct netbuf *nb)
{
	if (tc->app_closed) {
		return;
	}

	tc->recv_callback(tc->callback_inst, nb);
}

static void tcp_connection_thread_recv(struct tcp_connection *tc)
{
	int available = 0;
	if (ioctl(tc->sock, FIONREAD, &available) < 0) {
		tc->dead = true;
		return;
	}

	if (available <= 0) {
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
	ssize_t length = recv(tc->sock, (char *)buffer, recv_nb_size, 0);
	if (length <= 0) {
		netbuf_free(nb);
		tc->dead = true;
		return;
	}

	netbuf_set_end(nb, netbuf_get_pos(nb) + (size_t)length);

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
	int sock = (int)socket(af_inet, SOCK_STREAM, 0);
	if (sock == -1) {
		DEBUG_ERROR("failed to allocate socket");
		return TCP_ERROR_FAILED;
	}

	/* Set non-blocking. */
	if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
		DEBUG_ASSERT(0, "failed set socket to non-blocking");
		close(sock);		
		return TCP_ERROR_FAILED;
	}

	/* Set no-delay. */
	int sock_opt_nodelay = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&sock_opt_nodelay, sizeof(sock_opt_nodelay)) < 0) {
		DEBUG_WARN("setsockopt TCP_NODELAY error %d", errno);
	}

	/* Configure socket not to generate pipe-error signal (BSD/OSX). */
	tcp_set_sock_nosigpipe(sock);

	/* Set send buffer size. */
	tcp_set_sock_send_buffer_size(sock, tc->send_buffer_size);

	/* Set ttl */
	tcp_connection_set_ttl_internal(sock, tc->ip_mode, tc->ttl);

	/* Set tos */
	tcp_connection_set_tos_internal(sock, tc->ip_mode, tc->tos);

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

	errno = EAGAIN; /* workaround Abilis bug */
	if (connect(sock, (struct sockaddr *)&sock_addr, sock_addr_size) != 0) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
			DEBUG_WARN("connect failed (%d)", errno);
			close(sock);
			return TCP_ERROR_FAILED;
		}
	}

	tc->sock = sock;
	tc->established_timeout = timer_get_ticks() + TCP_ESTABLISHED_TIMEOUT;

	tcp_connection_ref(tc);

	spinlock_lock(&tcp_manager.connection_new_lock);
	slist_attach_head(struct tcp_connection, &tcp_manager.connection_new_list, tc);
	spinlock_unlock(&tcp_manager.connection_new_lock);
	tcp_connection_trigger_poll();

	return TCP_OK;
}

void tcp_connection_accept(struct tcp_connection *tc, int sock, ip_mode_t ip_mode, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst)
{
	/* Set send buffer size. */
	tcp_set_sock_send_buffer_size(sock, tc->send_buffer_size);

	/* Set keepalive time */
	tcp_set_sock_keepalive(sock, TCP_CONNECTION_KEEPALIVE_SECONDS);

	/* Set ttl */
	tcp_connection_set_ttl_internal(sock, ip_mode, tc->ttl);

	/* Set tos */
	tcp_connection_set_tos_internal(sock, ip_mode, tc->tos);

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
	tcp_connection_trigger_poll();
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

	struct pollfd *poll_fds = (struct pollfd *)heap_realloc(tcp_manager.connection_poll_fds, sizeof(struct pollfd) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.connection_poll_fds = poll_fds;
	poll_fds += tcp_manager.connection_poll_count;

	struct tcp_connection **pprev = slist_get_phead(struct tcp_connection, &tcp_manager.connection_active_list);
	struct tcp_connection *p = slist_get_head(struct tcp_connection, &tcp_manager.connection_active_list);
	while (p) {
		pprev = slist_get_pnext(struct tcp_connection, p);
		p = slist_get_next(struct tcp_connection, p);
	}

	while (1) {
		struct tcp_connection *tc = slist_detach_head(struct tcp_connection, &tcp_manager.connection_new_list);
		if (!tc) {
			break;
		}

		poll_fds->fd = tc->sock;
		poll_fds->events = POLLOUT;
		poll_fds->revents = 0;
		poll_fds++;

		slist_insert_pprev(struct tcp_connection, pprev, tc);
		pprev = slist_get_pnext(struct tcp_connection, tc);
	}

	tcp_manager.connection_poll_count = total_count;
}

static void tcp_connection_thread_delete_connection_from_poll_fds(struct pollfd *poll_fds)
{
	struct pollfd *poll_fds_end = tcp_manager.connection_poll_fds + tcp_manager.connection_poll_count;
	tcp_manager.connection_poll_count--;

	size_t move_count = poll_fds_end - (poll_fds + 1);
	if (move_count == 0) {
		return;
	}

	memmove(poll_fds, poll_fds + 1, move_count * sizeof(struct pollfd));
}

static inline void tcp_connection_update_send_event_mask(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (UNLIKELY(tc->send_nb)) {
		poll_fds->events |= POLLOUT;
		return;
	}

	poll_fds->events &= ~POLLOUT;
}

static inline void tcp_connection_update_recv_event_mask(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (UNLIKELY(tc->recv_event_received_while_paused)) {
		poll_fds->events &= ~POLLIN;
		return;
	}

	poll_fds->events |= POLLIN;
}

static void tcp_connection_thread_execute_active(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (tc->send_nb) {
		tcp_connection_thread_send(tc);
		tcp_connection_update_send_event_mask(tc, poll_fds);
	}

	if (poll_fds->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		tc->close_event_received = true;
	}

	if ((poll_fds->revents & POLLIN) || tc->recv_event_received_while_paused) {
		if (tc->recv_paused) {
			tc->recv_event_received_while_paused = true;
			tcp_connection_update_recv_event_mask(tc, poll_fds);
			return;
		}

		tc->recv_event_received_while_paused = false;
		tcp_connection_update_recv_event_mask(tc, poll_fds);
		tcp_connection_thread_recv(tc);
		return;
	}

	if (tc->close_event_received) {
		tc->dead = true;
		return;
	}
}

static void tcp_connection_thread_execute_est(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (poll_fds->revents & POLLOUT) {
		DEBUG_TRACE("connection established");
		tcp_manager.network_ok_indication = true;
		tc->established_timeout = 0;
		tcp_connection_update_send_event_mask(tc, poll_fds);
		tcp_connection_update_recv_event_mask(tc, poll_fds);

		if (tc->est_callback && !tc->app_closed) {
			thread_main_enter();
			tcp_connection_notify_established(tc);
			thread_main_exit();
		}

		tcp_connection_thread_execute_active(tc, poll_fds);
		return;
	}

	if (poll_fds->revents & (POLLERR | POLLHUP | POLLNVAL)) {
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

void tcp_connection_thread_execute(void *arg)
{
	while (1) {
		if (slist_get_head(struct tcp_connection, &tcp_manager.connection_new_list)) {
			spinlock_lock(&tcp_manager.connection_new_lock);
			tcp_connection_thread_new_connections();
			spinlock_unlock(&tcp_manager.connection_new_lock);
		}

		int ret = poll(tcp_manager.connection_poll_fds, (nfds_t)tcp_manager.connection_poll_count, 10);
		DEBUG_ASSERT(ret >= 0, "poll returned error");

		struct pollfd *poll_fds = tcp_manager.connection_poll_fds;
		if (poll_fds->revents) {
			uint8_t dummy[32];
			if (read(poll_fds->fd, dummy, sizeof(dummy)) < 0) {
				/* Nothing needs to be done on error */
			}
		}

		poll_fds++;

		struct tcp_connection **pprev = slist_get_phead(struct tcp_connection, &tcp_manager.connection_active_list);
		struct tcp_connection *tc = slist_get_head(struct tcp_connection, &tcp_manager.connection_active_list);
		while (tc) {
			DEBUG_ASSERT(tc->sock == poll_fds->fd, "list error");

			if (tc->dead) {
				if (!tc->close_callback) {
					tc->app_closed = true;
				}

				if (!tc->app_closed) {
					thread_main_enter();
					tcp_connection_notify_close(tc);
					thread_main_exit();
				}

				struct tcp_connection *discard = tc;
				tc = slist_get_next(struct tcp_connection, tc);

				tcp_connection_thread_delete_connection_from_poll_fds(poll_fds);
				(void)slist_detach_pprev(struct tcp_connection, pprev, discard);
				tcp_connection_deref(discard);
				continue;
			}

			if (tc->established_timeout > 0) {
				tcp_connection_thread_execute_est(tc, poll_fds);
			} else {
				tcp_connection_thread_execute_active(tc, poll_fds);
			}

			pprev = slist_get_pnext(struct tcp_connection, tc);
			tc = slist_get_next(struct tcp_connection, tc);
			poll_fds++;
		}
	}
}
