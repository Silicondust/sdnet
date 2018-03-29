/*
 * ./src/net/libc/tcp_connection.c
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

void tcp_connection_trigger_poll(void)
{
	uint8_t v = 0;
	write(tcp_manager.connection_poll_trigger_fd, &v, 1);
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

	struct netbuf *send_nb = (struct netbuf *)tc->send_nb;
	if (send_nb) {
		netbuf_free(send_nb);
	}

	close(tc->sock);

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

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t actual = send(tc->sock, (char *)buffer, (int)length, MSG_NOSIGNAL);
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
		timer_sleep_fast(FAST_TICK_RATE_MS * 10);
		nb = netbuf_alloc_with_fwd_space(tc->max_recv_nb_size);
	}

	uint8_t *buffer = netbuf_get_ptr(nb);
	ssize_t length = recv(tc->sock, (char *)buffer, tc->max_recv_nb_size, 0);
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

tcp_error_t tcp_connection_connect(struct tcp_connection *tc, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint16_t src_port, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close_callback, void *inst)
{
	DEBUG_ASSERT(tc->sock == -1, "already connected");
	DEBUG_ASSERT(recv, "no recv callback specified");

	tc->est_callback = est;
	tc->recv_callback = recv;
	tc->send_resume_callback = send_resume;
	tc->close_callback = close_callback;
	tc->callback_inst = inst;

	int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
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
	int flag = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag)) < 0) {
		DEBUG_WARN("setsockopt TCP_NODELAY error %d", errno);
	}

	/* Configure socket not to generate pipe-error signal (BSD/OSX). */
	tcp_set_sock_nosigpipe(sock);

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

	errno = EAGAIN; /* workaround Abilis bug */
	if (connect(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
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
	tc->next = tcp_manager.connection_new_list;
	tcp_manager.connection_new_list = tc;
	spinlock_unlock(&tcp_manager.connection_new_lock);

	tcp_connection_trigger_poll();
	return TCP_OK;
}

void tcp_connection_accept(struct tcp_connection *tc, int sock, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst)
{
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
	struct pollfd *poll_fds = (struct pollfd *)heap_realloc(tcp_manager.connection_poll_fds, sizeof(struct pollfd) * total_count, PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	tcp_manager.connection_poll_fds = poll_fds;
	poll_fds += tcp_manager.connection_poll_count;

	struct tcp_connection **pprev = &tcp_manager.connection_active_list;
	struct tcp_connection *p = tcp_manager.connection_active_list;
	while (p) {
		pprev = &p->next;
		p = p->next;
	}

	while (tcp_manager.connection_new_list) {
		struct tcp_connection *tc = tcp_manager.connection_new_list;
		tcp_manager.connection_new_list = tc->next;
		tc->next = NULL;

		poll_fds->fd = tc->sock;
		poll_fds->events = POLLOUT;
		poll_fds->revents = 0;
		poll_fds++;

		*pprev = tc;
		pprev = &tc->next;
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

static void tcp_connection_thread_execute_est(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (poll_fds->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		DEBUG_INFO("connection failed");
		tc->dead = true;
		return;
	}

	if (poll_fds->revents & POLLOUT) {
		DEBUG_INFO("connection established");
		tcp_manager.network_ok_indication = true;
		tc->established_timeout = 0;
		poll_fds->events = POLLIN;

		if (tc->est_callback && !tc->app_closed) {
			thread_main_enter();
			tcp_connection_notify_established(tc);
			thread_main_exit();
		}

		return;
	}

	if (timer_get_ticks() >= tc->established_timeout) {
		DEBUG_INFO("connection timeout");
		tc->dead = true;
		return;
	}
}

static void tcp_connection_thread_execute_active(struct tcp_connection *tc, struct pollfd *poll_fds)
{
	if (poll_fds->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		tc->close_event_received = true;
	}

	if (tc->close_event_received) {
		if (poll_fds->revents & POLLIN) {
			tcp_connection_thread_recv(tc);
			return;
		}

		tc->dead = true;
		return;
	}

	if (poll_fds->revents & POLLIN) {
		tcp_connection_thread_recv(tc);
	}

	if (tc->send_nb) {
		tcp_connection_thread_send(tc);
		if (tc->send_nb) {
			poll_fds->events = POLLIN | POLLOUT;
		} else {
			poll_fds->events = POLLIN;
		}
	}
}

void tcp_connection_thread_execute(void *arg)
{
	while (1) {
		if (tcp_manager.connection_new_list) {
			spinlock_lock(&tcp_manager.connection_new_lock);
			tcp_connection_thread_new_connections();
			spinlock_unlock(&tcp_manager.connection_new_lock);
		}

		int ret = poll(tcp_manager.connection_poll_fds, (nfds_t)tcp_manager.connection_poll_count, 10);
		DEBUG_ASSERT(ret >= 0, "poll returned error");

		struct pollfd *poll_fds = tcp_manager.connection_poll_fds;
		if (poll_fds->revents) {
			uint8_t dummy[32];
			read(poll_fds->fd, dummy, sizeof(dummy));
		}

		poll_fds++;

		struct tcp_connection **pprev = &tcp_manager.connection_active_list;
		struct tcp_connection *tc = tcp_manager.connection_active_list;
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

				tcp_connection_thread_delete_connection_from_poll_fds(poll_fds);
				*pprev = tc->next;
				tcp_connection_deref(tc);
				tc = *pprev;
				continue;
			}

			if (tc->established_timeout > 0) {
				tcp_connection_thread_execute_est(tc, poll_fds);
			} else {
				tcp_connection_thread_execute_active(tc, poll_fds);
			}

			pprev = &tc->next;
			tc = tc->next;
			poll_fds++;
		}
	}
}
