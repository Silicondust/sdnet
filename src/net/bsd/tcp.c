/*
 * ./src/net/bsd/tcp.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("tcp");

void tcp_set_sock_nosigpipe(int sock)
{
	int set = 1;
	setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (char *)&set, sizeof(set));
}

void tcp_set_sock_send_buffer_size(int sock, size_t size)
{
	int send_buffer_size_set = (int)size;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size_set, (int)sizeof(send_buffer_size_set)) < 0) {
		DEBUG_WARN("setsockopt SO_SNDBUF error %d", errno);
	}

	if (RUNTIME_DEBUG) {
		int send_buffer_size = 0;
		socklen_t send_buffer_size_sizeof = sizeof(send_buffer_size);
		getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&send_buffer_size, &send_buffer_size_sizeof);
		if (send_buffer_size != send_buffer_size_set) {
			DEBUG_ERROR("failed to set send buffer size to %d (actual = %d)", send_buffer_size_set, send_buffer_size);
		}
	}
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

	errno = EAGAIN; /* workaround Abilis bug */
	ssize_t send_actual = send(tc->sock, (char *)buffer, (int)read_actual, 0);
	if (send_actual < (ssize_t)read_actual) {
		if (send_actual <= 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
				DEBUG_INFO("tcp send failed (%d %d)", (int)send_actual, errno);
				return TCP_ERROR_FAILED;
			}
			send_actual = 0;
		}

		netbuf_set_end(txnb, netbuf_get_pos(txnb) + read_actual);
		netbuf_advance_pos(txnb, (size_t)send_actual);
		netbuf_set_start_to_pos(txnb);

		tc->send_nb = txnb; /* Atomic update of volatile variable. */
		tcp_connection_trigger_poll();

		*pactual = read_actual;
		return TCP_OK;
	}

	netbuf_free(txnb);
	*pactual = read_actual;
	return TCP_OK;
}
