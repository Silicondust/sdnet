/*
 * tcp.c
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

void tcp_set_sock_keepalive(int sock, int seconds)
{
}

tcp_error_t tcp_connection_send_file(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual)
{
	if (tcp_manager.disable_sendfile) {
		return tcp_connection_send_file_fallback(tc, file, length, pactual);
	}

	if (tc->app_closed) {
		return TCP_ERROR_FAILED;
	}
	if (tc->send_nb) {
		return TCP_ERROR_SOCKET_BUSY;
	}

	uint64_t file_position = file_get_pos(file, (uint64_t)-1);
	if (file_position == (uint64_t)-1) {
		DEBUG_WARN("file_get_pos failed");
		return TCP_ERROR_FAILED;
	}

#if defined(__APPLE__)
	off_t send_actual = length;
	int ret = sendfile(file->fp, tc->sock, file_position, &send_actual, NULL, 0);
#else
	off_t send_actual = 0;
	int ret = sendfile(file->fp, tc->sock, file_position, length, NULL, &send_actual, 0);
#endif

	if (send_actual == 0) {
		if (ret == 0) {
			DEBUG_WARN("sendfile eof");
			return TCP_ERROR_FILE;
		}

		if (errno == EAGAIN) {
			return TCP_ERROR_SOCKET_BUSY;
		}

		DEBUG_WARN("sendfile error %d", errno);
		return TCP_ERROR_FAILED;
	}

	if (!file_seek_advance(file, (uint64_t)send_actual)) {
		DEBUG_WARN("file_seek_advance failed");
		return TCP_ERROR_FAILED;
	}
	
	*pactual = (size_t)send_actual;
	return TCP_OK;
}
