/*
 * ./src/net/linux/tcp.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/sendfile.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("tcp");

void tcp_set_sock_nosigpipe(int sock)
{
	/* Linux rquires using MSG_NOSIGNAL on the send() call. */
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
		if (send_buffer_size != send_buffer_size_set * 2) {	/* Linux reports the buffer size to twice the requested value. */
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

	ssize_t ret = sendfile(tc->sock, file->fp, NULL, length);
	if (ret < 0) {
		if (errno == EAGAIN) {
			return TCP_ERROR_SOCKET_BUSY;
		}

		DEBUG_WARN("sendfile error %d", errno);
		return TCP_ERROR_FAILED;
	}

	if (ret == 0) {
		DEBUG_WARN("sendfile eof");
		return TCP_ERROR_FILE;
	}

	*pactual = (size_t)ret;
	return TCP_OK;
}
