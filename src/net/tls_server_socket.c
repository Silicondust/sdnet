/*
 * tls_server_socket.c
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("tls_server_socket");

struct tls_server_socket_t {
	struct tcp_socket *sock;

	tls_server_connect_callback_t connect_callback;
	void *callback_arg;
};

void tls_server_socket_reject(struct tls_server_socket_t *tls_sock)
{
	tcp_socket_reject(tls_sock->sock);
}

void tls_server_socket_accept(struct tls_server_socket_t *tls_sock, struct tls_server_connection_t *tls_conn, tls_server_establish_callback_t est, tls_server_recv_callback_t recv, tls_server_close_callback_t close, void *callback_arg)
{
	//tls_server_connection_accept(tls_conn, tls_sock->sock, est, recv, close, callback_arg);
}

static void tls_server_socket_tcp_connect_callback(void *arg)
{
	struct tls_server_socket_t *tls_sock = (struct tls_server_socket_t *)arg;
	tls_sock->connect_callback(tls_sock->callback_arg);
}

uint16_t tls_server_socket_get_port(struct tls_server_socket_t *tls_sock)
{
	return tcp_socket_get_port(tls_sock->sock);
}

bool tls_server_socket_listen(struct tls_server_socket_t *tls_sock, ipv4_addr_t addr, uint16_t port, tls_server_connect_callback_t connect, void *callback_arg)
{
	tls_sock->connect_callback = connect;
	tls_sock->callback_arg = callback_arg;

	if (tcp_socket_listen(tls_sock->sock, addr, port, tls_server_socket_tcp_connect_callback, tls_sock) != TCP_OK) {
		return false;
	}

	return true;
}

struct tls_server_socket_t *tls_server_socket_alloc(void)
{
	struct tls_server_socket_t *tls_sock = (struct tls_server_socket_t *)heap_alloc_and_zero(sizeof(struct tls_server_socket_t), PKG_OS, MEM_TYPE_OS_TLS_SERVER_SOCKET);
	if (!tls_sock) {
		DEBUG_WARN("out of memory");
		return NULL;
	}

	tls_sock->sock = tcp_socket_alloc();
	if (!tls_sock->sock) {
		heap_free(tls_sock);
		return NULL;
	}

	return tls_sock;
}
