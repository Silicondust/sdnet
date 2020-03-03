/*
 * tls_server.h
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct tls_server_socket_t;
struct tls_server_connection_t;

typedef void (*tls_server_connect_callback_t)(void *arg);
typedef void (*tls_server_establish_callback_t)(void *arg);
typedef void (*tls_server_recv_callback_t)(void *arg, struct netbuf *nb);
typedef void (*tls_server_send_resume_callback_t)(void *arg);
typedef void (*tls_server_close_callback_t)(void *arg, tcp_close_reason_t reason);

extern struct tls_server_connection_t *tls_server_connection_alloc(void);
extern struct tls_server_connection_t *tls_server_connection_ref(struct tls_server_connection_t *tls_conn);
extern int tls_server_connection_deref(struct tls_server_connection_t *tls_conn);
extern void tls_server_connection_close(struct tls_server_connection_t *tls_conn);
extern bool tls_server_connection_send_netbuf(struct tls_server_connection_t *tls_conn, struct netbuf *nb);
extern void tls_server_connection_pause_recv(struct tls_server_connection_t *tls_conn);
extern void tls_server_connection_resume_recv(struct tls_server_connection_t *tls_conn);
extern bool tls_server_connection_can_send(struct tls_server_connection_t *tls_conn);
extern ipv4_addr_t tls_server_connection_get_local_addr(struct tls_server_connection_t *tls_conn);
extern ipv4_addr_t tls_server_connection_get_remote_addr(struct tls_server_connection_t *tls_conn);

extern struct tls_server_socket_t *tls_server_socket_alloc(void);
extern bool tls_server_socket_listen(struct tls_server_socket_t *tls_sock, ipv4_addr_t addr, uint16_t port, tls_server_connect_callback_t connect, void *callback_arg);
extern void tls_server_socket_accept(struct tls_server_socket_t *tls_sock, struct tls_server_connection_t *tls_conn, tls_server_establish_callback_t est, tls_server_recv_callback_t recv, tls_server_send_resume_callback_t send_resume, tls_server_close_callback_t close, void *callback_arg);
extern void tls_server_socket_reject(struct tls_server_socket_t *tls_sock);
extern uint16_t tls_server_socket_get_port(struct tls_server_socket_t *tls_sock);

/* Internal */
extern void tls_server_connection_accept(struct tls_server_connection_t *tls_conn, struct tcp_socket *sock, tls_server_establish_callback_t est, tls_server_recv_callback_t recv, tls_server_send_resume_callback_t send_resume, tls_server_close_callback_t close, void *callback_arg);
