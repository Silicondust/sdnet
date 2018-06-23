/*
 * tls_client_connection.h
 *
 * Copyright © 2015-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct tls_client_connection_t;

typedef void (*tls_client_connection_establish_callback_t)(void *inst);
typedef void (*tls_client_connection_recv_callback_t)(void *inst, struct netbuf *nb);
typedef void (*tls_client_connection_send_resume_callback_t)(void *inst);
typedef void (*tls_client_connection_close_callback_t)(void *inst, tcp_close_reason_t reason);

extern struct tls_client_connection_t *tls_client_connection_alloc(void);
extern struct tls_client_connection_t *tls_client_connection_ref(struct tls_client_connection_t *tls_conn);
extern int tls_client_connection_deref(struct tls_client_connection_t *tls_conn);
extern void tls_client_connection_close(struct tls_client_connection_t *tls_conn);
extern bool tls_client_connection_connect(struct tls_client_connection_t *tls_conn, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint16_t src_port, const char *host_name, tls_client_connection_establish_callback_t est, tls_client_connection_recv_callback_t recv, tls_client_connection_send_resume_callback_t send_resume, tls_client_connection_close_callback_t close, void *callback_arg);
extern bool tls_client_connection_send_netbuf(struct tls_client_connection_t *tls_conn, struct netbuf *nb);
extern void tls_client_connection_pause_recv(struct tls_client_connection_t *tls_conn);
extern void tls_client_connection_resume_recv(struct tls_client_connection_t *tls_conn);
extern bool tls_client_connection_can_send(struct tls_client_connection_t *tls_conn);
extern void tls_client_connection_set_max_recv_nb_size(struct tls_client_connection_t *tls_conn, size_t recv_nb_size);
extern ipv4_addr_t tls_client_connection_get_local_addr(struct tls_client_connection_t *tls_conn);
extern ipv4_addr_t tls_client_connection_get_remote_addr(struct tls_client_connection_t *tls_conn);

extern void tls_client_init(void);
extern void tls_client_test(void);
