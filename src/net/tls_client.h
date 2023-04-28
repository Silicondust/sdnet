/*
 * tls_client.h
 *
 * Copyright © 2015-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct tls_client_connection_t;

typedef void (*tls_client_establish_callback_t)(void *arg);
typedef void (*tls_client_recv_callback_t)(void *arg, struct netbuf *nb);
typedef void (*tls_client_close_callback_t)(void *arg, tcp_close_reason_t reason);

extern struct tls_client_connection_t *tls_client_connection_alloc(void);
extern struct tls_client_connection_t *tls_client_connection_ref(struct tls_client_connection_t *tls_conn);
extern int tls_client_connection_deref(struct tls_client_connection_t *tls_conn);
extern void tls_client_connection_close(struct tls_client_connection_t *tls_conn);
extern bool tls_client_connection_connect(struct tls_client_connection_t *tls_conn, const ip_addr_t *dest_addr, uint16_t dest_port, uint32_t ipv6_scope_id, const char *host_name, tls_client_establish_callback_t est, tls_client_recv_callback_t recv, tls_client_close_callback_t close, void *callback_arg);
extern bool tls_client_connection_send_netbuf(struct tls_client_connection_t *tls_conn, struct netbuf *nb);
extern void tls_client_connection_pause_recv(struct tls_client_connection_t *tls_conn);
extern void tls_client_connection_resume_recv(struct tls_client_connection_t *tls_conn);
extern bool tls_client_connection_can_send(struct tls_client_connection_t *tls_conn);
extern uint32_t tls_client_connection_get_local_addr(struct tls_client_connection_t *tls_conn, ip_addr_t *result);
extern uint32_t tls_client_connection_get_remote_addr(struct tls_client_connection_t *tls_conn, ip_addr_t *result);

extern void tls_client_init(void);
extern void tls_client_test(void);
extern void tls_client_set_client_cert_mem(uint8_t *cert_data, size_t cert_length, uint8_t *key_data, size_t key_length);
extern void tls_client_set_client_cert_appfs(const char *client_crt_appfs_filename, const char *client_key_appfs_filename);
