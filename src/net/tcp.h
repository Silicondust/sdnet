/*
 * tcp.h
 *
 * Copyright © 2007-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define TCP_OK 0
#define TCP_ERROR_FAILED -1
#define TCP_ERROR_SOCKET_BUSY -2
#define TCP_ERROR_FILE -3
#define TCP_TOS_VIDEO (5 << 5)

#define TCP_TYPICAL_SEND_LENGTH 7680

struct tcp_socket;
struct tcp_connection;
struct file_t;

typedef int8_t tcp_error_t;
typedef uint8_t tcp_close_reason_t;
typedef void (*tcp_accept_callback_t)(void *inst, const ip_addr_t *remote_addr, uint32_t ipv6_scope_id);
typedef void (*tcp_connect_callback_t)(void *inst);
typedef void (*tcp_establish_callback_t)(void *inst);
typedef void (*tcp_recv_callback_t)(void *inst, struct netbuf *nb);
typedef void (*tcp_close_callback_t)(void *inst, tcp_close_reason_t reason);

extern struct tcp_connection *tcp_connection_alloc(void);
extern struct tcp_connection *tcp_connection_ref(struct tcp_connection *tc);
extern int tcp_connection_deref(struct tcp_connection *tc);
extern void tcp_connection_reset(struct tcp_connection *tc);
extern void tcp_connection_close(struct tcp_connection *tc);
extern tcp_error_t tcp_connection_connect(struct tcp_connection *tc, const ip_addr_t *dest_addr, uint16_t dest_port, uint32_t ipv6_scope_id, tcp_establish_callback_t est_callback, tcp_recv_callback_t recv_callback, tcp_close_callback_t close_callback, void *inst);
extern tcp_error_t tcp_connection_send_netbuf(struct tcp_connection *tc, struct netbuf *nb);
extern tcp_error_t tcp_connection_send_file(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual);
extern void tcp_connection_pause_recv(struct tcp_connection *tc);
extern void tcp_connection_resume_recv(struct tcp_connection *tc);
extern tcp_error_t tcp_connection_can_send(struct tcp_connection *tc);
extern void tcp_connection_set_send_buffer_size(struct tcp_connection *tc, size_t send_buffer_size);
extern void tcp_connection_set_max_recv_nb_size(struct tcp_connection *tc, size_t recv_nb_size);
extern void tcp_connection_set_ttl(struct tcp_connection *tc, uint8_t ttl);
extern void tcp_connection_set_tos(struct tcp_connection *tc, uint8_t tos);
extern uint32_t tcp_connection_get_local_addr(struct tcp_connection *tc, ip_addr_t *result);
extern uint32_t tcp_connection_get_remote_addr(struct tcp_connection *tc, ip_addr_t *result);
extern uint16_t tcp_connection_get_remote_port(struct tcp_connection *tc);

extern struct tcp_socket *tcp_socket_alloc(ip_mode_t ip_mode);
extern tcp_error_t tcp_socket_listen(struct tcp_socket *ts, uint16_t port, tcp_accept_callback_t accept_callback, void *inst);
extern void tcp_socket_accept(struct tcp_socket *ts, struct tcp_connection *tc, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst);
extern void tcp_socket_reject(struct tcp_socket *ts);
extern uint16_t tcp_socket_get_port(struct tcp_socket *ts);

extern bool tcp_manager_get_network_ok_indication(void);
extern void tcp_manager_reset_network_ok_indication(void);

extern void tcp_manager_init(void);
extern void tcp_manager_start(void);
extern void tcp_manager_disable_sendfile(void);
