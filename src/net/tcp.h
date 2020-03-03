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

struct tcp_addr_port_t {
	ipv4_addr_t addr;
	uint16_t port;
};

typedef int8_t tcp_error_t;
typedef uint8_t tcp_close_reason_t;
typedef void (*tcp_connect_callback_t)(void *inst);
typedef void (*tcp_establish_callback_t)(void *inst);
typedef void (*tcp_recv_callback_t)(void *inst, struct netbuf *nb);
typedef void (*tcp_send_resume_callback_t)(void *inst);
typedef void (*tcp_close_callback_t)(void *inst, tcp_close_reason_t reason);

static inline bool tcp_addr_port_compare(struct tcp_addr_port_t *a, struct tcp_addr_port_t *b)
{
	return (a->addr == b->addr) && (a->port == b->port);
}

extern struct tcp_connection *tcp_connection_alloc(void);
extern struct tcp_connection *tcp_connection_ref(struct tcp_connection *tc);
extern int tcp_connection_deref(struct tcp_connection *tc);
extern void tcp_connection_reset(struct tcp_connection *tc);
extern void tcp_connection_close(struct tcp_connection *tc);
extern tcp_error_t tcp_connection_connect(struct tcp_connection *tc, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint16_t src_port, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst);
extern tcp_error_t tcp_connection_send_netbuf(struct tcp_connection *tc, struct netbuf *nb);
extern tcp_error_t tcp_connection_send_file(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual);
extern void tcp_connection_pause_recv(struct tcp_connection *tc);
extern void tcp_connection_resume_recv(struct tcp_connection *tc);
extern tcp_error_t tcp_connection_can_send(struct tcp_connection *tc);
extern void tcp_connection_set_max_recv_nb_size(struct tcp_connection *tc, size_t recv_nb_size);
extern void tcp_connection_set_ttl(struct tcp_connection *tc, uint8_t ttl);
extern void tcp_connection_set_tos(struct tcp_connection *tc, uint8_t tos);
extern ipv4_addr_t tcp_connection_get_local_addr(struct tcp_connection *tc);
extern ipv4_addr_t tcp_connection_get_remote_addr(struct tcp_connection *tc);
extern uint16_t tcp_connection_get_remote_port(struct tcp_connection *tc);

extern struct tcp_socket *tcp_socket_alloc(void);
extern tcp_error_t tcp_socket_listen(struct tcp_socket *ts, ipv4_addr_t addr, uint16_t port, tcp_connect_callback_t connect, void *inst);
extern void tcp_socket_accept(struct tcp_socket *ts, struct tcp_connection *tc, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst);
extern void tcp_socket_reject(struct tcp_socket *ts);
extern uint16_t tcp_socket_get_port(struct tcp_socket *ts);

extern bool tcp_manager_get_network_ok_indication(void);
extern void tcp_manager_reset_network_ok_indication(void);

extern void tcp_manager_init(void);
extern void tcp_manager_start(void);
