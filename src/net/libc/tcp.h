/*
 * tcp.h
 *
 * Copyright © 2007-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define TCP_MAX_RECV_NB_SIZE_DEFAULT (3 * 1024)
#define TCP_SEND_BUFFER_SIZE_DEFAULT (128 * 1024)
#define TCP_ESTABLISHED_TIMEOUT (TICK_RATE * 5)

struct tcp_connection;
struct tcp_socket;

struct tcp_connection {
	struct slist_prefix_t slist_prefix;
	int refs;
	int sock;
	ip_mode_t ip_mode;
	uint8_t ttl;
	uint8_t tos;
	bool recv_event_received_while_paused;
	bool close_event_received;
	bool close_after_sending;
	bool app_closed;
	volatile bool dead;
	volatile bool recv_paused;
	volatile struct netbuf *send_nb;
	size_t max_recv_nb_size;
	size_t send_buffer_size;
	ticks_t established_timeout;
	uint8_t *sendfile_buffer;
	size_t sendfile_buffer_size;

	tcp_establish_callback_t est_callback;
	tcp_recv_callback_t recv_callback;
	tcp_close_callback_t close_callback;
	void *callback_inst;
};

struct tcp_manager_t {
	struct slist_t socket_active_list;
	struct slist_t socket_new_list;
	struct spinlock socket_new_lock;
	struct pollfd *socket_poll_fds;
	size_t socket_poll_count;
	int socket_poll_trigger_fd;

	struct slist_t connection_active_list;
	struct slist_t connection_new_list;
	struct spinlock connection_new_lock;
	struct pollfd *connection_poll_fds;
	size_t connection_poll_count;
	int connection_poll_trigger_fd;

	bool network_ok_indication;
	bool disable_sendfile;
};

extern struct tcp_manager_t tcp_manager;

extern void tcp_socket_thread_execute(void *arg);
extern void tcp_connection_thread_execute(void *arg);
extern void tcp_connection_accept(struct tcp_connection *tc, int sock, ip_mode_t ip_mode, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_close_callback_t close, void *inst);
extern void tcp_connection_trigger_poll(void);
extern void tcp_set_sock_nosigpipe(int sock);
extern void tcp_set_sock_send_buffer_size(int sock, size_t size);
extern void tcp_set_sock_keepalive(int sock, int seconds);

extern tcp_error_t tcp_connection_send_file_fallback(struct tcp_connection *tc, struct file_t *file, size_t length, size_t *pactual);
