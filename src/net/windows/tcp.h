/*
 * tcp.h
 *
 * Copyright © 2007-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct tcp_connection;
struct tcp_socket;

struct tcp_manager_t {
	struct slist_t socket_active_list;
	struct slist_t socket_new_list;
	struct spinlock socket_new_lock;
	HANDLE *socket_poll_handles;
	size_t socket_poll_count;
	HANDLE socket_poll_signal;

	struct slist_t connection_active_list;
	struct slist_t connection_new_list;
	struct spinlock connection_new_lock;
	HANDLE *connection_poll_handles;
	size_t connection_poll_count;
	HANDLE connection_poll_signal;

	bool network_ok_indication;
};

extern struct tcp_manager_t tcp_manager;

extern void tcp_socket_thread_execute(void *arg);
extern void tcp_connection_thread_execute(void *arg);

extern void tcp_connection_accept(struct tcp_connection *tc, int sock, tcp_establish_callback_t est, tcp_recv_callback_t recv, tcp_send_resume_callback_t send_resume, tcp_close_callback_t close, void *inst);
