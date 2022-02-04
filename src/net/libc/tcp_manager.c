/*
 * tcp_manager.c
 *
 * Copyright © 2007-2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("tcp_manager");

struct tcp_manager_t tcp_manager;

bool tcp_manager_get_network_ok_indication(void)
{
	return tcp_manager.network_ok_indication;
}

void tcp_manager_reset_network_ok_indication(void)
{
	tcp_manager.network_ok_indication = false;
}

void tcp_manager_disable_sendfile(void)
{
	tcp_manager.disable_sendfile = true;
}

void tcp_manager_start(void)
{
	thread_start(tcp_socket_thread_execute, NULL);
	thread_start(tcp_connection_thread_execute, NULL);
}

void tcp_manager_init(void)
{
	/*
	 * Init socket handling.
	 */
	spinlock_init(&tcp_manager.socket_new_lock, 0);

	tcp_manager.socket_poll_fds = (struct pollfd *)heap_alloc(sizeof(struct pollfd), PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!tcp_manager.socket_poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	int socket_poll_trigger_fds[2];
	if (pipe(socket_poll_trigger_fds) < 0) {
		DEBUG_ERROR("pipe create failed");
		return;
	}

	fcntl(socket_poll_trigger_fds[0], F_SETFL, O_NONBLOCK);
	fcntl(socket_poll_trigger_fds[1], F_SETFL, O_NONBLOCK);

	struct pollfd *poll_fds = tcp_manager.socket_poll_fds;
	poll_fds->fd = socket_poll_trigger_fds[0];
	poll_fds->events = POLLIN;
	poll_fds->revents = 0;

	tcp_manager.socket_poll_count = 1;
	tcp_manager.socket_poll_trigger_fd = socket_poll_trigger_fds[1];

	/*
	 * Init connection handling.
	 */
	spinlock_init(&tcp_manager.connection_new_lock, 0);

	tcp_manager.connection_poll_fds = (struct pollfd *)heap_alloc(sizeof(struct pollfd), PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!tcp_manager.connection_poll_fds) {
		DEBUG_ERROR("out of memory");
		return;
	}

	int connection_poll_trigger_fds[2];
	if (pipe(connection_poll_trigger_fds) < 0) {
		DEBUG_ERROR("pipe create failed");
		return;
	}

	fcntl(connection_poll_trigger_fds[0], F_SETFL, O_NONBLOCK);
	fcntl(connection_poll_trigger_fds[1], F_SETFL, O_NONBLOCK);

	poll_fds = tcp_manager.connection_poll_fds;
	poll_fds->fd = connection_poll_trigger_fds[0];
	poll_fds->events = POLLIN;
	poll_fds->revents = 0;

	tcp_manager.connection_poll_count = 1;
	tcp_manager.connection_poll_trigger_fd = connection_poll_trigger_fds[1];
}
