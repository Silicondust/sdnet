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
}

void tcp_manager_start(void)
{
	thread_start(tcp_socket_thread_execute, NULL);
	thread_start(tcp_connection_thread_execute, NULL);
}

void tcp_manager_init(void)
{
	spinlock_init(&tcp_manager.socket_new_lock, 0);
	spinlock_init(&tcp_manager.connection_new_lock, 0);

	tcp_manager.socket_poll_signal = CreateEvent(NULL, false, false, NULL);
	tcp_manager.socket_poll_handles = (HANDLE *)heap_alloc(sizeof(HANDLE), PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!tcp_manager.socket_poll_signal || !tcp_manager.socket_poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	*tcp_manager.socket_poll_handles = tcp_manager.socket_poll_signal;
	tcp_manager.socket_poll_count = 1;

	tcp_manager.connection_poll_signal = CreateEvent(NULL, false, false, NULL);
	tcp_manager.connection_poll_handles = (HANDLE *)heap_alloc(sizeof(HANDLE), PKG_OS, MEM_TYPE_OS_TCP_POLL);
	if (!tcp_manager.connection_poll_signal || !tcp_manager.connection_poll_handles) {
		DEBUG_ERROR("out of memory");
		return;
	}

	*tcp_manager.connection_poll_handles = tcp_manager.connection_poll_signal;
	tcp_manager.connection_poll_count = 1;
}
