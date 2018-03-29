/*
 * ./src/linux/os_app.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("os");

struct thread_signal_t *main_thread_signal;
struct mqueue_t *system_app_queue;

int os_main(int argc, char *argv[])
{
	/*
	 * Init.
	 */
	system_init();
	heap_manager_init();
	netbuf_manager_init();
	exe_args_init(argc, argv);

	flash_init();
	thread_manager_init();
	oneshot_manager_init();
	long_task_manager_init();
	ip_datalink_manager_init();
	igmp_manager_init();
	tcp_manager_init();
	udp_manager_init();
	dns_manager_init();
	crypto_test();

	main_thread_signal = thread_signal_alloc();
	system_app_queue = mqueue_alloc(1024, main_thread_signal);

	app_init();

	/*
	 * Start.
	 */
	thread_manager_start();

	app_start();

	long_task_manager_start();
	udp_manager_start();
	tcp_manager_start();
	oneshot_manager_start();

	heap_leaktrack_set_ignore_all();

	/*
	 * Run.
	 */
	thread_main_exit();

	while (1) {
		thread_suspend_wait_for_signal(main_thread_signal);

		mqueue_read_handler_func_t handler = mqueue_read_request(system_app_queue);
		if (!handler) {
			continue;
		}

		thread_main_enter();

		#if (RUNTIME_DEBUG)
		ticks_t start_time = timer_get_ticks();
		#endif

		handler();

		#if (RUNTIME_DEBUG)
		ticks_t duration = timer_get_ticks() - start_time;
		if (duration > 20) {
			DEBUG_WARN("long path took %ums", (unsigned int)duration);
		}
		#endif

		thread_main_exit();
	}
}

int main(int argc, char *argv[]) __attribute__((weak, alias("os_main")));
