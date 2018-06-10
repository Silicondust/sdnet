/*
 * daemon.c
 *
 * Copyright © 2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/wait.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("daemon");

static pid_t daemon_pid = 0;

uint8_t daemon_status(const char *exe_name, const char *daemon_name)
{
	if (daemon_pid <= 0) {
		return DAEMON_NOT_RUNNING;
	}

	if (kill(daemon_pid, 0) < 0) {
		return DAEMON_NOT_RUNNING;
	}

	return DAEMON_RUNNING;
}

uint8_t daemon_stop(const char *exe_name, const char *daemon_name)
{
	if (daemon_pid <= 0) {
		return DAEMON_NOT_RUNNING;
	}

	if (kill(daemon_pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			return DAEMON_NOT_RUNNING;
		}

		if (errno == EPERM) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	ticks_t timeout = timer_get_ticks() + 5000;

	while (1) {
		waitpid(daemon_pid, NULL, WNOHANG);

		timer_sleep_fast(FAST_TICK_RATE_MS * 50);

		if (kill(daemon_pid, SIGTERM) < 0) {
			return DAEMON_SUCCESS;
		}

		if (timer_get_ticks() >= timeout) {
			return DAEMON_FAILED;
		}
	}
}

uint8_t daemon_start(const char *exe_name, const char *daemon_name)
{
	if (daemon_status(exe_name, daemon_name) == DAEMON_RUNNING) {
		return DAEMON_RUNNING;
	}

	daemon_pid = fork();
	if (daemon_pid < 0) {
		return DAEMON_FAILED;
	}

	if (daemon_pid > 0) {
		return DAEMON_SUCCESS;
	}

	umask(0);
	setsid();

	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	return DAEMON_FORK_CHILD;
}
