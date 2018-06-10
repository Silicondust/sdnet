/*
 * daemon.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <libutil.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("daemon");

static bool daemon_test_proc(struct kinfo_proc *proc, const char *expected_name_without_path)
{
	char *running_name_without_path = strrchr(proc->ki_comm, '/');
	if (running_name_without_path) {
		running_name_without_path++;
	} else {
		running_name_without_path = proc->ki_comm;
	}

	return (strncmp(running_name_without_path, expected_name_without_path, COMMLEN) == 0);
}

static uint8_t daemon_stop_pid(pid_t pid, ticks_t timeout)
{
	if (kill(pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			return DAEMON_NOT_RUNNING;
		}

		if (errno == EPERM) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	while (1) {
		timer_sleep_fast(FAST_TICK_RATE_MS * 50);

		if (kill(pid, SIGTERM) < 0) {
			return DAEMON_SUCCESS;
		}

		if (timer_get_ticks() >= timeout) {
			return DAEMON_FAILED;
		}
	}
}

static bool daemon_get_procs(struct kinfo_proc **pprocs, struct kinfo_proc **pend)
{
	int mib[4];
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_ALL;
	mib[3] = 0;

	size_t size = 0;
	if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) {
		return false;
	}

	struct kinfo_proc *procs = NULL;

	while (1) {
		size += sizeof(struct kinfo_proc);

		struct kinfo_proc *procs_new = (struct kinfo_proc *)realloc(procs, size);
		if (!procs_new) {
			break;
		}

		procs = procs_new;

		size_t size_prev = size;
		if (sysctl(mib, 3, procs, &size, NULL, 0) != 0) {
			if (errno != ENOMEM) {
				break;
			}
			if (size < size_prev) {
				break;
			}
			continue;
		}

		*pprocs = procs;
		*pend = procs + (size / sizeof(struct kinfo_proc));
		return true;
	}

	if (procs) {
		free(procs);
	}

	return false;
}

uint8_t daemon_status(const char *exe_name, const char *daemon_name)
{
	const char *expected_name_without_path = strrchr(exe_name, '/');
	if (expected_name_without_path) {
		expected_name_without_path++;
	} else {
		expected_name_without_path = exe_name;
	}

	pid_t self_pid = getpid();

	struct kinfo_proc *procs;
	struct kinfo_proc *end;
	if (!daemon_get_procs(&procs, &end)) {
		return DAEMON_FAILED;
	}

	struct kinfo_proc *proc = procs;
	while (proc < end) {
		if (proc->ki_pid == self_pid) {
			proc++;
			continue;
		}

		if (daemon_test_proc(proc, expected_name_without_path)) {
			free(procs);
			return DAEMON_RUNNING;
		}

		proc++;
	}

	free(procs);
	return DAEMON_NOT_RUNNING;
}

uint8_t daemon_stop(const char *exe_name, const char *daemon_name)
{
	const char *expected_name_without_path = strrchr(exe_name, '/');
	if (expected_name_without_path) {
		expected_name_without_path++;
	} else {
		expected_name_without_path = exe_name;
	}

	pid_t self_pid = getpid();

	struct kinfo_proc *procs;
	struct kinfo_proc *end;
	if (!daemon_get_procs(&procs, &end)) {
		return DAEMON_FAILED;
	}

	uint8_t result = DAEMON_NOT_RUNNING;
	ticks_t timeout = timer_get_ticks() + 5000;

	struct kinfo_proc *proc = procs;
	while (proc < end) {
		if (proc->ki_pid == self_pid) {
			proc++;
			continue;
		}

		if (daemon_test_proc(proc, expected_name_without_path)) {
			uint8_t new_result = daemon_stop_pid(proc->ki_pid, timeout);
			if (new_result != DAEMON_NOT_RUNNING) {
				result = new_result;
			}
		}

		proc++;
	}

	free(procs);
	return result;
}

uint8_t daemon_start(const char *exe_name, const char *daemon_name)
{
	uint8_t status = daemon_status(exe_name, daemon_name);
	if (status != DAEMON_NOT_RUNNING) {
		return status;
	}

	pid_t pid = fork();
	if (pid < 0) {
		return DAEMON_FAILED;
	}

	if (pid > 0) {
		return DAEMON_SUCCESS;
	}

	umask(0);
	setsid();

	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	return DAEMON_FORK_CHILD;
}
