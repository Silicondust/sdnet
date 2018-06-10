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
#include <sys/mman.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("daemon");

static bool daemon_test_pid(pid_t pid, const char *expected_name_without_path)
{
	if (pid <= 1) {
		return false;
	}

	char filename[128];
	sprintf_custom(filename, filename + sizeof(filename), "/proc/%u/cmdline", pid);

	FILE *cmdline_fp = fopen_utf8(filename, "r");
	if (!cmdline_fp) {
		return false;
	}

	char line[128];
	if (!fgets(line, sizeof(line), cmdline_fp)) {
		line[0] = 0;
	}

	fclose(cmdline_fp);

	char *running_name_without_path = strrchr(line, '/');
	if (running_name_without_path) {
		running_name_without_path++;
	} else {
		running_name_without_path = line;
	}

	return (strcmp(running_name_without_path, expected_name_without_path) == 0);
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

uint8_t daemon_status(const char *exe_name, const char *daemon_name)
{
	const char *expected_name_without_path = strrchr(exe_name, '/');
	if (expected_name_without_path) {
		expected_name_without_path++;
	} else {
		expected_name_without_path = exe_name;
	}

	pid_t self_pid = getpid();

	DIR *search_dir = opendir("/proc/");
	if (!search_dir) {
		return DAEMON_FAILED;
	}

	while (1) {
		struct dirent *search_result = readdir(search_dir);
		if (!search_result) {
			closedir(search_dir);
			return DAEMON_NOT_RUNNING;
		}

		char *end;
		pid_t pid = (pid_t)strtoull(search_result->d_name, &end, 10);
		if (*end != 0) {
			continue;
		}

		if (pid == self_pid) {
			continue;
		}

		if (daemon_test_pid(pid, expected_name_without_path)) {
			closedir(search_dir);
			return DAEMON_RUNNING;
		}
	}
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

	DIR *search_dir = opendir("/proc/");
	if (!search_dir) {
		return DAEMON_FAILED;
	}

	uint8_t result = DAEMON_NOT_RUNNING;
	ticks_t timeout = timer_get_ticks() + 5000;

	while (1) {
		struct dirent *search_result = readdir(search_dir);
		if (!search_result) {
			closedir(search_dir);
			return result;
		}

		char *end;
		pid_t pid = (pid_t)strtoull(search_result->d_name, &end, 10);
		if (*end != 0) {
			continue;
		}

		if (pid == self_pid) {
			continue;
		}

		if (daemon_test_pid(pid, expected_name_without_path)) {
			uint8_t new_result = daemon_stop_pid(pid, timeout);
			if (new_result != DAEMON_NOT_RUNNING) {
				result = new_result;
			}
		}
	}
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
