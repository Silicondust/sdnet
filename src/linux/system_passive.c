/*
 * ./src/linux/system_passive.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("system");

static volatile uint32_t signal_in_progress = 0;

static void system_signal_handler_ignore(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL %d --", signal);
}

static void system_signal_handler_fault(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL %d --", signal);
	if (signal_in_progress++) {
		return;
	}

	addr_t pc = arch_get_crash_pc(si, context_addr);
	addr_t sp = arch_get_crash_sp(si, context_addr);

	struct file_t *fp = file_open_create("fault.log");
	if (!fp) {
		return;
	}

	char buffer[20];

	sprintf_custom(buffer, buffer + sizeof(buffer), "0x%08x\n", SYSTEM_CRASH_DUMP_MAGIC);
	file_write(fp, buffer, strlen(buffer));

	sprintf_custom(buffer, buffer + sizeof(buffer), "%d\n", signal);
	file_write(fp, buffer, strlen(buffer));

	sprintf_custom(buffer, buffer + sizeof(buffer), "%p\n", pc);
	file_write(fp, buffer, strlen(buffer));

	while (1) {
		addr_t addr = arch_call_backtrace(&sp);
		if (addr == 0) {
			break;
		}

		sprintf_custom(buffer, buffer + sizeof(buffer), "%p\n", addr);
		file_write(fp, buffer, strlen(buffer));
	}

	file_close(fp);
}

static void system_signal_handler_init(void)
{
	const struct sigaction sigaction_ignore = { .sa_flags = SA_SIGINFO,.sa_sigaction = system_signal_handler_ignore };
	sigaction(SIGPIPE, &sigaction_ignore, NULL); /* sendfile can cause sigpipe which needs to be ignored */

	const struct sigaction sigaction_fault = { .sa_flags = SA_SIGINFO | SA_RESETHAND, .sa_sigaction = system_signal_handler_fault };
	sigaction(SIGSEGV, &sigaction_fault, NULL); /* Segfault */
	sigaction(SIGILL, &sigaction_fault, NULL); /* Illegal instruction. */
	sigaction(SIGALRM, &sigaction_fault, NULL); /* Application watchdog */

	struct rlimit core_limit;
	if (getrlimit(RLIMIT_NOFILE, &core_limit) >= 0) {
		core_limit.rlim_cur = RLIM64_INFINITY;
		core_limit.rlim_max = RLIM64_INFINITY;
		setrlimit(RLIMIT_CORE, &core_limit);
	}
}

void system_reset(void)
{
	flash_shutdown(NULL);
	exit(0);
}

void system_init(void)
{
	system_signal_handler_init();
}
