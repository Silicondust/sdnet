/*
 * system_managed.c
 *
 * Copyright © 2012-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <linux/capability.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("system_managed");

#if !defined(SYSTEM_CAPSET_ADDITIONAL)
#define SYSTEM_CAPSET_ADDITIONAL 0
#endif

extern int capset(cap_user_header_t, const cap_user_data_t);

static volatile uint32_t signal_in_progress = 0;

static void system_signal_handler_ignore(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL %d --", signal);
}

static void system_signal_handler_quit(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL SIGQUIT --");
	if (signal_in_progress++) {
		return;
	}

	file_sync_all();
	flash_shutdown(NULL);

	if (RUNTIME_DEBUG) {
		sleep(1);
	}

	reboot(RB_AUTOBOOT);
	DEBUG_ASSERT(0, "reboot failed");
}

static void system_signal_handler_fault(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL %d --", signal);
	if (signal_in_progress++) {
		return;
	}

	struct system_crash_dump_t crash_dump;
	memset(&crash_dump, 0xFF, sizeof(struct system_crash_dump_t));

	uint32_t *data = crash_dump.data;
	data[0] = SYSTEM_CRASH_DUMP_MAGIC;
	data[1] = (uint32_t)signal;
	data[2] = (uint32_t)arch_get_crash_pc(si, context_addr);

	addr_t sp = arch_get_crash_sp(si, context_addr);
	size_t index = 3;
	while (index < 16) {
		addr_t addr = arch_call_backtrace(&sp);
		if (addr == 0) {
			break;
		}
		data[index++] = (uint32_t)addr;
	}

	DEBUG_ERROR("%08X %08X %08X %08X %08X %08X %08X %08X", data[0], data[1], data[2],  data[3],  data[4],  data[5],  data[6],  data[7]);
	DEBUG_ERROR("%08X %08X %08X %08X %08X %08X %08X %08X", data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);

	file_sync_all();
	flash_shutdown(&crash_dump);

	if (RUNTIME_DEBUG) {
		sleep(1);
	}

	reboot(RB_AUTOBOOT);
	DEBUG_ASSERT(0, "reboot failed");
}

static void system_signal_handler_init(void)
{
	const struct sigaction sigaction_ignore = { .sa_flags = SA_SIGINFO, .sa_sigaction = system_signal_handler_ignore };
	sigaction(SIGTRAP, &sigaction_ignore, NULL);
	sigaction(SIGABRT, &sigaction_ignore, NULL);
	sigaction(SIGBUS, &sigaction_ignore, NULL);
	sigaction(SIGFPE, &sigaction_ignore, NULL);
	sigaction(SIGPIPE, &sigaction_ignore, NULL);

	const struct sigaction sigaction_quit = { .sa_flags = SA_SIGINFO, .sa_sigaction = system_signal_handler_quit };
	sigaction(SIGQUIT, &sigaction_quit, NULL); /* Reboot requested */

	const struct sigaction sigaction_fault = { .sa_flags = SA_SIGINFO, .sa_sigaction = system_signal_handler_fault };
	sigaction(SIGSEGV, &sigaction_fault, NULL); /* Segfault */
	sigaction(SIGILL, &sigaction_fault, NULL); /* Illegal instruction. */
	sigaction(SIGALRM, &sigaction_fault, NULL); /* Application watchdog */
}

void system_drop_root(void)
{
	int status = 0;

#if 0
	/* Keep the current capabilities after setuid/setgid
	 * then drop the root uid/gid
	 */
	status |= prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	status |= setgid(-1);
	status |= setuid(-1);
#endif

	/* Restrict the capabilities
	 * (see man 7 capabilities)
	 */
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct cap;

	header.version = _LINUX_CAPABILITY_VERSION;
	header.pid = 0;
	cap.permitted = SYSTEM_CAPSET_ADDITIONAL | (1 << CAP_SYS_BOOT) | (1 << CAP_SYS_TIME) | (1 << CAP_SYS_RAWIO) | (1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW) | (1 << CAP_NET_BROADCAST);
	cap.effective = cap.permitted; 
	cap.inheritable = 0;
	status |= capset(&header, &cap);

	if (status != 0) {
		DEBUG_ERROR("system_drop_root failed");
	}
}

void system_reset(void)
{
	DEBUG_WARN("Sending reboot");
	kill(getpid(), SIGQUIT);

	while (1) {
		thread_yield();
	}
}

static void system_custom_init_default(void)
{
}

void system_custom_init(void) __attribute__((weak, alias("system_custom_init_default")));

void system_init(void)
{
	system_custom_init();
	system_signal_handler_init();
}
