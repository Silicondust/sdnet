/*
 * system_android.c
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

static void system_signal_handler_ignore(int signal, siginfo_t *si, void *context_addr)
{
	DEBUG_ERROR("-- SIGNAL %d --", signal);
}

static void system_signal_handler_init(void)
{
	const struct sigaction sigaction_ignore = { .sa_flags = SA_SIGINFO,.sa_sigaction = system_signal_handler_ignore };
	sigaction(SIGPIPE, &sigaction_ignore, NULL); /* sendfile can cause sigpipe which needs to be ignored */
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
