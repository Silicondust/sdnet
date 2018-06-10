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

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("daemon");

uint8_t daemon_status(const char *exe_name, const char *daemon_name)
{
	return DAEMON_NOT_SUPPORTED;
}

uint8_t daemon_stop(const char *exe_name, const char *daemon_name)
{
	return DAEMON_NOT_SUPPORTED;
}

uint8_t daemon_start(const char *exe_name, const char *daemon_name)
{
	return DAEMON_NOT_SUPPORTED;
}
