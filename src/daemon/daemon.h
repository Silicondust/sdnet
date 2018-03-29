/*
 * ./src/daemon/daemon.h
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define DAEMON_SUCCESS 0
#define DAEMON_RUNNING 1
#define DAEMON_NOT_RUNNING 2
#define DAEMON_NOT_SUPPORTED 3
#define DAEMON_ACCESS_DENIED 4
#define DAEMON_FAILED 5
#define DAEMON_FORK_CHILD 6

extern uint8_t daemon_start(const char *exe_name, const char *daemon_name);
extern uint8_t daemon_stop(const char *exe_name, const char *daemon_name);
extern uint8_t daemon_status(const char *exe_name, const char *daemon_name);
