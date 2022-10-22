/*
 * ntp_server.h
 *
 * Copyright © 202 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct ntp_server_t;

extern void ntp_server_init(void);
extern bool ntp_server_register_name(const char *name);
