/*
 * dns_responder.h
 *
 * Copyright © 2020-2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct dns_responder_t;

extern void dns_responder_init(void);
extern bool dns_responder_register_name(const char *name);
