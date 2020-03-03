/*
 * mdns_responder.h
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct mdns_responder_t;

extern void mdns_responder_init(void);
extern bool mdns_responder_register_name(const char *name);
