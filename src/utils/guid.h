/*
 * ./src/utils/guid.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct guid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq_hi_and_reserved;
	uint8_t clock_seq_low;
	uint8_t node[6];
};

extern void guid_create_random(struct guid *guid);
extern void guid_create_ubicom(struct guid *guid, uint8_t mac_addr[6], uint8_t sequence);
extern bool guid_read_string(struct guid *guid, const char *str);
extern bool guid_read_netbuf(struct guid *guid, struct netbuf *nb);
extern void guid_write_string(struct guid *guid, char *str);
extern void guid_write_string_upper(struct guid *guid, char *str);
