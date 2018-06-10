/*
 * i2c_master.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct i2c_master_instance;

extern struct i2c_master_instance *i2c_master_instance_alloc(unsigned int i2c_bus_index);
extern bool i2c_master_send_recv(struct i2c_master_instance *i2c, uint8_t device, uint8_t *send, size_t send_length, uint8_t *recv, size_t recv_length);
