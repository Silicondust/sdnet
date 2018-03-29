/*
 * ./src/io/linux/i2c_master.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <linux/i2c-dev.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("i2c_master");

struct i2c_master_instance
{
	int dev_fp;
	uint8_t last_device;
};

struct i2c_master_instance *i2c_master_instance_alloc(unsigned int i2c_bus_index)
{
	struct i2c_master_instance *i2c = (struct i2c_master_instance *)heap_alloc_and_zero(sizeof(struct i2c_master_instance), PKG_OS, MEM_TYPE_OS_I2C);
	if (!i2c) {
		return NULL;
	}

	char dev_name[16];
	sprintf(dev_name, "/dev/i2c-%u", i2c_bus_index);

	i2c->dev_fp = open(dev_name, O_RDWR);
	if (i2c->dev_fp < 0) {
		DEBUG_ERROR("failed to open %s", dev_name);
		heap_free(i2c);
		return NULL;
	}

	return i2c;
}

bool i2c_master_send_recv(struct i2c_master_instance *i2c, uint8_t device, uint8_t *send, size_t send_length, uint8_t *recv, size_t recv_length)
{
	if (i2c->last_device != device) {
		if (ioctl(i2c->dev_fp, I2C_SLAVE, device >> 1) < 0) {
			DEBUG_ERROR("i2c ioctl failed: err %d", errno);
			return false;
		}

		i2c->last_device = device;
	}

	if (send_length > 0) {
		int ret = write(i2c->dev_fp, send, send_length);
		if (ret != send_length) {
			DEBUG_ERROR("i2c write failed: err %d (%d != %d)", errno, ret, send_length);
			return false;
		}
	}

	if (recv_length > 0) {
		int ret = read(i2c->dev_fp, recv, recv_length);
		if (ret != recv_length) {
			DEBUG_ERROR("i2c recv failed: err %d (%d != %d)", errno, ret, recv_length);
			return false;
		}
	}

	return true;
}
