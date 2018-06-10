/*
 * spi_master.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <linux/spi/spidev.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("spi_master");

struct spi_master_instance
{
	int dev_fp;
};

struct spi_master_instance *spi_master_instance_alloc(unsigned int spi_bus_index)
{
	struct spi_master_instance *spi = (struct spi_master_instance *)heap_alloc_and_zero(sizeof(struct spi_master_instance), PKG_OS, MEM_TYPE_OS_SPI);
	if (!spi) {
		return NULL;
	}

	char dev_name[16];
	sprintf(dev_name, "/dev/spidev0.%u", spi_bus_index);

	spi->dev_fp = open(dev_name, O_RDWR);
	if (spi->dev_fp < 0) {
		DEBUG_ERROR("failed to open %s", dev_name);
		heap_free(spi);
		return NULL;
	}

	return spi;
}

bool spi_master_send_recv(struct spi_master_instance *spi, uint8_t *send_recv_buffer, size_t send_recv_length)
{
	struct spi_ioc_transfer xfer[1];
	memset(xfer, 0, sizeof(xfer));
	xfer[0].tx_buf = (unsigned long)send_recv_buffer;
	xfer[0].rx_buf = (unsigned long)send_recv_buffer;
	xfer[0].len = send_recv_length;

	if (ioctl(spi->dev_fp, SPI_IOC_MESSAGE(1), xfer) < 0) {
		DEBUG_ERROR("spi_master_send_recv failed (%d)", errno);
		return false;
	}

	return true;
}

bool spi_master_send_only(struct spi_master_instance *spi, uint8_t *send_buffer, size_t send_length)
{
	struct spi_ioc_transfer xfer[1];
	memset(xfer, 0, sizeof(xfer));
	xfer[0].tx_buf = (unsigned long)send_buffer;
	xfer[0].len = send_length;

	if (ioctl(spi->dev_fp, SPI_IOC_MESSAGE(1), xfer) < 0) {
		DEBUG_ERROR("spi_master_send_only failed (%d)", errno);
		return false;
	}

	return true;
}

bool spi_master_send_then_recv(struct spi_master_instance *spi, uint8_t *send_buffer, size_t send_length, uint8_t *recv_buffer, size_t recv_length)
{
	struct spi_ioc_transfer xfer[2];
	memset(xfer, 0, sizeof(xfer));
	xfer[0].tx_buf = (unsigned long)send_buffer;
	xfer[0].len = send_length;
	xfer[1].rx_buf = (unsigned long)recv_buffer;
	xfer[1].len = recv_length;

	if (ioctl(spi->dev_fp, SPI_IOC_MESSAGE(2), xfer) < 0) {
		DEBUG_ERROR("spi_master_send_then_recv failed (%d)", errno);
		return false;
	}

	return true;
}
