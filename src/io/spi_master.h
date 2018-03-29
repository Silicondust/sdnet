/*
 * ./src/io/spi_master.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct spi_master_instance;

extern struct spi_master_instance *spi_master_instance_alloc(unsigned int spi_bus_index);
extern bool spi_master_send_recv(struct spi_master_instance *spi, uint8_t *send_recv_buffer, size_t send_recv_length);
extern bool spi_master_send_only(struct spi_master_instance *spi, uint8_t *send_buffer, size_t send_length);
extern bool spi_master_send_then_recv(struct spi_master_instance *spi, uint8_t *send_buffer, size_t send_length, uint8_t *recv_buffer, size_t recv_length);
