/*
 * ./src/io/gpio_dummy.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("gpio");

void gpio_init(void)
{
}

void gpio_pin_init(uint32_t port, uint8_t pin)
{
}

bool gpio_pin_read(uint32_t port, uint8_t pin)
{
	return 0;
}

void gpio_pin_write_high(uint32_t port, uint8_t pin)
{
}

void gpio_pin_write_low(uint32_t port, uint8_t pin)
{
}

void gpio_pin_write_xor(uint32_t port, uint8_t pin)
{
}

void gpio_pin_dir_input(uint32_t port, uint8_t pin)
{
}

void gpio_pin_dir_output(uint32_t port, uint8_t pin, bool initial_value)
{
}
