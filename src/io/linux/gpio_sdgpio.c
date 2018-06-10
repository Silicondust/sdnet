/*
 * gpio_sdgpio.c
 *
 * Copyright © 2012-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <os.h>
#include <linux/types.h>
#include <silicondust/sdgpio.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("gpio_sdgpio");

#define GPIO_DEV_NAME "/dev/sdgpio"

static int gpio_fd = -1;

void gpio_init(void)
{
	gpio_fd = open(GPIO_DEV_NAME, O_RDONLY);
	DEBUG_ASSERT(gpio_fd >= 0, "gpio_init: failed to open %s", GPIO_DEV_NAME);
}

void gpio_pin_init(uint32_t port, uint8_t pin)
{
#if defined(GPIO_PIN_INIT)
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;

	if (ioctl(gpio_fd, GPIO_PIN_INIT, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_init %x.%u failed", port, pin);
		return;
	}
#endif
}

bool gpio_pin_read(uint32_t port, uint8_t pin)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;

	if (ioctl(gpio_fd, GPIO_PIN_READ, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_read %x.%u failed", port, pin);
		return 0;
	}

	return gp.value;
}

void gpio_pin_write_high(uint32_t port, uint8_t pin)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;
	gp.value = 1;

	if (ioctl(gpio_fd, GPIO_PIN_WRITE_VAL, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_write_high %x.%u failed", port, pin);
		return;
	}
}

void gpio_pin_write_low(uint32_t port, uint8_t pin)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;
	gp.value = 0;

	if (ioctl(gpio_fd, GPIO_PIN_WRITE_VAL, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_write_low %x.%u failed", port, pin);
		return;
	}
}

void gpio_pin_write_xor(uint32_t port, uint8_t pin)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;

	if (ioctl(gpio_fd, GPIO_PIN_WRITE_XOR, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_write_xor %x.%u failed", port, pin);
		return;
	}
}

void gpio_pin_dir_input(uint32_t port, uint8_t pin)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;

	if (ioctl(gpio_fd, GPIO_PIN_DIR_INPUT, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_dir_input %x.%u failed", port, pin);
		return;
	}
}

void gpio_pin_dir_output(uint32_t port, uint8_t pin, bool initial_value)
{
	struct sd_gpio gp;
	gp.port = port;
	gp.pin = pin;
	gp.value = initial_value;

	if (ioctl(gpio_fd, GPIO_PIN_DIR_OUTPUT, &gp) < 0) {
		DEBUG_ERROR("gpio_pin_dir_output %x.%u failed", port, pin);
		return;
	}
}
