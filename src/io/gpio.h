/*
 * gpio.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void gpio_init(void);
extern void gpio_pin_init(uint32_t port, uint8_t pin);
extern bool gpio_pin_read(uint32_t port, uint8_t pin);
extern void gpio_pin_write_high(uint32_t port, uint8_t pin);
extern void gpio_pin_write_low(uint32_t port, uint8_t pin);
extern void gpio_pin_write_xor(uint32_t port, uint8_t pin);
extern void gpio_pin_dir_input(uint32_t port, uint8_t pin);
extern void gpio_pin_dir_output(uint32_t port, uint8_t pin, bool initial_value);
