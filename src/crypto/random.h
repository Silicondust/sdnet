/*
 * random.h
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern uint16_t random_get16(void);
extern uint32_t random_get32(void);
extern void random_getbytes(uint8_t *out, size_t length);
