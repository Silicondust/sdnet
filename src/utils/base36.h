/*
 * base36.h
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool base36_encode_upper_from_uint64(uint64_t v, char *str, char *end);
extern bool base36_encode_lower_from_uint64(uint64_t v, char *str, char *end);

extern uint64_t base36_decode_to_uint64(const char *str, uint64_t value_on_error);
