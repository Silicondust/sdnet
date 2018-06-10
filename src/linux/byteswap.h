/*
 * byteswap.h
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifdef __GNUC_PREREQ
#if __GNUC_PREREQ (4, 2)

#define CUSTOM_BYTESWAP 1

static inline uint16_t byteswap_u16(uint16_t v)
{
	return (v << 8) | (v >> 8);
}

static inline uint32_t byteswap_u32(uint32_t v)
{
	return __builtin_bswap32(v);
}

static inline uint64_t byteswap_u64(uint64_t v)
{
	return __builtin_bswap64(v);
}

#endif
#endif
