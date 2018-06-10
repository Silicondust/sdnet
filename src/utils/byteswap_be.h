/*
 * byteswap_be.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#if !defined(CUSTOM_BYTESWAP)
static inline uint16_t byteswap_u16(uint16_t v)
{
	return (v << 8) | (v >> 8);
}

static inline uint32_t byteswap_u32(uint32_t v)
{
	return ((uint32_t)byteswap_u16((uint16_t)v) << 16) | (uint32_t)byteswap_u16((uint16_t)(v >> 16));
}

static inline uint64_t byteswap_u64(uint64_t v)
{
	return ((uint64_t)byteswap_u32((uint32_t)v) << 32) | (uint64_t)byteswap_u32((uint32_t)(v >> 32));
}
#endif

static inline uint16_t byteswap_cpu_to_be_u16(uint16_t v)
{
	return v;
}

static inline uint32_t byteswap_cpu_to_be_u32(uint32_t v)
{
	return v;
}

static inline uint64_t byteswap_cpu_to_be_u64(uint64_t v)
{
	return v;
}

static inline uint16_t byteswap_be_to_cpu_u16(uint16_t v)
{
	return v;
}

static inline uint32_t byteswap_be_to_cpu_u32(uint32_t v)
{
	return v;
}

static inline uint64_t byteswap_be_to_cpu_u64(uint64_t v)
{
	return v;
}

static inline uint16_t byteswap_cpu_to_le_u16(uint16_t v)
{
	return byteswap_u16(v);
}

static inline uint32_t byteswap_cpu_to_le_u32(uint32_t v)
{
	return byteswap_u32(v);
}

static inline uint64_t byteswap_cpu_to_le_u64(uint64_t v)
{
	return byteswap_u64(v);
}

static inline uint16_t byteswap_le_to_cpu_u16(uint16_t v)
{
	return byteswap_u16(v);
}

static inline uint32_t byteswap_le_to_cpu_u32(uint32_t v)
{
	return byteswap_u32(v);
}

static inline uint64_t byteswap_le_to_cpu_u64(uint64_t v)
{
	return byteswap_u64(v);
}
