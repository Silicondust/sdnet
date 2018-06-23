/*
 * os_include.h
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma warning(disable:4200)

#define _WINSOCKAPI_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <sys/types.h>
#include <sys/timeb.h>

#define LTC_NO_PROTOTYPES
#include <tomcrypt.h>
#include <tommath.h>

#define __attribute__(x)

#if !defined(__unused)
#define __unused __pragma(warning(suppress: 4100 4101))
#endif

#if !defined(alignas)
#define alignas(n) __declspec(align(n))
#endif

typedef size_t addr_t;
typedef signed long ssize_t;

typedef union {
	void *ptr;
	uint8_t *ptr8;
	uint16_t *ptr16;
	uint32_t *ptr32;
	addr_t addr;
} ptr_union_t;

typedef int ref_t;
typedef uint32_t ipv4_addr_t;
typedef uint64_t ticks_t;

#define atoll _atoi64
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define snprintf _snprintf
#define strdup _strdup
#define fseeko _fseeki64
#define ftello _ftelli64

#define LIKELY(exp) (exp)
#define UNLIKELY(exp) (exp)

extern char *strcasestr(const char *haystack, const char *needle);
