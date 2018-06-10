/*
 * os_include.h
 *
 * Copyright © 2007-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define _GNU_SOURCE
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <tomcrypt.h>
#include <tommath.h>

#define min(a, b) ((a) <= (b) ? (a) : (b))
#define max(a, b) ((a) >= (b) ? (a) : (b))

#if !defined(alignas)
#define alignas(n) __attribute__((aligned(n)))
#endif

#ifndef __addr_t_defined
#define __addr_t_defined
typedef size_t addr_t;
#endif

typedef union {
	void *ptr;
	uint8_t *ptr8;
	uint16_t *ptr16;
	uint32_t *ptr32;
	addr_t addr;
} ptr_union_t;

typedef int8_t ref_t;
typedef uint32_t ipv4_addr_t;
typedef uint64_t ticks_t;
typedef addr_t handle_t;

#define LIKELY(exp) __builtin_expect((exp) != 0, 1)
#define UNLIKELY(exp) __builtin_expect((exp) != 0, 0)
