/*
 * ./src/appfs/osx/appfs.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <app_include.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("appfs");

void appfs_init(void)
{
	unsigned long length;
	uint8_t *appfs_addr = (uint8_t *)getsectdata("__DATA", "__appfs", &length);
	DEBUG_ASSERT(appfs_addr, "appfs not found");
	appfs_addr += (addr_t)_dyld_get_image_vmaddr_slide(0);

	if ((addr_t)appfs_addr & 0x3) {
		uint8_t *ptr = malloc(length);
		DEBUG_ASSERT(ptr, "out of memory");
		memcpy(ptr, appfs_addr, length);
		appfs_tar_init(ptr, ptr + length);
		return;
	}

	appfs_tar_init(appfs_addr, appfs_addr + length);
}
