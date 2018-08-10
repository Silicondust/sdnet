/*
 * appfs.c
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
	uint8_t *start = (uint8_t *)getsectdata("__DATA", "__appfs", &length);
	DEBUG_ASSERT(start, "no appfs data");
	start += (size_t)_dyld_get_image_vmaddr_slide(0);

#if defined(APPFS_ENC_IV) && defined(APPFS_ENC_KEY)
	aes_128_iv_t iv = { .u8 = APPFS_ENC_IV };
	aes_128_key_t key = { .u8 = APPFS_ENC_KEY };
	appfs_tar_init_encrypted(start, start + length, &iv, &key);
#else
	appfs_tar_init(start, start + length);
#endif
}
