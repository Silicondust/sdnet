/*
 * appfs.c
 *
 * Copyright © 2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <app_include.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("appfs");

extern addr_t appfs_tar_start;
extern addr_t appfs_tar_end;

void appfs_init(void)
{
#if defined(APPFS_ENC_IV) && defined(APPFS_ENC_KEY)
	aes_128_iv_t iv = { .u8 = APPFS_ENC_IV };
	aes_128_key_t key = { .u8 = APPFS_ENC_KEY };
	appfs_tar_init_encrypted(&appfs_tar_start, &appfs_tar_end, &iv, &key);
#else
	appfs_tar_init(&appfs_tar_start, &appfs_tar_end);
#endif
}
