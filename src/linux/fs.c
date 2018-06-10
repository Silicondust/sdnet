/*
 * fs.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <sys/mount.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("fs");

void fs_init(void)
{
	int ret = mount("sysfs", "/sys", "sysfs", 0, NULL);
	if (ret < 0) {
		DEBUG_WARN("mount /sys: %s", strerror(errno));
		return;
	}
}
