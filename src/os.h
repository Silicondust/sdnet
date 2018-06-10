/*
 * os.h
 *
 * Copyright © 2006-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#if defined(_WIN32)
#include <windows/os.h>
#elif defined(__APPLE__)
#include <osx/os.h>
#elif defined(__FreeBSD__)
#include <bsd/os.h>
#else
#include <linux/os.h>
#endif

extern int os_main(int argc, char *argv[]);

extern void app_init(void);
extern void app_start(void);
extern void app_factory_apply(void);
