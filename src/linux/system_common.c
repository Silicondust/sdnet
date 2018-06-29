/*
 * system_common.c
 *
 * Copyright © 2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("system_common");

uint32_t system_detect_file_limit(void)
{
	struct rlimit existing_limit;
	if (getrlimit(RLIMIT_NOFILE, &existing_limit) < 0) {
		DEBUG_ERROR("getrlimit failed (%d)", errno);
		return 0;
	}

	return (uint32_t)existing_limit.rlim_cur;
}

void system_update_file_limit(uint32_t new_limit)
{
	struct rlimit existing_limit;
	if (getrlimit(RLIMIT_NOFILE, &existing_limit) < 0) {
		DEBUG_ERROR("getrlimit failed (%d)", errno);
		return;
	}

	struct rlimit requested_limit;
	requested_limit.rlim_cur = (rlim_t)new_limit;
	requested_limit.rlim_max = (existing_limit.rlim_max > (rlim_t)new_limit) ? existing_limit.rlim_max : (rlim_t)new_limit;

	if (setrlimit(RLIMIT_NOFILE, &requested_limit) < 0) {
		if (errno != EPERM) {
			DEBUG_ERROR("setrlimit failed (%d)", errno);
			return;
		}

		if (existing_limit.rlim_cur >= existing_limit.rlim_max) {
			DEBUG_WARN("unable to increase file limit above existing limit of %u", (unsigned int)existing_limit.rlim_cur);
			return;
		}

		requested_limit.rlim_cur = existing_limit.rlim_max;
		requested_limit.rlim_max = existing_limit.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &requested_limit) < 0) {
			DEBUG_ERROR("setrlimit failed (%d)", errno);
			return;
		}

		DEBUG_INFO("file limit chagned from %u to %u (limited by os)", (unsigned int)existing_limit.rlim_cur, (unsigned int)requested_limit.rlim_cur);
		return;
	}

	DEBUG_INFO("file limit changed from %u to %u", (unsigned int)existing_limit.rlim_cur, (unsigned int)requested_limit.rlim_cur);
}
