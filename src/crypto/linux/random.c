/*
 * random.c
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("random");

uint32_t random_get32(void)
{
	struct thread_public_context_t *context = thread_get_public_context();

	uint32_t result;
	if (fread(&result, 4, 1, context->random_fp) != 1) {
		fprintf(stderr, "failed to read /dev/urandom\n");
		exit(1);
	}

	return result;
}
