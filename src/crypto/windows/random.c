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

uint16_t random_get16(void)
{
	uint16_t result;
	random_getbytes((uint8_t *)&result, 2);
	return result;
}

uint32_t random_get32(void)
{
	uint32_t result;
	random_getbytes((uint8_t *)&result, 4);
	return result;
}

void random_getbytes(uint8_t *out, size_t length)
{
	struct thread_public_context_t *context = thread_get_public_context();

	if (!CryptGenRandom(context->crypt_handle, (DWORD)length, out)) {
		fprintf(stderr, "CryptGenRandom failed\n");
		exit(1);
	}
}
