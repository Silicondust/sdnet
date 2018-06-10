/*
 * crypto_des.c
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("crypto_aes");

void des3_ede_ecb_decrypt_inplace(uint8_t *ptr, uint8_t *end, des3_key_t *key)
{
	DEBUG_ASSERT(((end - ptr) % 8) == 0, "bad length %u", end - ptr);

	symmetric_key skey;
	des3_setup(key->u8, 24, 0, &skey);

	while (ptr < end) {
		des3_ecb_decrypt(ptr, ptr, &skey);
		ptr += 8;
	}
}
