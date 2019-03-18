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

struct des3_instance_t {
	symmetric_key skey;
};

void des3_instance_free(struct des3_instance_t *des3)
{
	heap_free(des3);
}

void des3_instance_ecb_decrypt_inplace(struct des3_instance_t *des3, uint8_t *ptr, uint8_t *end)
{
	DEBUG_ASSERT(((end - ptr) % 8) == 0, "bad length %u", end - ptr);

	while (ptr < end) {
		des3_ecb_decrypt(ptr, ptr, &des3->skey);
		ptr += 8;
	}
}

void des3_instance_set_key(struct des3_instance_t *des3, des3_key_t *key)
{
	des3_setup(key->u8, 24, 0, &des3->skey);
}

struct des3_instance_t *des3_instance_alloc(void)
{
	struct des3_instance_t *des3 = (struct des3_instance_t *)heap_alloc_and_zero(sizeof(struct des3_instance_t), PKG_OS, MEM_TYPE_OS_DES3_INSTANCE);
	if (!des3) {
		return NULL;
	}

	return des3;
}
