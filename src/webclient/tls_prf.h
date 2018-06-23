/*
 * tls_prf.h
 *
 * Copyright © 2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern void tls_prf(uint8_t *out, uint8_t out_len, const char *label, uint8_t *seed, size_t seed_len, uint8_t *secret, size_t secret_len);
extern void tls_prf_test(void);
