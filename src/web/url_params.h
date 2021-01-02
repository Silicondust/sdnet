/*
 * url_params.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool url_params_str_get_value(const char *params_str, const char *name, char *value, size_t value_buffer_size);
extern bool url_params_str_get_value_u32(const char *params_str, const char *name, uint32_t *pvalue, int base);
extern bool url_params_str_get_value_u64(const char *params_str, const char *name, uint64_t *pvalue, int base);

extern bool url_params_nb_get_value(struct netbuf *params_nb, const char *name, char *value, size_t value_buffer_size);
extern bool url_params_nb_get_value_u32(struct netbuf *params_nb, const char *name, uint32_t *pvalue, int base);
extern bool url_params_nb_get_value_u64(struct netbuf *params_nb, const char *name, uint64_t *pvalue, int base);
