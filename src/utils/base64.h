/*
 * base64.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern size_t base64_encode_length(size_t raw_size);
extern void base64_encode_mem_to_str(uint8_t *raw, size_t raw_size, char *output);
extern void base64_encode_netbuf_to_str(struct netbuf *raw_nb, size_t raw_size, char *output);
extern bool base64_encode_mem_to_netbuf(uint8_t *raw, size_t raw_size, struct netbuf *output_nb);
extern bool base64_encode_netbuf_to_netbuf2(struct netbuf *raw_nb, size_t raw_size, struct netbuf *output_nb);

extern size_t base64_decode_max_length(size_t encoded_size);
extern size_t base64_decode_str_max_length(const char *encoded_data);
extern size_t base64_decode_str_to_mem(const char *encoded_data, uint8_t *buffer, size_t buffer_size);
extern bool base64_decode_str_to_netbuf(const char *encoded_data, struct netbuf *output_nb);
extern size_t base64_decode_netbuf_max_length(struct netbuf *nb);
extern size_t base64_decode_netbuf_to_mem(struct netbuf *nb, uint8_t *buffer, size_t buffer_size);
extern bool base64_decode_netbuf_to_netbuf2(struct netbuf *encoded_nb,struct netbuf *output_nb);
