/*
 * char.h
 *
 * Copyright © 2013-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern uint16_t utf8_get_wchar(const char **pptr, uint16_t error_char);
extern void utf8_put_wchar(char **pptr, char *end, uint16_t c);
extern void utf8_put_null(char *ptr, char *end);
extern void utf8_truncate_str_on_error(char *str);

extern uint16_t iso8859_get_wchar(uint8_t table, uint8_t index, uint16_t error_char);

extern uint16_t big5_get_wchar(char **pptr, uint16_t error_char);

extern void str_utf16_to_utf8(char *out, char *end, uint16_t *in);
extern void str_big5_to_utf8(char *out, char *end, char *in);
extern void str_utf8_to_utf16(uint16_t *out, uint16_t *end, const char *in);
extern bool str_nb_to_str(char *out, char *end, struct netbuf *nb);
extern void str_to_upper(char *str);
extern char *str_trim_whitespace(char *str);
extern int strprefixcmp(const char *str, const char *prefix);
extern int strprefixcasecmp(const char *str, const char *prefix);
