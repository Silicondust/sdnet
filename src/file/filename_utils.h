/*
 * filename_utils.h
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#if defined(WIN32)
#define FILENAME_DIR_SEPARATOR_CHAR '\\'
#define FILENAME_DIR_SEPARATOR_STR "\\"
#else
#define FILENAME_DIR_SEPARATOR_CHAR '/'
#define FILENAME_DIR_SEPARATOR_STR "/"
#endif

extern bool filename_is_cross_platform_valid_leading_char(uint16_t c);
extern bool filename_is_cross_platform_valid_middle_char(uint16_t c);
extern bool filename_is_cross_platform_valid_trailing_char(uint16_t c);
extern void filename_inplace_fix_filename_str_without_path(char *str);
extern const char *filename_without_path(const char *input);
extern const char *filename_ext(const char *input);
extern bool filename_ext_cmp(const char *input, const char *match);
extern bool filename_ext_casecmp(const char *input, const char *match);
extern bool filename_strcpy_without_path(char *output, char *end, const char *input);
extern char *filename_strdup_without_path(const char *input, uint8_t pkg, uint8_t type);
extern char *filename_strdup_append_slash(const char *input, uint8_t pkg, uint8_t type);
