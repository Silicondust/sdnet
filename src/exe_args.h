/*
 * ./src/exe_args.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct exe_arg_t {
	struct slist_prefix_t slit_prefix;
	char *name;
	char *value;
};

extern void exe_args_init(int argc, char *argv[]);
extern void exe_args_add(const char *name, const char *value);
extern bool exe_args_conf_file(const char *filename);
extern struct exe_arg_t *exe_args_lookup(const char *name);
