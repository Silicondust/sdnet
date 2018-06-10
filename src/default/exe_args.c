/*
 * exe_args.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("exe_args");

static struct slist_t exe_args_list;

struct exe_arg_t *exe_args_lookup(const char *name)
{
	struct exe_arg_t *exe_arg = slist_get_head(struct exe_arg_t, &exe_args_list);
	while (exe_arg) {
		if (strcmp(name, exe_arg->name) == 0) {
			return exe_arg;
		}

		exe_arg = slist_get_next(struct exe_arg_t, exe_arg);
	}

	return NULL;
}

void exe_args_add(const char *name, const char *value)
{
	size_t name_length = strlen(name) + 1;
	size_t value_length = (value) ? strlen(value) + 1 : 0;

	struct exe_arg_t *exe_arg = heap_alloc_and_zero(sizeof(struct exe_arg_t) + name_length + value_length, PKG_OS, MEM_TYPE_OS_EXE_ARG);
	if (!exe_arg) {
		DEBUG_ERROR("out of memory");
		return;
	}

	exe_arg->name = (char *)(void *)(exe_arg + 1);
	memcpy(exe_arg->name, name, name_length);

	if (value) {
		exe_arg->value = exe_arg->name + name_length;
		memcpy(exe_arg->value, value, value_length);
	}

	slist_attach_tail(struct exe_arg_t, &exe_args_list, exe_arg);
}

static void exe_args_parse_line(char *line)
{
	char *split = strchr(line, '=');
	if (!split) {
		return;
	}

	*split++ = 0;

	char *name = str_trim_whitespace(line);
	char *value = str_trim_whitespace(split);
	if ((name[0] == 0) || (value[0] == 0)) {
		return;
	}

	exe_args_add(name, value);
}

bool exe_args_conf_file(const char *filename)
{
	FILE *fp = fopen_utf8(filename, "rb");
	if (!fp) {
		return false;
	}

	while (1) {
		char line[1024];
		if (!fgets(line, sizeof(line), fp)) {
			break;
		}

		char *ptr = strchr(line, '#');
		if (ptr) {
			*ptr = 0;
		}

		exe_args_parse_line(line);
	}

	fclose(fp);
	return true;
}

void exe_args_init(int argc, char *argv[])
{
	DEBUG_ASSERT(argc > 0, "exe name not present");

	char *exe = *argv++; argc--;
	exe_args_add("exe", exe);

	while (argc > 0) {
		char line[1024];
		sprintf_custom(line, line + sizeof(line), "%s", *argv++);
		argc--;

		if (strchr(line, '=')) {
			exe_args_parse_line(line);
			continue;
		}

		char *name = line;
		if ((name[0] != '-') || (argc == 0)) {
			exe_args_add(name, NULL);
			continue;
		}

		char *value = *argv;
		if (value[0] == '-') {
			exe_args_add(name, NULL);
			continue;
		}

		exe_args_add(name, value);
		argv++; argc--;
	}
}
