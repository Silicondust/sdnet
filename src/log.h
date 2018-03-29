/*
 * ./src/log.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct log_reader_t;
struct log_manager_t;

typedef void (*log_reader_notify_func_t)(void *arg);

extern void log_error(const char *class_name, const char *fmt, ...);
extern void log_warning(const char *class_name, const char *fmt, ...);
extern void log_info(const char *class_name, const char *fmt, ...);
extern void log_trace(const char *class_name, const char *fmt, ...);
extern void log_vtrace(const char *class_name, const char *fmt, va_list ap);
extern void log_trace_dump_array(const char *class_name, uint8_t *data, size_t length);
extern void log_trace_dump_netbuf(const char *class_name, struct netbuf *nb);

extern struct log_reader_t *log_reader_alloc(struct log_manager_t *log_manager);
extern void log_reader_free(struct log_reader_t *reader);
extern const char *log_reader_get_text(struct log_reader_t *reader);
extern void log_reader_advance(struct log_reader_t *reader);
extern void log_reader_register_notify(struct log_reader_t *reader, log_reader_notify_func_t notify_func, void *arg);

extern struct log_manager_t log_manager_normal;
extern struct log_manager_t log_manager_trace;
