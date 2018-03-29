/*
 * ./src/default/log.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("log");

#define LOG_MANAGER_MAX_ENTRY_COUNT 1024
#define LOG_MANAGER_MAX_ENTRY_LENGTH 256

struct log_reader_t {
	struct log_reader_t *next;
	struct log_manager_t *log_manager;
	uint32_t tail;

	log_reader_notify_func_t notify_func;
	void *notify_arg;
};

struct log_manager_t {
	uint32_t head;
	uint32_t tail;
	struct log_reader_t *reader_list;
	char *entries[LOG_MANAGER_MAX_ENTRY_COUNT];
};

struct log_manager_t log_manager_normal;
struct log_manager_t log_manager_trace;

static void log_vappend_store(struct log_manager_t *log_manager, char *line)
{
	char *line_dup = heap_strdup(line, PKG_OS, MEM_TYPE_OS_LOG_LINE);
	if (!line_dup) {
		DEBUG_WARN("out of memory");
		return;
	}

	if (log_manager->entries[log_manager->head]) {
		heap_free(log_manager->entries[log_manager->head]);
	}

	log_manager->entries[log_manager->head] = line_dup;
	log_manager->head = (log_manager->head + 1) % LOG_MANAGER_MAX_ENTRY_COUNT;

	if (log_manager->head == log_manager->tail) {
		log_manager->tail = (log_manager->tail + 1) % LOG_MANAGER_MAX_ENTRY_COUNT;

		struct log_reader_t *reader = log_manager->reader_list;
		while (reader) {
			if (reader->tail == log_manager->head) {
				reader->tail = log_manager->tail;
			}

			reader = reader->next;
		}
	}
}

static void log_vappend_notify(struct log_manager_t *log_manager)
{
	struct log_reader_t *reader = log_manager->reader_list;
	while (reader) {
		if (reader->notify_func) {
			reader->notify_func(reader->notify_arg);
		}

		reader = reader->next;
	}
}

static void log_vappend(struct log_manager_t *log_manager, const char *class_name, const char *fmt, va_list ap)
{
	DEBUG_ASSERT(thread_is_main_thread(), "log_vappend called from unsupported thread");

	/*
	 * Build text.
	 */
	char buffer[LOG_MANAGER_MAX_ENTRY_LENGTH];
	char *ptr = buffer;
	char *end = buffer + sizeof(buffer);

	/* Timestamp. */
	struct tm current_tm;
	unix_time_to_tm(unix_time(), &current_tm);
	sprintf_custom(ptr, end, "%04u%02u%02u-%02u:%02u:%02u ", current_tm.tm_year + 1900, current_tm.tm_mon + 1, current_tm.tm_mday, current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec);
	ptr = strchr(ptr, 0);

	/* Class name. */
	char *debug __attribute__((unused)) = ptr;
	sprintf_custom(ptr, end, "%s: ", class_name);
	ptr = strchr(ptr, 0);

	/* Body. */
	vsprintf_custom(ptr, end, fmt, ap);
	buffer[sizeof(buffer) - 1] = 0;

	DEBUG_INFO("%s", debug);

	/*
	 * Add to log.
	 */
	log_vappend_store(&log_manager_trace, buffer);
	log_vappend_notify(&log_manager_trace);

	if (log_manager) {
		log_vappend_store(log_manager, buffer);
		log_vappend_notify(log_manager);
	}
}

void log_error(const char *class_name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vappend(&log_manager_normal, class_name, fmt, ap);
	va_end(ap);
}

void log_warning(const char *class_name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vappend(&log_manager_normal, class_name, fmt, ap);
	va_end(ap);
}

void log_info(const char *class_name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vappend(&log_manager_normal, class_name, fmt, ap);
	va_end(ap);
}

void log_trace(const char *class_name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vappend(NULL, class_name, fmt, ap);
	va_end(ap);
}

void log_vtrace(const char *class_name, const char *fmt, va_list ap)
{
	log_vappend(NULL, class_name, fmt, ap);
}

void log_trace_dump_array(const char *class_name, uint8_t *data, size_t length)
{
	uint8_t *end = data + length;
	while (data < end) {
		uint8_t *local_end = data + 64;
		if (local_end > end) {
			local_end = end;
		}

		char str_buffer[64 * 2 + 4];
		char *str_ptr = str_buffer;
		while (data < local_end) {
			sprintf(str_ptr, "%02x", *data++);
			str_ptr = strchr(str_ptr, 0);
		}

		log_trace(class_name, "%s", str_buffer);
	}
}

void log_trace_dump_netbuf(const char *class_name, struct netbuf *nb)
{
	addr_t bookmark = netbuf_get_pos(nb);

	while (1) {
		size_t length = netbuf_get_remaining(nb);
		if (length == 0) {
			netbuf_set_pos(nb, bookmark);
			return;
		}

		uint8_t data[64];
		if (length > sizeof(data)) {
			length = sizeof(data);
		}

		netbuf_fwd_read(nb, data, length);
		uint8_t *data_ptr = data;

		char str_buffer[64 * 2 + 4];
		char *str_ptr = str_buffer;
		while (length--) {
			sprintf(str_ptr, "%02x", *data_ptr++);
			str_ptr = strchr(str_ptr, 0);
		}

		log_trace(class_name, "%s", str_buffer);
	}
}

const char *log_reader_get_text(struct log_reader_t *reader)
{
	struct log_manager_t *log_manager = reader->log_manager;
	if (reader->tail == log_manager->head) {
		return NULL;
	}

	return log_manager->entries[reader->tail];
}

void log_reader_advance(struct log_reader_t *reader)
{
	reader->tail = (reader->tail + 1) % LOG_MANAGER_MAX_ENTRY_COUNT;
}

void log_reader_free(struct log_reader_t *reader)
{
	struct log_manager_t *log_manager = reader->log_manager;
	struct log_reader_t **pprev = &log_manager->reader_list;
	struct log_reader_t *p = reader = log_manager->reader_list;

	while (p) {
		if (p == reader) {
			*pprev = p->next;
			heap_free(p);
			return;
		}

		pprev = &p->next;
		p = p->next;
	}
}

struct log_reader_t *log_reader_alloc(struct log_manager_t *log_manager)
{
	struct log_reader_t *reader = (struct log_reader_t *)heap_alloc_and_zero(sizeof(struct log_reader_t), PKG_OS, MEM_TYPE_OS_LOG_READER);
	if (!reader) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	reader->log_manager = log_manager;
	reader->tail = log_manager->tail;
	reader->next = log_manager->reader_list;
	log_manager->reader_list = reader;

	return reader;
}

void log_reader_register_notify(struct log_reader_t *reader, log_reader_notify_func_t notify_func, void *arg)
{
	reader->notify_func = notify_func;
	reader->notify_arg = arg;
}
