/*
 * webclient_operation.c
 *
 * Copyright © 2014-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <os.h>
#include <webclient/webclient_internal.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("webclient_operation");

#define WEBCLIENT_OPERATION_TIMEOUT (30 * TICK_RATE)

struct webclient_operation_t *webclient_operation_ref(struct webclient_operation_t *operation)
{
	operation->refs++;
	return operation;
}

int webclient_operation_deref(struct webclient_operation_t *operation)
{
	operation->refs--;
	if (operation->refs != 0) {
		return operation->refs;
	}

	DEBUG_ASSERT(!operation->webclient, "deref free with active webclient");
	DEBUG_ASSERT(!oneshot_is_attached(&operation->post_callback_timer), "deref free with timer active");
	DEBUG_ASSERT(!oneshot_is_attached(&operation->timeout_timer), "deref free with timer active");

	if (operation->additional_header_lines) {
		heap_free(operation->additional_header_lines);
	}

	heap_free(operation);
	return 0;
}

void webclient_operation_release(struct webclient_operation_t *operation)
{
	oneshot_detach(&operation->post_callback_timer);
	oneshot_detach(&operation->timeout_timer);

	operation->redirect_callback = NULL;
	operation->post_callback = NULL;
	operation->data_callback = NULL;
	operation->complete_callback = NULL;

	if (operation->webclient) {
		webclient_release_operation(operation->webclient, operation);
	}

	webclient_operation_deref(operation);
}

void webclient_operation_signal_complete_and_deref(struct webclient_operation_t *operation, uint8_t result, uint16_t http_error, const char *error_str)
{
	oneshot_detach(&operation->post_callback_timer);
	oneshot_detach(&operation->timeout_timer);

	webclient_operation_complete_callback_t complete_callback = operation->complete_callback;
	operation->redirect_callback = NULL;
	operation->post_callback = NULL;
	operation->data_callback = NULL;
	operation->complete_callback = NULL;

	operation->stats.complete_time = timer_get_ticks();

	if (operation->stats_last_pause_time > 0) {
		operation->stats.paused_duration += operation->stats.complete_time - operation->stats_last_pause_time;
		operation->stats_last_pause_time = 0;
	}

	if (complete_callback) {
		complete_callback(operation->callback_arg, operation, result, http_error, error_str);
	}

	webclient_operation_deref(operation);
}

static void webclient_operation_timeout(void *arg)
{
	struct webclient_operation_t *operation = (struct webclient_operation_t *)arg;
	struct webclient_t *webclient = operation->webclient;
	DEBUG_WARN("webclient_operation_timeout");

	webclient_timeout_operation(webclient, operation);
}

static void webclient_operation_post_callback(void *arg)
{
	struct webclient_operation_t *operation = (struct webclient_operation_t *)arg;
	operation->post_callback(operation->callback_arg, operation);
}

void webclient_operation_schedule_post_callback(struct webclient_operation_t *operation)
{
	oneshot_attach(&operation->post_callback_timer, 1, webclient_operation_post_callback, operation);
}

bool webclient_operation_can_post_data(struct webclient_operation_t *operation)
{
	struct webclient_t *webclient = operation->webclient;
	if (operation != webclient->current_operation) {
		return false;
	}

	return webclient_can_post_data(webclient);
}

bool webclient_operation_post_data(struct webclient_operation_t *operation, struct netbuf *txnb, bool end)
{
	struct webclient_t *webclient = operation->webclient;
	if (operation != webclient->current_operation) {
		DEBUG_ASSERT(0, "not current operation");
		return false;
	}

	return webclient_post_data(webclient, txnb, end);
}

void webclient_operation_pause_recv(struct webclient_operation_t *operation)
{
	struct webclient_t *webclient = operation->webclient;
	if (operation != webclient->current_operation) {
		DEBUG_ASSERT(0, "not current operation");
		return;
	}

	if (operation->stats_last_pause_time == 0) {
		operation->stats_last_pause_time = timer_get_ticks();
	}

	webclient_pause_recv(webclient);
}

void webclient_operation_resume_recv(struct webclient_operation_t *operation)
{
	struct webclient_t *webclient = operation->webclient;
	if (operation != webclient->current_operation) {
		DEBUG_ASSERT(0, "not current operation");
		return;
	}

	if (operation->stats_last_pause_time > 0) {
		operation->stats.paused_duration += timer_get_ticks() - operation->stats_last_pause_time;
		operation->stats_last_pause_time = 0;
	}

	webclient_resume_recv(webclient);
}

struct webclient_operation_stats_t *webclient_operation_get_stats(struct webclient_operation_t *operation)
{
	return &operation->stats;
}

ticks_t webclient_operation_get_timeout_time_remaining(struct webclient_operation_t *operation)
{
	return oneshot_get_ticks_remaining(&operation->timeout_timer);
}

void webclient_operation_set_timeout(struct webclient_operation_t *operation, ticks_t timeout)
{
	oneshot_detach(&operation->timeout_timer);
	if (timeout == TICKS_INFINITE) {
		return;
	}

	oneshot_attach(&operation->timeout_timer, timeout, webclient_operation_timeout, operation);
}

struct webclient_operation_t *webclient_operation_execute_post(struct webclient_t *webclient, struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_operation_redirect_callback_t redirect_callback, webclient_operation_post_callback_t post_callback, webclient_operation_data_callback_t data_callback, webclient_operation_complete_callback_t complete_callback, void *callback_arg)
{
	struct webclient_operation_t *operation = (struct webclient_operation_t *)heap_alloc_and_zero(sizeof(struct webclient_operation_t), PKG_OS, MEM_TYPE_OS_WEBCLIENT_OPERATION);
	if (!operation) {
		DEBUG_WARN("out of memory");
		return NULL;
	}

	if (additional_header_lines) {
		operation->additional_header_lines = heap_strdup(additional_header_lines, PKG_OS, MEM_TYPE_OS_WEBCLIENT_STR);
		if (!operation->additional_header_lines) {
			heap_free(operation);
			return NULL;
		}
	}

	operation->url = *url;
	operation->http_tag_list = http_tag_list;

	operation->redirect_callback = redirect_callback;
	operation->post_callback = post_callback;
	operation->data_callback = data_callback;
	operation->complete_callback = complete_callback;
	operation->callback_arg = callback_arg;

	operation->refs = 1;

	oneshot_init(&operation->post_callback_timer);
	oneshot_init(&operation->timeout_timer);
	oneshot_attach(&operation->timeout_timer, WEBCLIENT_OPERATION_TIMEOUT, webclient_operation_timeout, operation);

	operation->stats.first_start_time = timer_get_ticks();
	webclient_add_operation(webclient, operation);

	return operation;
}

struct webclient_operation_t *webclient_operation_execute_get(struct webclient_t *webclient, struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_operation_redirect_callback_t redirect_callback, webclient_operation_data_callback_t data_callback, webclient_operation_complete_callback_t complete_callback, void *callback_arg)
{
	return webclient_operation_execute_post(webclient, url, additional_header_lines, http_tag_list, redirect_callback, NULL, data_callback, complete_callback, callback_arg);
}
