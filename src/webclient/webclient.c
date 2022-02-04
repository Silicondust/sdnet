/*
 * webclient.c
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

THIS_FILE("webclient");

static void webclient_execute_future(void *arg);
static http_parser_error_t webclient_http_tag_webclient(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t webclient_http_tag_location(void *arg, const char *header, struct netbuf *nb);

static const struct http_parser_tag_lookup_t webclient_http_tag_list[] = {
	{ "Connection", webclient_http_tag_webclient },
	{ "Location", webclient_http_tag_location },
	{ NULL, NULL }
};

static struct webclient_t *webclient_ref(struct webclient_t *webclient)
{
	webclient->refs++;
	return webclient;
}

static int webclient_deref(struct webclient_t *webclient)
{
	webclient->refs--;
	if (webclient->refs != 0) {
		return webclient->refs;
	}

	DEBUG_ASSERT(!oneshot_is_attached(&webclient->disconnect_timer), "deref free with active timer");
	DEBUG_ASSERT(!oneshot_is_attached(&webclient->execute_timer), "deref free with active timer");
	DEBUG_ASSERT(!webclient->dns_lookup, "deref free with active dns_lookup");
	DEBUG_ASSERT(!webclient->tcp_conn, "deref free with active tcp_conn");
	DEBUG_ASSERT(!webclient->tls_conn, "deref free with active tls_conn");

	http_parser_set_tag_list(webclient->http_parser, NULL, NULL);
	http_parser_deref(webclient->http_parser);

	if (webclient->http_tag_list_allocated) {
		heap_free(webclient->http_tag_list_allocated);
	}

	if (webclient->additional_header_lines) {
		heap_free(webclient->additional_header_lines);
	}

	heap_free(webclient);
	return 0;
}

static void webclient_close_internal(struct webclient_t *webclient)
{
	oneshot_detach(&webclient->disconnect_timer);

	if (webclient->dns_lookup) {
		dns_lookup_deref(webclient->dns_lookup);
		webclient->dns_lookup = NULL;
	}

	if (webclient->tcp_conn) {
		tcp_connection_close(webclient->tcp_conn);
		tcp_connection_deref(webclient->tcp_conn);
		webclient->tcp_conn = NULL;
	}

	if (webclient->tls_conn) {
		tls_client_connection_close(webclient->tls_conn);
		tls_client_connection_deref(webclient->tls_conn);
		webclient->tls_conn = NULL;
	}

	http_parser_reset(webclient->http_parser);

	webclient->http_result = 0;
	webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_NULL;
	webclient->data_on_dead_operation = 0;
	webclient->redirect_url_updated = false;
	webclient->keep_alive_accepted = false;
	webclient->must_close = false;
}

void webclient_release(struct webclient_t *webclient)
{
	DEBUG_ASSERT(!webclient->current_operation, "webclient_release called with current operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "webclient_release called with pipelined operation");
	DEBUG_ASSERT(!slist_get_head(struct webclient_operation_t, &webclient->future_operations), "idle_disconnect with future operation");

	oneshot_detach(&webclient->execute_timer);
	webclient_close_internal(webclient);
	webclient_deref(webclient);
}

static void webclient_disconnect_callback(void *arg)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	DEBUG_ASSERT(!webclient->current_operation, "disconnect with current operation");

	if (webclient->pipelined_operation || slist_get_head(struct webclient_operation_t, &webclient->future_operations)) {
		DEBUG_INFO("timeout waiting for old transfer to complete - closing");
	} else {
		DEBUG_INFO("webclient not being used - closing");
	}

	webclient_close_internal(webclient);
}

static void webclient_schedule_disconnect(struct webclient_t *webclient, ticks_t delay)
{
	oneshot_detach(&webclient->disconnect_timer);
	oneshot_attach(&webclient->disconnect_timer, delay, webclient_disconnect_callback, webclient);
}

static void webclient_schedule_execute(struct webclient_t *webclient)
{
	if (oneshot_is_attached(&webclient->execute_timer)) {
		return;
	}

	oneshot_attach(&webclient->execute_timer, 0, webclient_execute_future, webclient);
}

static bool webclient_operation_complete_close_webclient(struct webclient_t *webclient, uint8_t result, uint16_t http_error, const char *error_str)
{
	webclient_close_internal(webclient);

	if (webclient->pipelined_operation) {
		slist_attach_head(struct webclient_operation_t, &webclient->future_operations, webclient->pipelined_operation);
		webclient->pipelined_operation = NULL;
	}

	webclient_schedule_execute(webclient);

	struct webclient_operation_t *current_operation = webclient->current_operation;
	if (current_operation) {
		webclient->current_operation = NULL;
		current_operation->webclient = NULL;
		webclient_ref(webclient);
		webclient_operation_signal_complete_and_deref(current_operation, result, http_error, error_str);
		return (webclient_deref(webclient) > 0);
	}

	return true;
}

static bool webclient_operation_complete_healthy_webclient(struct webclient_t *webclient, uint8_t result, uint16_t http_error, const char *error_str)
{
	if (webclient->must_close || !webclient->keep_alive_accepted) {
		DEBUG_INFO("unable to pipeline");
		return webclient_operation_complete_close_webclient(webclient, result, http_error, error_str);
	}

	if (!webclient->tcp_conn && !webclient->tls_conn) {
		DEBUG_ASSERT(0, "keep-alive but no connection");
		return webclient_operation_complete_close_webclient(webclient, result, http_error, error_str);
	}

	struct webclient_operation_t *current_operation = webclient->current_operation;
	webclient->current_operation = NULL;

	if (webclient->pipeline_state != WEBCLIENT_PIPELINE_STATE_NULL) {
		webclient_schedule_disconnect(webclient, TICK_RATE);
	}

	webclient_resume_recv(webclient);
	webclient_schedule_execute(webclient);

	if (current_operation) {
		current_operation->webclient = NULL;
		webclient_ref(webclient);
		webclient_operation_signal_complete_and_deref(current_operation, result, http_error, error_str);
		return (webclient_deref(webclient) > 0);
	}

	return true;
}

void webclient_release_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (operation == webclient->current_operation) {
		DEBUG_INFO("current operation release");
		webclient->current_operation = NULL;

		if (webclient->pipeline_state != WEBCLIENT_PIPELINE_STATE_NULL) {
			webclient_schedule_disconnect(webclient, TICK_RATE);
		}

		webclient_resume_recv(webclient);
		webclient_schedule_execute(webclient);

		operation->webclient = NULL;
		webclient_operation_deref(operation);
		return;
	}

	if (operation == webclient->pipelined_operation) {
		DEBUG_INFO("pipelined operation release");
		webclient->must_close = true;
		webclient->pipelined_operation = NULL;
		webclient_schedule_execute(webclient);

		operation->webclient = NULL;
		webclient_operation_deref(operation);
		return;
	}

	if (slist_detach_item(struct webclient_operation_t, &webclient->future_operations, operation)) {
		operation->webclient = NULL;
		webclient_operation_deref(operation);
		return;
	}
}

void webclient_timeout_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (operation == webclient->current_operation) {
		DEBUG_INFO("current operation timeout");
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
		return;
	}

	if (operation == webclient->pipelined_operation) {
		DEBUG_INFO("pipelined operation timeout");
		webclient->must_close = true;
		webclient->pipelined_operation = NULL;
		webclient_schedule_execute(webclient);

		operation->webclient = NULL;
		webclient_ref(webclient);
		webclient_operation_signal_complete_and_deref(operation, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
		webclient_deref(webclient);
		return;
	}

	if (slist_detach_item(struct webclient_operation_t, &webclient->future_operations, operation)) {
		operation->webclient = NULL;
		webclient_ref(webclient);
		webclient_operation_signal_complete_and_deref(operation, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
		webclient_deref(webclient);
		return;
	}
}

static void webclient_conn_close(void *arg, tcp_close_reason_t reason)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;

	if (webclient->tcp_conn) {
		tcp_connection_deref(webclient->tcp_conn);
		webclient->tcp_conn = NULL;
	}

	if (webclient->tls_conn) {
		tls_client_connection_deref(webclient->tls_conn);
		webclient->tls_conn = NULL;
	}

	if (!http_parser_is_valid_complete(webclient->http_parser)) {
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_EARLY_CLOSE, 0, "early close");
		return;
	}

	webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_SUCCESS, 0, "success");
}

static http_parser_error_t webclient_http_tag_webclient(void *arg, const char *header, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	webclient->keep_alive_accepted = (netbuf_fwd_strcasecmp(nb, "keep-alive") == 0);
	return HTTP_PARSER_OK;
}

static http_parser_error_t webclient_http_tag_location(void *arg, const char *header, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation;
	if (!operation) {
		return HTTP_PARSER_OK;
	}

	struct url_t url;
	memset(&url, 0, sizeof(struct url_t));
	if (!url_parse_nb_with_base(&url, &operation->url, nb)) {
		return HTTP_PARSER_OK;
	}

	if (url_compare(&url, &operation->url)) {
		DEBUG_WARN("redirect loop");
		return HTTP_PARSER_OK;
	}

	operation->url = url;
	webclient->redirect_url_updated = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t webclient_http_tag_passthrough(void *arg, const char *header, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation;
	if (!operation) {
		return HTTP_PARSER_OK;
	}

	const struct http_parser_tag_lookup_t *entry = operation->http_tag_list;
	while (entry->header) {
		if (strcasecmp(entry->header, header) == 0) {
			return entry->func(operation->callback_arg, header, nb);
		}

		entry++;
	}

	return HTTP_PARSER_OK;
}

static uint16_t webclient_is_http_result_redirect(struct webclient_t *webclient)
{
	switch (webclient->http_result) {
	case 301:
	case 302:
	case 307:
	case 308:
		return true;

	default:
		return false;
	}
}

static http_parser_error_t webclient_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation; /* May be NULL */
	char error_str[20];

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		DEBUG_ASSERT(webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY, "http event status code without current operation busy");
		DEBUG_ASSERT(!webclient->pipelined_operation, "http event status code with pipelined operation");

		webclient->http_result = (uint16_t)netbuf_fwd_strtoul(nb, NULL, 10);

		if (webclient_is_http_result_redirect(webclient)) {
			http_parser_set_tag_list(webclient->http_parser, webclient_http_tag_list, webclient);
		}

		webclient->redirect_url_updated = false;
		webclient->data_on_dead_operation = 0;
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		DEBUG_TRACE("HTTP_PARSER_EVENT_HEADER_COMPLETE: keep_alive=%u", webclient->keep_alive_accepted);
		DEBUG_ASSERT(webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY, "http event status code without current operation busy");
		DEBUG_ASSERT(!webclient->pipelined_operation, "http event header complete with pipelined operation");

		if ((webclient->http_result == 100) && webclient->expect_100_continue) {
			DEBUG_TRACE("webclient_http_event: 100");

			if (!operation) {
				return (webclient_operation_complete_close_webclient(webclient, 0, 0, "")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
			}

			webclient_operation_schedule_post_callback(operation);
			return HTTP_PARSER_OK;
		}

		if (!operation) {
			return (webclient_operation_complete_healthy_webclient(webclient, 0, 0, "")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
		}

		operation->stats.header_complete_time = timer_get_ticks();

		if (webclient->http_result == 200) {
			DEBUG_TRACE("webclient_http_event: %u", webclient->http_result);
			return HTTP_PARSER_OK;
		}

		if (webclient->http_result == 304) {
			DEBUG_TRACE("webclient_http_event: %u", webclient->http_result);
			return (webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, "not-modified")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
		}

		if (webclient_is_http_result_redirect(webclient)) {
			if (!webclient->redirect_url_updated) {
				DEBUG_WARN("webclient_http_event: redirect without location");
				sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", webclient->http_result);
				return (webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, error_str)) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
			}

			if (operation->redirect_callback) {
				webclient_operation_ref(operation);
				operation->redirect_callback(operation->callback_arg, operation, &operation->url);

				if (!webclient->current_operation) {
					webclient_operation_deref(operation);
					return (webclient_operation_complete_healthy_webclient(webclient, 0, 0, "")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
				}

				if (operation != webclient->current_operation) {
					webclient_operation_deref(operation);
					return HTTP_PARSER_OK;
				}

				webclient_operation_deref(operation);
			}

			DEBUG_INFO("webclient_http_event: redirecting to new url");
			operation->stats.redirect_count++;
			slist_attach_head(struct webclient_operation_t, &webclient->future_operations, webclient->current_operation);
			webclient->current_operation = NULL;
			webclient_schedule_disconnect(webclient, TICK_RATE);
			return HTTP_PARSER_OK;
		}

		DEBUG_WARN("webclient_http_event: non-ok status code %u", webclient->http_result);
		sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", webclient->http_result);
		return (webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, error_str)) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_DATA:
		if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY) {
			webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_CAN_PIPELINE;
			webclient_schedule_execute(webclient);
		}

		if (!operation) {
			DEBUG_ASSERT(oneshot_is_attached(&webclient->disconnect_timer), "data without operation or disconnect timer");

			if (webclient->data_on_dead_operation >= 16384) {
				DEBUG_WARN("webclient_http_event: force close due to data limit for dead transaction");
				return (webclient_operation_complete_close_webclient(webclient, 0, 0, "")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
			}

			DEBUG_WARN("webclient_http_event: dropping data for dead transaction");
			webclient->data_on_dead_operation += netbuf_get_remaining(nb);
			return HTTP_PARSER_OK;
		}

		if (webclient->http_result != 200) {
			return HTTP_PARSER_OK;
		}

		if (operation->stats.data_start_time == 0) {
			operation->stats.data_start_time = timer_get_ticks();
		}

		operation->stats.download_size += netbuf_get_remaining(nb);

		if (operation->data_callback) {
			webclient_operation_ref(operation);
			operation->data_callback(operation->callback_arg, operation, nb);

			if (!webclient->current_operation) {
				webclient_operation_deref(operation);
				return (webclient_operation_complete_healthy_webclient(webclient, 0, 0, "")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;
			}

			if (operation != webclient->current_operation) {
				webclient_operation_deref(operation);
				return HTTP_PARSER_OK;
			}

			webclient_operation_deref(operation);
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		DEBUG_TRACE("HTTP_PARSER_EVENT_DATA_COMPLETE");
		if ((webclient->http_result == 100) && webclient->expect_100_continue) {
			return HTTP_PARSER_OK;
		}

		if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY) {
			webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_CAN_PIPELINE;
		}

		if (operation) {
			operation->stats.data_complete_time = timer_get_ticks();
			if (!webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_SUCCESS, 0, "success")) {
				return HTTP_PARSER_ESTOP;
			}
			DEBUG_ASSERT(!webclient->current_operation, "current operation set after complete");
		}

		oneshot_detach(&webclient->disconnect_timer);
		webclient->current_operation = webclient->pipelined_operation;
		webclient->pipelined_operation = NULL;
		webclient_resume_recv(webclient);

		operation = webclient->current_operation;
		if (operation) {
			webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY;
			webclient_operation_pipelined_to_current(operation);
			return HTTP_PARSER_OK;
		}

		webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_NULL;
		webclient_schedule_execute(webclient);
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("http error event - closing webclient");
		return (webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_HTTP_PARSE_ERROR, 0, "parse error")) ? HTTP_PARSER_OK : HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void webclient_conn_recv(void *arg, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;

	DEBUG_TRACE("webclient_conn_recv");
	http_parser_recv_netbuf(webclient->http_parser, nb);
}

static bool webclient_send_header(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	/* Don't use expect-100-continue for HTTP as it isn't understood by some proxy servers */
	webclient->expect_100_continue = operation->post_callback && (operation->url.protocol == URL_PROTOCOL_HTTPS);

	struct netbuf *header_nb = netbuf_alloc();
	if (!header_nb) {
		return false;
	}

	bool success = true;
	success &= netbuf_sprintf(header_nb, "%s %s HTTP/1.1\r\n", (operation->post_callback) ? "POST" : "GET", operation->url.uri);
	if (operation->url.flags & URL_FLAGS_PORT_SPECIFIED) {
		success &= netbuf_sprintf(header_nb, "HOST: %s:%u\r\n", operation->url.dns_name, operation->url.ip_port);
	} else {
		success &= netbuf_sprintf(header_nb, "HOST: %s\r\n", operation->url.dns_name);
	}
	if (webclient->expect_100_continue) {
		success &= netbuf_sprintf(header_nb, "EXPECT: 100-Continue\r\n");
	}
	if (operation->post_callback) {
		success &= netbuf_sprintf(header_nb, "TRANSFER-ENCODING: chunked\r\n");
	}
	if (webclient->additional_header_lines) {
		success &= netbuf_sprintf(header_nb, "%s", webclient->additional_header_lines);
	}
	if (operation->additional_header_lines) {
		success &= netbuf_sprintf(header_nb, "%s", operation->additional_header_lines);
	}
	success &= netbuf_sprintf(header_nb, "CONNECTION: keep-alive\r\n");
	success &= netbuf_sprintf(header_nb, "\r\n");
	if (!success) {
		netbuf_free(header_nb);
		return false;
	}

	netbuf_set_pos_to_start(header_nb);

	success = false;
	if (webclient->tcp_conn) {
		success = (tcp_connection_send_netbuf(webclient->tcp_conn, header_nb) == TCP_OK);
	}
	if (webclient->tls_conn) {
		success = tls_client_connection_send_netbuf(webclient->tls_conn, header_nb);
	}

	netbuf_free(header_nb);
	return success;
}

static void webclient_conn_established(void *arg)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation;
	if (!operation) {
		webclient_schedule_execute(webclient);
		return;
	}

	DEBUG_TRACE("webclient_conn_established");
	operation->stats.establish_time = timer_get_ticks();

	if (!webclient_send_header(webclient, operation)) {
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_SEND_FAILED, 0, "send failed");
		return;
	}

	if (operation->post_callback && !webclient->expect_100_continue) {
		webclient_operation_schedule_post_callback(operation);
	}
}

static bool webclient_build_and_set_http_tag_list(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = (webclient->pipelined_operation) ? webclient->pipelined_operation : webclient->current_operation;

	if (!operation->http_tag_list) {
		http_parser_set_tag_list(webclient->http_parser, webclient_http_tag_list, webclient);
		return true;
	}

	uint32_t operation_entry_count = 0;
	const struct http_parser_tag_lookup_t *operation_entry = operation->http_tag_list;
	while (operation_entry->header) {
		operation_entry_count++;
		operation_entry++;
	}

	if (operation_entry_count == 0) {
		http_parser_set_tag_list(webclient->http_parser, webclient_http_tag_list, webclient);
		return true;
	}

	uint32_t webclient_entry_count = 0;
	const struct http_parser_tag_lookup_t *webclient_entry = webclient_http_tag_list;
	while (webclient_entry->header) {
		webclient_entry_count++;
		webclient_entry++;
	}

	size_t alloc_count = webclient_entry_count + operation_entry_count + 1; /* include null entry at end */

	struct http_parser_tag_lookup_t *http_tag_list_allocated = heap_realloc(webclient->http_tag_list_allocated, sizeof(struct http_parser_tag_lookup_t) * alloc_count, PKG_OS, MEM_TYPE_OS_WEBCLIENT_HTTP_TAG_LIST);
	if (!http_tag_list_allocated) {
		return false;
	}

	struct http_parser_tag_lookup_t *new_entry = http_tag_list_allocated;
	memcpy(new_entry, webclient_http_tag_list, sizeof(struct http_parser_tag_lookup_t) * webclient_entry_count);
	new_entry += webclient_entry_count;

	operation_entry = operation->http_tag_list;
	while (operation_entry->header) {
		new_entry->header = operation_entry->header;
		new_entry->func = webclient_http_tag_passthrough;
		new_entry++;
		operation_entry++;
	}

	new_entry->header = NULL;
	new_entry->func = NULL;

	webclient->http_tag_list_allocated = http_tag_list_allocated;
	http_parser_set_tag_list(webclient->http_parser, http_tag_list_allocated, webclient);
	return true;
}

static void webclient_execute_connect(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = webclient->current_operation;
	DEBUG_ASSERT(webclient->current_operation, "execute_connect called without operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "execute_connect called with pipelined operation");
	DEBUG_ASSERT(!webclient->tcp_conn, "active webclient");
	DEBUG_ASSERT(!webclient->tls_conn, "active webclient");

	if (!webclient_build_and_set_http_tag_list(webclient)) {
		DEBUG_WARN("out of memory");
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_RESOURCE_ERROR, 0, "resource error");
		return;
	}

	if (operation->url.protocol == URL_PROTOCOL_HTTP) {
		webclient->tcp_conn = tcp_connection_alloc();
		if (!webclient->tcp_conn) {
			DEBUG_WARN("out of memory");
			webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_RESOURCE_ERROR, 0, "resource error");
			return;
		}

		if (webclient->max_recv_nb_size != 0) {
			tcp_connection_set_max_recv_nb_size(webclient->tcp_conn, webclient->max_recv_nb_size);
		}

		if (tcp_connection_connect(webclient->tcp_conn, operation->url.ip_addr, operation->url.ip_port, 0, 0, webclient_conn_established, webclient_conn_recv, webclient_conn_close, webclient) != TCP_OK) {
			DEBUG_WARN("connect failed");
			tcp_connection_deref(webclient->tcp_conn);
			webclient->tcp_conn = NULL;
			webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_CONNECT_FAILED, 0, "connect failed");
			return;
		}

		return;
	}

	if (operation->url.protocol == URL_PROTOCOL_HTTPS) {
		webclient->tls_conn = tls_client_connection_alloc();
		if (!webclient->tls_conn) {
			DEBUG_WARN("out of memory");
			webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_RESOURCE_ERROR, 0, "resource error");
			return;
		}

		if (!tls_client_connection_connect(webclient->tls_conn, operation->url.ip_addr, operation->url.ip_port, 0, 0, operation->url.dns_name, webclient_conn_established, webclient_conn_recv, webclient_conn_close, webclient)) {
			DEBUG_WARN("connect failed");
			tls_client_connection_deref(webclient->tls_conn);
			webclient->tls_conn = NULL;
			webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_CONNECT_FAILED, 0, "connect failed");
			return;
		}

		return;
	}

	DEBUG_ERROR("unsupported protocol");
	webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_CONNECT_FAILED, 0, "connect failed");
}

static void webclient_execute_dns_callback(void *arg, ipv4_addr_t ip, ticks_t expire_time)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation;

	dns_lookup_deref(webclient->dns_lookup);
	webclient->dns_lookup = NULL;

	if (!operation) {
		return;
	}

	operation->stats.dns_time = timer_get_ticks();

	if (ip == 0) {
		DEBUG_WARN("dns failed");
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_DNS_FAILED, 0, "dns failed");
		return;
	}

	operation->url.ip_addr = ip;
	webclient_execute_connect(webclient);
}

static void webclient_execute_dns_or_connect(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = webclient->current_operation;
	DEBUG_ASSERT(webclient->current_operation, "execute_dns called without operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "execute_dns called with pipelined operation");
	DEBUG_ASSERT(!webclient->dns_lookup, "active dns operation");

	if (operation->url.ip_addr != 0) {
		webclient_execute_connect(webclient);
		return;
	}

	webclient->dns_lookup = dns_lookup_alloc();
	if (!webclient->dns_lookup) {
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_RESOURCE_ERROR, 0, "resource error");
		return;
	}

	if (!dns_lookup_gethostbyname(webclient->dns_lookup, operation->url.dns_name, webclient_execute_dns_callback, webclient)) {
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_DNS_FAILED, 0, "dns failed");
		return;
	}
}

static bool webclient_is_url_valid_to_pipeline(struct webclient_t *webclient, struct url_t *url)
{
	if (webclient->must_close || !webclient->keep_alive_accepted) {
		return false;
	}

	if (strcmp(webclient->dns_name, url->dns_name) != 0) {
		return false;
	}

	switch (url->protocol) {
	case URL_PROTOCOL_HTTP:
		return (webclient->tcp_conn != NULL);

	case URL_PROTOCOL_HTTPS:
		return (webclient->tls_conn != NULL);

	default:
		return false;
	}
}

static void webclient_execute_start(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (RUNTIME_DEBUG) {
		char url_str[512];
		url_to_str(&operation->url, url_str, url_str + sizeof(url_str));

		if (webclient->pipelined_operation) {
			DEBUG_INFO("requesting %s (pipelined)", url_str);
		} else if (webclient->tcp_conn || webclient->tls_conn) {
			DEBUG_INFO("requesting %s (existing connection)", url_str);
		} else {
			DEBUG_INFO("requesting %s (new connection)", url_str);
		}
	}

	operation->stats.start_time = timer_get_ticks();
	operation->stats.dns_time = 0;
	operation->stats.establish_time = 0;
	operation->stats.header_complete_time = 0;

	if (!webclient->tcp_conn && !webclient->tls_conn) {
		sprintf_custom(webclient->dns_name, webclient->dns_name + sizeof(webclient->dns_name), "%s", operation->url.dns_name);
		webclient_execute_dns_or_connect(webclient);
		return;
	}

	if (!webclient_send_header(webclient, operation)) {
		if (operation == webclient->pipelined_operation) {
			DEBUG_INFO("failed to send pipelined request using existing webclient");
			webclient->must_close = true;
			slist_attach_head(struct webclient_operation_t, &webclient->future_operations, webclient->pipelined_operation);
			webclient->pipelined_operation = NULL;
			return;
		}

		DEBUG_INFO("failed to send using existing webclient, starting new webclient");
		webclient_close_internal(webclient);
		webclient_execute_dns_or_connect(webclient);
		return;
	}

	if (operation->post_callback && !webclient->expect_100_continue) {
		webclient_operation_schedule_post_callback(operation);
	}
}

static void webclient_execute_future(void *arg)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;

	struct webclient_operation_t *operation = slist_get_head(struct webclient_operation_t, &webclient->future_operations);
	if (!operation) {
		if (!webclient->tcp_conn && !webclient->tls_conn) {
			return;
		}
		if (webclient->max_idle_time == TICKS_INFINITE) {
			return;
		}

		if (webclient->current_operation) {
			return;
		}
		if (webclient->pipelined_operation) {
			return;
		}

		webclient_schedule_disconnect(webclient, webclient->max_idle_time);
		return;
	}

	if (webclient->pipelined_operation) {
		return;
	}

	if (webclient->current_operation) {
		if (!webclient_is_url_valid_to_pipeline(webclient, &operation->url)) {
			return;
		}

		if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY) {
			return;
		}

		(void)slist_detach_head(struct webclient_operation_t, &webclient->future_operations);
		webclient->pipelined_operation = operation;
		webclient_execute_start(webclient, operation);
		return;
	}

	if (webclient->tcp_conn || webclient->tls_conn) {
		if (!webclient_is_url_valid_to_pipeline(webclient, &operation->url)) {
			DEBUG_INFO("unable to use existing webclient - forcing restart of webclient");
			webclient_close_internal(webclient);
		}

		if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY) {
			if (oneshot_is_attached(&webclient->disconnect_timer)) {
				return;
			}

			DEBUG_ASSERT(0, "no current operation, busy, no disconnect timer set");
			webclient_close_internal(webclient);
		}
	}

	if (!webclient->tcp_conn && !webclient->tls_conn && (webclient->pipeline_state != WEBCLIENT_PIPELINE_STATE_NULL)) {
		DEBUG_ASSERT(0, "state error");
		webclient_close_internal(webclient);
	}

	if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_NULL) {
		(void)slist_detach_head(struct webclient_operation_t, &webclient->future_operations);
		oneshot_detach(&webclient->disconnect_timer);
		webclient->current_operation = operation;
		webclient->pipeline_state = WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY;
		webclient_execute_start(webclient, operation);
		return;
	}

	if (webclient->pipeline_state == WEBCLIENT_PIPELINE_STATE_CAN_PIPELINE) {
		(void)slist_detach_head(struct webclient_operation_t, &webclient->future_operations);
		webclient->pipelined_operation = operation;
		webclient_execute_start(webclient, operation);
		return;
	}

	DEBUG_ASSERT(0, "state error");
}

void webclient_add_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	webclient_operation_ref(operation);
	operation->webclient = webclient;
	slist_attach_tail(struct webclient_operation_t, &webclient->future_operations, operation);

	webclient_schedule_execute(webclient);
}

bool webclient_can_post_data(struct webclient_t *webclient)
{
	if (webclient->tcp_conn) {
		return tcp_connection_can_send(webclient->tcp_conn) == TCP_OK;
	}

	if (webclient->tls_conn) {
		return tls_client_connection_can_send(webclient->tls_conn);
	}

	return false;
}

bool webclient_post_data(struct webclient_t *webclient, struct netbuf *txnb, bool end)
{
	if (!http_response_encode_chunked(txnb)) {
		return false;
	}

	if (end) {
		if (!http_response_encode_chunked_end(txnb)) {
			return false;
		}
	}

	netbuf_set_pos_to_start(txnb);

	bool success = false;
	if (webclient->tcp_conn) {
		success = (tcp_connection_send_netbuf(webclient->tcp_conn, txnb) == TCP_OK);
	}
	if (webclient->tls_conn) {
		success = tls_client_connection_send_netbuf(webclient->tls_conn, txnb);
	}
	if (!success) {
		DEBUG_ERROR("send error");
		return false;
	}

	return true;
}

void webclient_pause_recv(struct webclient_t *webclient)
{
	if (webclient->tcp_conn) {
		tcp_connection_pause_recv(webclient->tcp_conn);
		return;
	}

	if (webclient->tls_conn) {
		tls_client_connection_pause_recv(webclient->tls_conn);
		return;
	}
}

void webclient_resume_recv(struct webclient_t *webclient)
{
	if (webclient->tcp_conn) {
		tcp_connection_resume_recv(webclient->tcp_conn);
		return;
	}

	if (webclient->tls_conn) {
		tls_client_connection_resume_recv(webclient->tls_conn);
		return;
	}
}

ipv4_addr_t webclient_get_local_ip(struct webclient_t *webclient)
{
	if (webclient->tcp_conn) {
		return tcp_connection_get_local_addr(webclient->tcp_conn);
	}

	if (webclient->tls_conn) {
		return tls_client_connection_get_local_addr(webclient->tls_conn);
	}

	return 0;
}

void webclient_set_max_recv_nb_size(struct webclient_t *webclient, size_t max_recv_nb_size)
{
	webclient->max_recv_nb_size = max_recv_nb_size;

	if (webclient->tcp_conn) {
		tcp_connection_set_max_recv_nb_size(webclient->tcp_conn, max_recv_nb_size);
		return;
	}
}

struct webclient_t *webclient_alloc(const char *additional_header_lines, ticks_t max_idle_time)
{
	struct webclient_t *webclient = (struct webclient_t *)heap_alloc_and_zero(sizeof(struct webclient_t), PKG_OS, MEM_TYPE_OS_WEBCLIENT);
	if (!webclient) {
		DEBUG_WARN("out of memory");
		return NULL;
	}

	webclient->refs = 1;
	webclient->max_idle_time = max_idle_time;
	oneshot_init(&webclient->execute_timer);
	oneshot_init(&webclient->disconnect_timer);

	webclient->http_parser = http_parser_alloc(webclient_http_event, webclient);
	if (!webclient->http_parser) {
		heap_free(webclient);
		return NULL;
	}

	if (additional_header_lines) {
		webclient->additional_header_lines = heap_strdup(additional_header_lines, PKG_OS, MEM_TYPE_OS_WEBCLIENT_STR);
		if (!webclient->additional_header_lines) {
			http_parser_deref(webclient->http_parser);
			heap_free(webclient);
			return NULL;
		}
	}

	return webclient;
}
