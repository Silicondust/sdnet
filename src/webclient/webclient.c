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

static bool webclient_execute_start(struct webclient_t *webclient);
static http_parser_error_t webclient_http_tag_webclient(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t webclient_http_tag_location(void *arg, const char *header, struct netbuf *nb);

static const struct http_parser_tag_lookup_t webclient_http_tag_list[] = {
	{ "Connection", webclient_http_tag_webclient },
	{ "Location", webclient_http_tag_location },
	{ NULL, NULL }
};

static void webclient_close_internal(struct webclient_t *webclient)
{
	oneshot_detach(&webclient->idle_disconnect_timer);

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
	webclient->http_last_event = HTTP_PARSER_EVENT_RESET;

	webclient->keep_alive_accepted = false;
	webclient->must_close = false;
}

void webclient_release(struct webclient_t *webclient)
{
	DEBUG_ASSERT(!webclient->current_operation, "webclient_release called with current operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "webclient_release called with pipelined operation");

	webclient_close_internal(webclient);

	http_parser_set_tag_list(webclient->http_parser, NULL, NULL);
	http_parser_deref(webclient->http_parser);

	if (webclient->http_tag_list_allocated) {
		heap_free(webclient->http_tag_list_allocated);
	}

	if (webclient->additional_header_lines) {
		heap_free(webclient->additional_header_lines);
	}

	heap_free(webclient);
}

static void webclient_idle_disconnect_callback(void *arg)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	DEBUG_ASSERT(!webclient->current_operation, "idle_disconnect with current operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "idle_disconnect with pipelined operation");

	DEBUG_INFO("webclient not being used - closing");
	webclient_close_internal(webclient);
}

static void webclient_operation_complete_close_webclient(struct webclient_t *webclient, uint8_t result, uint16_t http_error, const char *error_str)
{
	webclient_close_internal(webclient);

	struct webclient_operation_t *ended_current_operation = webclient->current_operation;
	struct webclient_operation_t *ended_pipelined_operation = webclient->pipelined_operation;
	webclient->pipelined_operation = NULL;
	webclient->current_operation = NULL;

	if (ended_current_operation) {
		ended_current_operation->webclient = NULL;
		webclient_operation_signal_complete(ended_current_operation, result, http_error, error_str);
		webclient_operation_deref(ended_current_operation);
	}

	if (ended_pipelined_operation) {
		ended_pipelined_operation->webclient = NULL;
		webclient_operation_signal_complete(ended_pipelined_operation, WEBCLIENT_RESULT_EARLY_CLOSE, 0, "early close");
		webclient_operation_deref(ended_pipelined_operation);
	}
}

static void webclient_operation_complete_healthy_webclient(struct webclient_t *webclient, uint8_t result, uint16_t http_error, const char *error_str)
{
	if (webclient->must_close || !webclient->keep_alive_accepted) {
		DEBUG_INFO("unable to pipeline");
		webclient_operation_complete_close_webclient(webclient, result, http_error, error_str);
		return;
	}

	if (!webclient->tcp_conn && !webclient->tls_conn) {
		DEBUG_ASSERT(0, "keep-alive but no connection");
		webclient_operation_complete_close_webclient(webclient, result, http_error, error_str);
		return;
	}

	struct webclient_operation_t *ended_operation = webclient->current_operation;
	webclient->current_operation = NULL;

	if (!webclient->pipelined_operation && (webclient->max_idle_time != TICKS_INFINITE) && !oneshot_is_attached(&webclient->idle_disconnect_timer)) {
		oneshot_attach(&webclient->idle_disconnect_timer, webclient->max_idle_time, webclient_idle_disconnect_callback, webclient);
	}

	if (ended_operation) {
		ended_operation->webclient = NULL;
		webclient_operation_signal_complete(ended_operation, result, http_error, error_str);
		webclient_operation_deref(ended_operation);
	}
}

void webclient_release_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (operation == webclient->pipelined_operation) {
		DEBUG_INFO("pipelined operation release");
		webclient->pipelined_operation = NULL;
		webclient->must_close = true;

		operation->webclient = NULL;
		webclient_operation_deref(operation);
		return;
	}

	if (operation == webclient->current_operation) {
		DEBUG_INFO("current operation release");
		webclient->current_operation = NULL;

		operation->webclient = NULL;
		webclient_operation_deref(operation);
		return;
	}
}

void webclient_timeout_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (operation == webclient->pipelined_operation) {
		DEBUG_INFO("pipelined operation timeout");
		webclient->pipelined_operation = NULL;
		webclient->must_close = true;

		operation->webclient = NULL;
		webclient_operation_signal_complete(operation, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
		webclient_operation_deref(operation);
		return;
	}

	if (operation == webclient->current_operation) {
		DEBUG_INFO("current operation timeout");
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
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
	struct webclient_operation_t *operation = webclient->current_operation;
	char error_str[20];

	webclient->http_last_event = event;

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		DEBUG_ASSERT(webclient->current_operation, "http event status code without current operation");
		DEBUG_ASSERT(!webclient->pipelined_operation, "http event status code with pipelined operation");
		if (!operation) {
			return HTTP_PARSER_ESTOP;
		}

		webclient->http_result = (uint16_t)netbuf_fwd_strtoul(nb, NULL, 10);

		if (webclient_is_http_result_redirect(webclient)) {
			http_parser_set_tag_list(webclient->http_parser, webclient_http_tag_list, webclient);
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		DEBUG_TRACE("HTTP_PARSER_EVENT_HEADER_COMPLETE: keep_alive=%u", webclient->keep_alive_accepted);
		DEBUG_ASSERT(webclient->current_operation, "http event header complete without current operation");
		DEBUG_ASSERT(!webclient->pipelined_operation, "http event header complete with pipelined operation");
		if (!operation) {
			return HTTP_PARSER_ESTOP;
		}

		if ((webclient->http_result == 100) && webclient->expect_100_continue) {
			DEBUG_TRACE("webclient_http_event: 100");
			webclient_operation_schedule_post_callback(operation);
			return HTTP_PARSER_OK;
		}

		operation->stats.header_complete_time = timer_get_ticks();

		if (webclient_is_http_result_redirect(webclient)) {
			if (!webclient->redirect_url_updated) {
				DEBUG_WARN("webclient_http_event: redirect without location");
				sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", webclient->http_result);
				webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, error_str);
				return HTTP_PARSER_OK;
			}

			if (operation->redirect_callback) {
				webclient_operation_ref(operation);
				operation->redirect_callback(operation->callback_arg, operation, &operation->url);
				if (webclient_operation_deref(operation) == 0) {
					DEBUG_ASSERT(!webclient->current_operation, "zero deref but operation still set");
					webclient_operation_complete_healthy_webclient(webclient, 0, 0, "");
					return HTTP_PARSER_OK;
				}
			}

			DEBUG_INFO("webclient_http_event: redirecting to new url");
			operation->stats.redirect_count++;

			if (!webclient_execute_start(webclient)) {
				sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", webclient->http_result);
				webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, error_str);
				return HTTP_PARSER_OK;
			}

			return HTTP_PARSER_OK;
		}

		if (webclient->http_result == 200) {
			DEBUG_TRACE("webclient_http_event: 200");
			return HTTP_PARSER_OK;
		}

		DEBUG_WARN("webclient_http_event: non-ok status code %u", webclient->http_result);
		sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", webclient->http_result);
		webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_NON_200_RESULT, webclient->http_result, error_str);
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA:
		if (!operation) {
			DEBUG_INFO("dropping data for dead operation");
			return HTTP_PARSER_OK;
		}

		if (operation->stats.data_start_time == 0) {
			operation->stats.data_start_time = timer_get_ticks();
		}

		operation->stats.download_size += netbuf_get_remaining(nb);

		webclient_operation_ref(operation);
		if (operation->data_callback) {
			operation->data_callback(operation->callback_arg, operation, nb);
		}
		if (webclient_operation_deref(operation) == 0) {
			DEBUG_ASSERT(!webclient->current_operation, "zero deref but operation still set");
			webclient_operation_complete_close_webclient(webclient, 0, 0, "");
			return HTTP_PARSER_OK;
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		DEBUG_TRACE("HTTP_PARSER_EVENT_DATA_COMPLETE");
		if ((webclient->http_result == 100) && webclient->expect_100_continue) {
			return HTTP_PARSER_OK;
		}

		if (operation) {
			operation->stats.data_complete_time = timer_get_ticks();
			webclient_operation_complete_healthy_webclient(webclient, WEBCLIENT_RESULT_SUCCESS, 0, "success");
			operation = webclient->current_operation;
		}

		if (!operation) {
			webclient->current_operation = webclient->pipelined_operation;
			webclient->pipelined_operation = NULL;
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("http error event - closing webclient");
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_HTTP_PARSE_ERROR, 0, "parse error");
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void webclient_conn_recv(void *arg, struct netbuf *nb)
{
	struct webclient_t *webclient = (struct webclient_t *)arg;
	struct webclient_operation_t *operation = webclient->current_operation;
	if (!operation) {
		DEBUG_ERROR("conn recv without current operation");
		webclient_close_internal(webclient);
		return;
	}

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
		oneshot_detach(&webclient->idle_disconnect_timer);
		oneshot_attach(&webclient->idle_disconnect_timer, min(webclient->max_idle_time, 5 * TICK_RATE), webclient_idle_disconnect_callback, webclient);
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

static bool webclient_execute_connect(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = webclient->current_operation;
	DEBUG_ASSERT(webclient->current_operation, "execute_connect called without operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "execute_connect called with pipelined operation");
	DEBUG_ASSERT(!webclient->tcp_conn, "active webclient");
	DEBUG_ASSERT(!webclient->tls_conn, "active webclient");

	if (!webclient_build_and_set_http_tag_list(webclient)) {
		DEBUG_WARN("out of memory");
		return false;
	}

	if (operation->url.protocol == URL_PROTOCOL_HTTP) {
		webclient->tcp_conn = tcp_connection_alloc();
		if (!webclient->tcp_conn) {
			DEBUG_WARN("out of memory");
			return false;
		}

		if (webclient->max_recv_nb_size != 0) {
			tcp_connection_set_max_recv_nb_size(webclient->tcp_conn, webclient->max_recv_nb_size);
		}

		if (tcp_connection_connect(webclient->tcp_conn, operation->url.ip_addr, operation->url.ip_port, 0, 0, webclient_conn_established, webclient_conn_recv, NULL, webclient_conn_close, webclient) != TCP_OK) {
			DEBUG_WARN("connect failed");
			tcp_connection_deref(webclient->tcp_conn);
			webclient->tcp_conn = NULL;
			return false;
		}

		return true;
	}

	if (operation->url.protocol == URL_PROTOCOL_HTTPS) {
		webclient->tls_conn = tls_client_connection_alloc();
		if (!webclient->tls_conn) {
			DEBUG_WARN("out of memory");
			return false;
		}

		if (!tls_client_connection_connect(webclient->tls_conn, operation->url.ip_addr, operation->url.ip_port, 0, 0, operation->url.dns_name, webclient_conn_established, webclient_conn_recv, NULL, webclient_conn_close, webclient)) {
			DEBUG_WARN("connect failed");
			tls_client_connection_deref(webclient->tls_conn);
			webclient->tls_conn = NULL;
			return false;
		}

		return true;
	}

	DEBUG_ERROR("unsupported protocol");
	return false;
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

	if (!webclient_execute_connect(webclient)) {
		webclient_operation_complete_close_webclient(webclient, WEBCLIENT_RESULT_CONNECT_FAILED, 0, "connect failed");
		return;
	}
}

static bool webclient_execute_dns_or_connect(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = webclient->current_operation;
	DEBUG_ASSERT(webclient->current_operation, "execute_dns called without operation");
	DEBUG_ASSERT(!webclient->pipelined_operation, "execute_dns called with pipelined operation");
	DEBUG_ASSERT(!webclient->dns_lookup, "active dns operation");

	if (operation->url.ip_addr != 0) {
		return webclient_execute_connect(webclient);
	}

	webclient->dns_lookup = dns_lookup_alloc();
	if (!webclient->dns_lookup) {
		return false;
	}

	if (!dns_lookup_gethostbyname(webclient->dns_lookup, operation->url.dns_name, webclient_execute_dns_callback, webclient)) {
		DEBUG_WARN("dns failed");
		return false;
	}

	return true;
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

static bool webclient_execute_start(struct webclient_t *webclient)
{
	struct webclient_operation_t *operation = (webclient->pipelined_operation) ? webclient->pipelined_operation : webclient->current_operation;

	if (webclient->tcp_conn || webclient->tls_conn) {
		if (!webclient_is_url_valid_to_pipeline(webclient, &operation->url)) {
			DEBUG_ASSERT(!webclient->pipelined_operation, "invalid state");
			DEBUG_INFO("unable to use existing webclient - forcing restart of webclient");
			webclient_close_internal(webclient);
		}
	}

	if (RUNTIME_DEBUG) {
		char url_str[512];
		url_to_str(&operation->url, url_str, url_str + sizeof(url_str));

		if (webclient->pipelined_operation) {
			DEBUG_INFO("requesting %s (pipelined)", url_str);
		} else if (webclient->tcp_conn || webclient->tls_conn) {
			DEBUG_INFO("requesting %s (existing webclient)", url_str);
		} else {
			DEBUG_INFO("requesting %s (new webclient)", url_str);
		}
	}

	oneshot_detach(&webclient->idle_disconnect_timer);

	webclient->http_result = 0;
	webclient->redirect_url_updated = false;

	operation->stats.start_time = timer_get_ticks();
	operation->stats.dns_time = 0;
	operation->stats.establish_time = 0;
	operation->stats.header_complete_time = 0;

	if (!webclient->tcp_conn && !webclient->tls_conn) {
		sprintf_custom(webclient->dns_name, webclient->dns_name + sizeof(webclient->dns_name), "%s", operation->url.dns_name);
		return webclient_execute_dns_or_connect(webclient);
	}

	if (!webclient_send_header(webclient, operation)) {
		if (operation == webclient->pipelined_operation) {
			DEBUG_INFO("failed to send pipelined request using existing webclient");
			webclient->must_close = true;
			return false;
		}

		DEBUG_INFO("failed to send using existing webclient, starting new webclient");
		webclient_close_internal(webclient);
		return webclient_execute_dns_or_connect(webclient);
	}

	if (operation->post_callback && !webclient->expect_100_continue) {
		webclient_operation_schedule_post_callback(operation);
	}

	return true;
}

bool webclient_execute_operation(struct webclient_t *webclient, struct webclient_operation_t *operation)
{
	if (webclient->pipelined_operation) {
		DEBUG_WARN("unable to execute operation - busy with existing pipelined operation");
		return false;
	}

	if (webclient->current_operation) {
		if (!webclient_is_url_valid_to_pipeline(webclient, &operation->url)) {
			DEBUG_WARN("unable to execute operation - unable to pipeline with current operation");
			return false;
		}

		webclient->pipelined_operation = webclient_operation_ref(operation);
		operation->webclient = webclient;

		if (!webclient_execute_start(webclient)) {
			DEBUG_WARN("unable to execute operation - start failed");
			operation->webclient = NULL;
			webclient_operation_deref(operation);
			webclient->pipelined_operation = NULL;
			return false;
		}

		return true;
	}

	if ((webclient->http_last_event != HTTP_PARSER_EVENT_DATA_COMPLETE) && (webclient->http_last_event != HTTP_PARSER_EVENT_RESET)) {
		DEBUG_INFO("forcing restart of webclient to reset http state");
		webclient_close_internal(webclient);
	}

	webclient->current_operation = webclient_operation_ref(operation);
	operation->webclient = webclient;

	if (!webclient_execute_start(webclient)) {
		DEBUG_WARN("unable to execute operation - start failed");
		operation->webclient = NULL;
		webclient_operation_deref(operation);
		webclient->current_operation = NULL;
		return false;
	}
			
	return true;
}

bool webclient_can_execute(struct webclient_t *webclient, struct url_t *url)
{
	if (webclient->pipelined_operation) {
		return false;
	}

	if (webclient->current_operation) {
		return webclient_is_url_valid_to_pipeline(webclient, url);
	}

	return true;
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

	oneshot_init(&webclient->idle_disconnect_timer);
	webclient->max_idle_time = max_idle_time;
	webclient->http_last_event = HTTP_PARSER_EVENT_RESET;

	return webclient;
}
