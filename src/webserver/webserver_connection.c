/*
 * webserver_connection.c
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("webserver_connection");

static http_parser_error_t webserver_connection_http_tag_host(void *arg, struct netbuf *nb);
static http_parser_error_t webserver_connection_http_tag_range(void *arg, struct netbuf *nb);
static http_parser_error_t webserver_connection_http_tag_accept_language(void *arg, struct netbuf *nb);

static const struct http_parser_tag_lookup_t webserver_connection_http_tag_list[] = {
	{"HOST", webserver_connection_http_tag_host},
	{"RANGE", webserver_connection_http_tag_range},
	{"ACCEPT-LANGUAGE", webserver_connection_http_tag_accept_language},
	{NULL, NULL}
};

void webserver_connection_free(struct webserver_connection_t *connection)
{
	webserver_remove_connection(connection->webserver, connection);

	const struct webserver_page_t *page = connection->page;
	if (page && page->free_callback) {
		page->free_callback(page->callback_arg, connection, connection->page_callback_state);
	}

	if (connection->http_connection) {
		http_server_connection_close(connection->http_connection);
	}

	if (connection->uri_nb) {
		netbuf_free(connection->uri_nb);
	}
	if (connection->params_nb) {
		netbuf_free(connection->params_nb);
	}

	heap_free(connection);
}

static void webserver_connection_tcp_close(void *arg)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;
	DEBUG_TRACE("connection close");

	connection->http_connection = NULL;
	connection->conn = NULL;

	webserver_connection_free(connection);
}

void webserver_connection_send_error(struct webserver_connection_t *connection, const char *http_result)
{
	struct webserver_t *webserver = connection->webserver;
	if (webserver->error_page_handler) {
		webserver->error_page_handler(connection, http_result);
		return;
	}

	/*
	 * Default handling.
	 */
	struct netbuf *nb = netbuf_alloc();
	if (!nb) {
		DEBUG_ERROR("out of memory");
		return;
	}

	if (!netbuf_sprintf(nb, "%s", http_result)) {
		DEBUG_ERROR("out of memory");
		netbuf_free(nb);
		return;
	}

	size_t content_length = netbuf_get_extent(nb);
	if (!webserver_connection_send_header(connection, http_result, "text/plain", content_length, 0)) {
		DEBUG_ERROR("out of memory");
		netbuf_free(nb);
		return;
	}

	netbuf_set_pos_to_start(nb);
	webserver_connection_send_payload(connection, nb);
	netbuf_free(nb);
}

bool webserver_connection_send_header(struct webserver_connection_t *connection, const char *http_result, const char *content_type, uint64_t content_length, uint32_t cache_duration)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 %s\r\n", http_result);
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", WEBSERVER_NAME);
	success &= netbuf_sprintf(txnb, "Connection: close\r\n");
	if (content_type) {
		success &= netbuf_sprintf(txnb, "Content-Type: %s\r\n", content_type);
	}
	if (content_type && connection->language_header) {
		success &= netbuf_sprintf(txnb, "Content-Language: en\r\n");
	}
	if (content_length != WEBSERVER_CONTENT_LENGTH_UNKNOWN) {
		success &= netbuf_sprintf(txnb, "Content-Length: %llu\r\n", content_length);
	}
	success &= http_header_write_cache_control(txnb, cache_duration);
	success &= netbuf_sprintf(txnb, "Access-Control-Allow-Origin: *\r\n");
	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		DEBUG_ERROR("out of memory");
		netbuf_free(txnb);
		return false;
	}

	netbuf_set_pos_to_start(txnb);

	if (tcp_connection_send_netbuf(connection->conn, txnb) != TCP_OK) {
		netbuf_free(txnb);
		return false;
	}

	netbuf_free(txnb);
	return true;
}

bool webserver_connection_send_payload(struct webserver_connection_t *connection, struct netbuf *nb)
{
	return (tcp_connection_send_netbuf(connection->conn, nb) == TCP_OK);
}

static bool webserver_connection_header_params(struct webserver_connection_t *connection, struct netbuf *nb)
{
	DEBUG_ASSERT(!connection->params_nb, "params already present");

	connection->params_nb = netbuf_clone(nb);
	if (!connection->params_nb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	return true;
}

static webserver_page_result_t webserver_connection_execute(struct webserver_connection_t *connection)
{
	if (!connection->uri_nb) {
		webserver_connection_send_error(connection, http_result_bad_request);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	struct webserver_t *webserver = connection->webserver;
	if (webserver->uri_fixup_handler) {
		if (!webserver->uri_fixup_handler(connection, connection->uri_nb, &connection->params_nb)) {
			return WEBSERVER_PAGE_RESULT_CLOSE;
		}
	}

	struct webserver_page_t *page = webserver_find_page_handler(webserver, connection->uri_nb);
	if (!page) {
		webserver_connection_send_error(connection, http_result_not_found);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	/*
	 * Page handler.
	 */
	connection->page = page;

	netbuf_set_pos_to_start(connection->uri_nb);
	if (connection->params_nb) {
		netbuf_set_pos_to_start(connection->params_nb);
	}

	return page->start_callback(page->callback_arg, connection, connection->uri_nb, connection->params_nb, &connection->page_callback_state);
}

static http_parser_error_t webserver_connection_http_tag_host(void *arg, struct netbuf *nb)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;
	connection->host_detected = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t webserver_connection_http_tag_range(void *arg, struct netbuf *nb)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;

	DEBUG_PRINT_NETBUF_TEXT(nb, 0);

	if (netbuf_fwd_strncasecmp(nb, "bytes=", 6) != 0) {
		DEBUG_WARN("invalid range request");
		return HTTP_PARSER_OK;
	}

	netbuf_advance_pos(nb, 6);

	uint64_t range_start = 0;
	uint64_t range_last = 0;

	if (netbuf_fwd_strncmp(nb, "-", 1) != 0) {
		addr_t end;
		range_start = netbuf_fwd_strtoull(nb, &end, 10);
		netbuf_set_pos(nb, end);

		if (netbuf_fwd_strncmp(nb, "-", 1) != 0) {
			DEBUG_WARN("invalid range request");
			return HTTP_PARSER_OK;
		}
	}

	netbuf_advance_pos(nb, 1);

	if (netbuf_get_remaining(nb) > 0) {
		addr_t end;
		range_last = netbuf_fwd_strtoull(nb, &end, 10);

		if (end != netbuf_get_end(nb)) {
			DEBUG_WARN("invalid range request");
			return HTTP_PARSER_OK;
		}
	}

	if ((range_last != 0) && (range_start > range_last)) {
		DEBUG_WARN("invalid range request");
		return HTTP_PARSER_OK;
	}

	DEBUG_INFO("range request = %llu - %llu", range_start, range_last);
	connection->range_detected = true;
	connection->range_start = range_start;
	connection->range_last = range_last;
	return HTTP_PARSER_OK;
}

static http_parser_error_t webserver_connection_http_tag_accept_language(void *arg, struct netbuf *nb)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;
	connection->language_header = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t webserver_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;
	webserver_page_result_t ret;

	switch (event) {
	case HTTP_PARSER_EVENT_PARAMS:
		if (!webserver_connection_header_params(connection, nb)) {
			webserver_connection_free(connection);
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_PROTOCOL:
		if (netbuf_fwd_strcasecmp(nb, "HTTP") != 0) {
			DEBUG_WARN("bad protocol");
			webserver_connection_send_error(connection, http_result_bad_request);
			webserver_connection_free(connection);
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_VERSION:
		if (netbuf_fwd_strcmp(nb, "1.1") >= 0) {
			connection->host_required = true;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		if (connection->host_required && !connection->host_detected) {
			DEBUG_WARN("no host field");
			webserver_connection_send_error(connection, http_result_bad_request);
			webserver_connection_free(connection);
			return HTTP_PARSER_ESTOP;
		}
		ret = webserver_connection_execute(connection);
		if (ret == WEBSERVER_PAGE_RESULT_CLOSE) {
			webserver_connection_free(connection);
			return HTTP_PARSER_ESTOP;
		}
		if (ret == WEBSERVER_PAGE_RESULT_PAUSE) {
			connection->page_active_state = false;
			return HTTP_PARSER_ESTOP;
		}
		DEBUG_ASSERT(ret == WEBSERVER_PAGE_RESULT_CONTINUE, "unexpected result");
		webserver_connection_page_resume(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
		webserver_connection_send_error(connection, http_result_bad_request);
		webserver_connection_free(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		webserver_connection_send_error(connection, http_result_internal_server_error);
		webserver_connection_free(connection);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void webserver_connection_send_resume(void *arg)
{
	struct webserver_connection_t *connection = (struct webserver_connection_t *)arg;
	if (!connection->page_active_state) {
		return;
	}

	webserver_start_page_timer(connection->webserver);
}

void webserver_connection_page_resume(struct webserver_connection_t *connection)
{
	if (!connection->page) {
		DEBUG_ASSERT(0, "resume but no page handler");
		return;
	}
	if (!connection->page->continue_callback) {
		DEBUG_ASSERT(0, "resume but no continue handler");
		return;
	}

	connection->page_active_state = true;
	webserver_start_page_timer(connection->webserver);
}

ipv4_addr_t webserver_connection_get_local_ip(struct webserver_connection_t *connection)
{
	return tcp_connection_get_local_addr(connection->conn);
}

ipv4_addr_t webserver_connection_get_remote_ip(struct webserver_connection_t *connection)
{
	return tcp_connection_get_remote_addr(connection->conn);
}

void *webserver_connection_get_page_callback_state(struct webserver_connection_t *connection)
{
	return connection->page_callback_state;
}

void webserver_connection_disable_timeout(struct webserver_connection_t *connection)
{
	http_server_connection_disable_timeout(connection->http_connection);
}

bool webserver_connection_accept(struct webserver_t *webserver, struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri)
{
	/*
	 * Create connection object.
	 */
	struct webserver_connection_t *connection = (struct webserver_connection_t *)heap_alloc_and_zero(sizeof(struct webserver_connection_t), PKG_OS, MEM_TYPE_OS_WEBSERVER_CONNECTION);
	if (!connection) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	connection->webserver = webserver;
	connection->http_connection = http_connection;
	connection->conn = http_server_connection_get_tcp_connection(http_connection);
	connection->method = method;

	size_t len = strlen(uri);
	connection->uri_nb = netbuf_alloc_with_rev_space(len);
	if (!connection->uri_nb) {
		DEBUG_ERROR("out of memory");
		heap_free(connection);
		return false;
	}

	netbuf_rev_write(connection->uri_nb, uri, len);

	/*
	 * Add connection to list.
	 */
	webserver_add_connection(webserver, connection);

	/*
	 * Accept connection.
	 */
	http_server_connection_set_http_tag_list(http_connection, webserver_connection_http_tag_list, connection);
	http_server_connection_accept(http_connection, webserver_connection_http_event, webserver_connection_send_resume, webserver_connection_tcp_close, connection);

	/*
	 * Validate method.
	 */
	switch (method) {
	case HTTP_SERVER_CONNECTION_METHOD_GET:
	case HTTP_SERVER_CONNECTION_METHOD_HEAD:
	case HTTP_SERVER_CONNECTION_METHOD_POST:
		break;

	default:
		webserver_connection_send_error(connection, http_result_bad_request);
		webserver_connection_free(connection);
		break;
	}

	return true;
}
