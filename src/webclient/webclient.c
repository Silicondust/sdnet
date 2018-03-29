/*
 * ./src/webclient/webclient.c
 *
 * Copyright © 2014-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("webclient");

#define WEBCLIENT_CONNECTION_TIMEOUT (30 * TICK_RATE)
#define WEBCLIENT_USE_EXPECT_100_CONTINUE 0

struct webclient_connection_t {
	struct url_t url;
	char *additional_header_lines;
	struct dns_lookup_t *dns_lookup;
	struct tcp_connection *conn;
	struct https_client_t *https_client;
	struct http_parser_t *http_parser;
	const struct http_parser_tag_lookup_t *http_tag_list;
	struct oneshot timer;
	size_t max_recv_nb_size;
	uint16_t http_result;
	int refs;

	webclient_connection_post_callback_t post_callback;
	webclient_connection_data_callback_t data_callback;
	webclient_connection_complete_callback_t complete_callback;
	void *callback_arg;
};

static void webclient_connection_ref_internal(struct webclient_connection_t *connection)
{
	connection->refs++;
}

static int webclient_connection_deref_internal(struct webclient_connection_t *connection)
{
	connection->refs--;
	if (connection->refs != 0) {
		return connection->refs;
	}

	DEBUG_ASSERT(!connection->dns_lookup, "deref free with active session");
	DEBUG_ASSERT(!connection->conn, "deref free with active session");
	DEBUG_ASSERT(!connection->http_parser, "deref free with active session");

	if (connection->additional_header_lines) {
		heap_free(connection->additional_header_lines);
	}
		
	heap_free(connection);
	return 0;
}

void webclient_connection_release(struct webclient_connection_t *connection)
{
	connection->post_callback = NULL;
	connection->data_callback = NULL;
	connection->complete_callback = NULL;

	oneshot_detach(&connection->timer);

	if (connection->dns_lookup) {
		dns_lookup_deref(connection->dns_lookup);
		connection->dns_lookup = NULL;
	}

	if (connection->conn) {
		tcp_connection_close(connection->conn);
		tcp_connection_deref(connection->conn);
		connection->conn = NULL;
	}

	if (connection->http_parser) {
		http_parser_set_tag_list(connection->http_parser, NULL, NULL);
		http_parser_deref(connection->http_parser);
		connection->http_parser = NULL;
	}

	webclient_connection_deref_internal(connection);
}

static void webclient_connection_signal_complete(struct webclient_connection_t *connection, uint8_t result, uint16_t http_error, const char *error_str)
{
	webclient_connection_ref_internal(connection);

	if (connection->complete_callback) {
		connection->complete_callback(connection->callback_arg, connection, result, http_error, error_str);
	}

	if (webclient_connection_deref_internal(connection) != 0) {
		DEBUG_WARN("app failed to release connection in complete callback");
	}
}

static void webclient_connection_timeout(void *arg)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;
	DEBUG_WARN("webclient_connection_timeout");

	webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_TIMEOUT, 0, "timeout");
}

static void webclient_connection_conn_close(void *arg, tcp_close_reason_t reason)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;

	tcp_connection_deref(connection->conn);
	connection->conn = NULL;

	if (!http_parser_is_valid_complete(connection->http_parser)) {
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_EARLY_CLOSE, 0, "early close");
		return;
	}

	webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_SUCCESS, 0, "success");
}

static http_parser_error_t webclient_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;
	char error_str[20];

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		connection->http_result = (uint16_t)netbuf_fwd_strtoul(nb, NULL, 10);
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		if (connection->post_callback && WEBCLIENT_USE_EXPECT_100_CONTINUE && (connection->http_result == 100)) {
			DEBUG_TRACE("webclient_connection_http_event: 100");
			http_parser_reset(connection->http_parser);

			webclient_connection_ref_internal(connection);
			connection->post_callback(connection->callback_arg, connection);
			webclient_connection_deref_internal(connection);
			return HTTP_PARSER_ESTOP;
		}

		if (connection->http_result == 200) {
			DEBUG_TRACE("webclient_connection_http_event: 200");
			return HTTP_PARSER_OK;
		}

		DEBUG_WARN("webclient_connection_http_event: non-ok status code");
		sprintf_custom(error_str, error_str + sizeof(error_str), "http error %u", connection->http_result);
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_NON_200_RESULT, connection->http_result, error_str);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_DATA:
		webclient_connection_ref_internal(connection);
		if (connection->data_callback) {
			connection->data_callback(connection->callback_arg, connection, nb);
		}
		if (webclient_connection_deref_internal(connection) == 0) {
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		DEBUG_INFO("webclient_connection_http_event: data complete");
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_SUCCESS, 0, "success");
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("webclient_connection_http_event: error");
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_HTTP_PARSE_ERROR, 0, "parse error");
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void webclient_connection_conn_recv(void *arg, struct netbuf *nb)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;
	DEBUG_TRACE("webclient_connection_conn_recv");
	http_parser_recv_netbuf(connection->http_parser, nb);
}

static void webclient_connection_conn_established(void *arg)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;
	DEBUG_INFO("webclient_connection_conn_established");

	struct netbuf *header_nb = netbuf_alloc();
	if (!header_nb) {
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_SEND_FAILED, 0, "send failed");
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(header_nb, "%s %s HTTP/1.1\r\n", (connection->post_callback) ? "POST" : "GET", connection->url.uri);
	if (connection->url.flags & URL_FLAGS_PORT_SPECIFIED) {
		success &= netbuf_sprintf(header_nb, "HOST: %s:%u\r\n", connection->url.dns_name, connection->url.ip_port);
	} else {
		success &= netbuf_sprintf(header_nb, "HOST: %s\r\n", connection->url.dns_name);
	}
	if (connection->post_callback && WEBCLIENT_USE_EXPECT_100_CONTINUE) {
		success &= netbuf_sprintf(header_nb, "EXPECT: 100-Continue\r\n");
	}
	if (connection->post_callback) {
		success &= netbuf_sprintf(header_nb, "TRANSFER-ENCODING: chunked\r\n");
	}
	if (connection->additional_header_lines) {
		success &= netbuf_sprintf(header_nb, "%s", connection->additional_header_lines);
	}
	success &= netbuf_sprintf(header_nb, "CONNECTION: close\r\n");
	success &= netbuf_sprintf(header_nb, "\r\n");
	if (!success) {
		netbuf_free(header_nb);
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_SEND_FAILED, 0, "send failed");
		return;
	}

	netbuf_set_pos_to_start(header_nb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, header_nb);
	netbuf_free(header_nb);
	if (tcp_error != TCP_OK) {
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_SEND_FAILED, 0, "send failed");
		return;
	}

	if (connection->post_callback && !WEBCLIENT_USE_EXPECT_100_CONTINUE) {
		webclient_connection_ref_internal(connection);
		connection->post_callback(connection->callback_arg, connection);
		webclient_connection_deref_internal(connection);
	}
}

static bool webclient_connection_execute_connect(struct webclient_connection_t *connection)
{
	connection->http_parser = http_parser_alloc(webclient_connection_http_event, connection);
	if (!connection->http_parser) {
		return false;
	}

	http_parser_set_tag_list(connection->http_parser, connection->http_tag_list, connection->callback_arg);

	connection->conn = tcp_connection_alloc();
	if (!connection->conn) {
		DEBUG_WARN("out of memory");
		return false;
	}

	if (connection->max_recv_nb_size != 0) {
		tcp_connection_set_max_recv_nb_size(connection->conn, connection->max_recv_nb_size);
	}

	if (tcp_connection_connect(connection->conn, connection->url.ip_addr, connection->url.ip_port, 0, 0, webclient_connection_conn_established, webclient_connection_conn_recv, NULL, webclient_connection_conn_close, connection) != TCP_OK) {
		DEBUG_WARN("connect failed");
		tcp_connection_deref(connection->conn);
		connection->conn = NULL;
		return false;
	}

	return true;
}

static void webclient_connection_execute_dns_callback(void *arg, ipv4_addr_t ip, ticks_t expire_time)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)arg;

	dns_lookup_deref(connection->dns_lookup);
	connection->dns_lookup = NULL;

	if (ip == 0) {
		DEBUG_WARN("dns failed");
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_DNS_FAILED, 0, "dns failed");
		return;
	}

	connection->url.ip_addr = ip;

	if (!webclient_connection_execute_connect(connection)) {
		webclient_connection_signal_complete(connection, WEBCLIENT_RESULT_CONNECT_FAILED, 0, "connect failed");
		return;
	}
}

static bool webclient_connection_execute_dns(struct webclient_connection_t *connection)
{
	connection->dns_lookup = dns_lookup_alloc();
	if (!connection->dns_lookup) {
		DEBUG_WARN("out of memory");
		return false;
	}

	if (!dns_lookup_gethostbyname(connection->dns_lookup, connection->url.dns_name, webclient_connection_execute_dns_callback, connection)) {
		DEBUG_WARN("dns failed");
		return false;
	}

	return true;
}

bool webclient_connection_can_post_data(struct webclient_connection_t *connection)
{
	return tcp_connection_can_send(connection->conn) == TCP_OK;
}

bool webclient_connection_post_data(struct webclient_connection_t *connection, struct netbuf *txnb, bool end)
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
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, txnb);
	if (tcp_error != TCP_OK) {
		DEBUG_ERROR("tcp error");
		return false;
	}

	return true;
}

ipv4_addr_t webclient_connection_get_local_ip(struct webclient_connection_t *connection)
{
	return tcp_connection_get_local_addr(connection->conn);
}

ticks_t webclient_connection_get_timeout_time_remaining(struct webclient_connection_t *connection)
{
	return oneshot_get_ticks_remaining(&connection->timer);
}

void webclient_connection_set_timeout(struct webclient_connection_t *connection, ticks_t timeout)
{
	oneshot_detach(&connection->timer);
	if (timeout == TICKS_INFINITE) {
		return;
	}

	oneshot_attach(&connection->timer, timeout, webclient_connection_timeout, connection);
}

void webclient_connection_set_max_recv_nb_size(struct webclient_connection_t *connection, size_t max_recv_nb_size)
{
	connection->max_recv_nb_size = max_recv_nb_size;

	if (connection->conn) {
		tcp_connection_set_max_recv_nb_size(connection->conn, max_recv_nb_size);
	}
}

void webclient_connection_set_callback_arg(struct webclient_connection_t *connection, void *callback_arg)
{
	connection->callback_arg = callback_arg;
}

struct webclient_connection_t *webclient_connection_execute_post(struct url_t *url, const char *additional_header_lines, webclient_connection_post_callback_t post_callback, const struct http_parser_tag_lookup_t *http_tag_list, webclient_connection_data_callback_t data_callback, webclient_connection_complete_callback_t complete_callback, void *callback_arg)
{
	struct webclient_connection_t *connection = (struct webclient_connection_t *)heap_alloc_and_zero(sizeof(struct webclient_connection_t), PKG_OS, MEM_TYPE_OS_WEBCLIENT_CONNECTION);
	if (!connection) {
		DEBUG_WARN("out of memory");
		return NULL;
	}

	connection->refs = 1;
	connection->url = *url;
	connection->post_callback = post_callback;
	connection->http_tag_list = http_tag_list;
	connection->data_callback = data_callback;
	connection->complete_callback = complete_callback;
	connection->callback_arg = callback_arg;

	if (additional_header_lines) {
		connection->additional_header_lines = heap_strdup(additional_header_lines, PKG_OS, MEM_TYPE_OS_WEBCLIENT_CONNECTION_STR);
		if (!connection->additional_header_lines) {
			heap_free(connection);
			return NULL;
		}
	}

	oneshot_init(&connection->timer);
	oneshot_attach(&connection->timer, WEBCLIENT_CONNECTION_TIMEOUT, webclient_connection_timeout, connection);

	if (connection->url.ip_addr == 0) {
		if (!webclient_connection_execute_dns(connection)) {
			webclient_connection_release(connection);
			return NULL;
		}
	} else {
		if (!webclient_connection_execute_connect(connection)) {
			webclient_connection_release(connection);
			return NULL;
		}
	}

	return connection;
}

struct webclient_connection_t *webclient_connection_execute_get(struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_connection_data_callback_t data_callback, webclient_connection_complete_callback_t complete_callback, void *callback_arg)
{
	return webclient_connection_execute_post(url, additional_header_lines, NULL, http_tag_list, data_callback, complete_callback, callback_arg);
}

