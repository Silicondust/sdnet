/*
 * gena_service_connection.c
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

THIS_FILE("gena_service_connection");

static http_parser_error_t gena_service_connection_http_tag_callback(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t gena_service_connection_http_tag_nt(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t gena_service_connection_http_tag_sid(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t gena_service_connection_http_tag_timeout(void *arg, const char *header, struct netbuf *nb);

static const struct http_parser_tag_lookup_t gena_service_connection_http_tag_list[] = {
	{"CALLBACK", gena_service_connection_http_tag_callback},
	{"NT", gena_service_connection_http_tag_nt},
	{"SID", gena_service_connection_http_tag_sid},
	{"TIMEOUT", gena_service_connection_http_tag_timeout},
	{NULL, NULL}
};

void gena_service_connection_free(struct gena_service_connection_t *connection)
{
	if (connection->http_connection) {
		http_server_connection_close(connection->http_connection);
	}

	if (connection->callback_uri) {
		heap_free(connection->callback_uri);
	}

	heap_free(connection);
}

static void gena_service_connection_tcp_close_callback(void *arg)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;
	DEBUG_TRACE("connection close");

	connection->http_connection = NULL;
	connection->conn = NULL;

	gena_service_connection_free(connection);
}

static void gena_service_connection_send_basic_result(struct gena_service_connection_t *connection, const char *result_str)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 %s\r\n", result_str);
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", GENA_SERVER_NAME);
	success &= netbuf_sprintf(txnb, "Connection: close\r\n");
	success &= netbuf_sprintf(txnb, "Content-Length: 0\r\n");
	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, txnb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_free(txnb);
}

static void gena_service_connection_send_subscribe_result(struct gena_service_connection_t *connection, struct guid *sid)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	char sid_str[37];
	guid_write_string(sid, sid_str);

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 %s\r\n", http_result_ok);
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", GENA_SERVER_NAME);
	success &= netbuf_sprintf(txnb, "Connection: close\r\n");
	success &= netbuf_sprintf(txnb, "SID: uuid:%s\r\n", sid_str);
	success &= netbuf_sprintf(txnb, "Timeout: Second-%u\r\n", connection->subscription_period);
	success &= netbuf_sprintf(txnb, "Content-Length: 0\r\n");
	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, txnb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_free(txnb);
}

static void gena_service_connection_subscribe_renew(struct gena_service_connection_t *connection)
{
	if (connection->callback_present || connection->nt_present) {
		DEBUG_WARN("invalid: sid present and callback or nt present");
		gena_service_connection_send_basic_result(connection, http_result_bad_request);
		return;
	}

	if (connection->precondition_failed) {
		DEBUG_WARN("precondition failed");
		gena_service_connection_send_basic_result(connection, http_result_precondition_failed);
		return;
	}

	struct gena_subscription_t *subscription = gena_service_find_subscription_by_sid(connection->service, &connection->sid);
	if (!subscription) {
		DEBUG_WARN("unknown subscription");
		gena_service_connection_send_basic_result(connection, http_result_precondition_failed);
		return;
	}

	DEBUG_INFO("renew subscription http://%v:%u%s for %us", subscription->callback_ip, subscription->callback_port, subscription->callback_uri, connection->subscription_period);
	gena_subscription_renew(subscription, connection->subscription_period);
	gena_service_connection_send_subscribe_result(connection, &subscription->sid);
}

static void gena_service_connection_subscribe(struct gena_service_connection_t *connection)
{
	if (connection->subscription_period == 0) {
		connection->subscription_period = connection->service->default_subscription_period;
	}
	if (connection->subscription_period > GENA_MAX_SUBSCRIPTION_PERIOD) {
		connection->subscription_period = GENA_MAX_SUBSCRIPTION_PERIOD;
	}

	if (connection->sid_present) {
		gena_service_connection_subscribe_renew(connection);
		return;
	}

	if (connection->precondition_failed || !connection->callback_present) {
		DEBUG_WARN("precondition failed or missing callback");
		gena_service_connection_send_basic_result(connection, http_result_precondition_failed);
		return;
	}

	DEBUG_INFO("new subscription http://%v:%u%s for %us", connection->callback_ip, connection->callback_port, connection->callback_uri, connection->subscription_period);
	ipv4_addr_t local_ip = tcp_connection_get_local_addr(connection->conn);
	struct gena_subscription_t *subscription = gena_subscription_accept(connection->service, local_ip, connection->callback_ip, connection->callback_port, connection->callback_uri, connection->subscription_period);
	if (!subscription) {
		gena_service_connection_send_basic_result(connection, http_result_internal_server_error);
		return;
	}

	gena_service_connection_send_subscribe_result(connection, &subscription->sid);
}

static void gena_service_connection_unsubscribe(struct gena_service_connection_t *connection)
{
	if (connection->callback_present || connection->nt_present) {
		DEBUG_WARN("invalid: sid present and callback or nt present");
		gena_service_connection_send_basic_result(connection, http_result_bad_request);
		return;
	}

	if (connection->precondition_failed || !connection->sid_present) {
		DEBUG_WARN("precondition failed or sid not present");
		gena_service_connection_send_basic_result(connection, http_result_precondition_failed);
		return;
	}

	struct gena_subscription_t *subscription = gena_service_find_subscription_by_sid(connection->service, &connection->sid);
	if (!subscription) {
		DEBUG_WARN("unknown subscription");
		gena_service_connection_send_basic_result(connection, http_result_ok);
		return;
	}

	DEBUG_INFO("unsubscribe http://%v:%u%s", subscription->callback_ip, subscription->callback_port, subscription->callback_uri);
	gena_subscription_unsubscribe(subscription);
	gena_service_connection_send_basic_result(connection, http_result_ok);
}

static void gena_service_connection_execute(struct gena_service_connection_t *connection)
{
	switch (connection->method) {
	case HTTP_SERVER_CONNECTION_METHOD_SUBSCRIBE:
		gena_service_connection_subscribe(connection);
		return;

	case HTTP_SERVER_CONNECTION_METHOD_UNSUBSCRIBE:
		gena_service_connection_unsubscribe(connection);
		return;

	default:
		gena_service_connection_send_basic_result(connection, http_result_bad_request);
		return;
	}
}

static bool gena_service_connection_http_tag_callback_parse(struct url_t *callback_url, struct netbuf *nb)
{
	if (!netbuf_fwd_check_space(nb, 2)) {
		return false;
	}

	/* Check for leading '<' */
	if (netbuf_fwd_read_u8(nb) != '<') {
		return false;
	}
	netbuf_set_start_to_pos(nb);

	/* Check for trailing '>' */
	netbuf_set_pos(nb, netbuf_get_end(nb) - 1);
	if (netbuf_fwd_read_u8(nb) != '>') {
		return false;
	}
	netbuf_set_pos_to_start(nb);
	netbuf_retreat_end(nb, 1);

	/* Parse URL */
	if (!url_parse_nb(callback_url, nb)) {
		return false;
	}
	if ((callback_url->ip_addr == 0) || (callback_url->ip_port == 0)) {
		return false;
	}

	/* Success */
	return true;
}

static http_parser_error_t gena_service_connection_http_tag_callback(void *arg, const char *header, struct netbuf *nb)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;
	connection->callback_present = true;

	if (connection->callback_uri) {
		DEBUG_WARN("callback uri repeated");
		return HTTP_PARSER_OK;
	}

	struct url_t callback_url;
	if (!gena_service_connection_http_tag_callback_parse(&callback_url, nb)) {
		DEBUG_WARN("unexpected callback format");
		connection->precondition_failed = true;
		return HTTP_PARSER_OK; /* Need to check bad-request error before reporting this error. */
	}

	connection->callback_ip = callback_url.ip_addr;
	connection->callback_port = callback_url.ip_port;
	connection->callback_uri = heap_strdup(callback_url.uri, PKG_OS, MEM_TYPE_OS_GENA_CONNECTION_CALLBACK_URI);
	if (!connection->callback_uri) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		gena_service_connection_free(connection);
		return HTTP_PARSER_ESTOP;
	}

	return HTTP_PARSER_OK;
}

static http_parser_error_t gena_service_connection_http_tag_nt(void *arg, const char *header, struct netbuf *nb)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;
	connection->nt_present = true;

	if (netbuf_fwd_strcasecmp(nb, "upnp:event") != 0) {
		DEBUG_WARN("unexpected nt value");
		connection->precondition_failed = true;
		return HTTP_PARSER_OK; /* Need to check bad-request error before reporting this error. */
	}

	return HTTP_PARSER_OK;
}

static http_parser_error_t gena_service_connection_http_tag_sid(void *arg, const char *header, struct netbuf *nb)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;
	connection->sid_present = true;

	if (netbuf_fwd_strncasecmp(nb, "uuid:", 5) != 0) {
		DEBUG_WARN("unexpected sid format");
		connection->precondition_failed = true;
		return HTTP_PARSER_OK; /* Need to check bad-request error before reporting this error. */
	}

	netbuf_advance_pos(nb, 5);
	if (!guid_read_netbuf(&connection->sid, nb)) {
		DEBUG_WARN("unexpected sid format");
		connection->precondition_failed = true;
		return HTTP_PARSER_OK; /* Need to check bad-request error before reporting this error. */
	}

	return HTTP_PARSER_OK;
}

static http_parser_error_t gena_service_connection_http_tag_timeout(void *arg, const char *header, struct netbuf *nb)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;

	if (netbuf_fwd_strncasecmp(nb, "second-", 7) != 0) {
		DEBUG_WARN("unexpected timeout format");
		return HTTP_PARSER_OK;
	}

	netbuf_advance_pos(nb, 7);

	if (!netbuf_sscanf(nb, "%u", &connection->subscription_period)) {
		DEBUG_WARN("unexpected timeout format:");
		DEBUG_PRINT_NETBUF_TEXT(nb, 0);
		return HTTP_PARSER_OK;
	}

	return HTTP_PARSER_OK;
}

static http_parser_error_t gena_service_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		if (!connection->method || !connection->service) {
			gena_service_connection_send_basic_result(connection, http_result_bad_request);
			gena_service_connection_free(connection);
			return HTTP_PARSER_ESTOP;
		}
		gena_service_connection_execute(connection);
		gena_service_connection_free(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
		gena_service_connection_send_basic_result(connection, http_result_bad_request);
		gena_service_connection_free(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		gena_service_connection_send_basic_result(connection, http_result_internal_server_error);
		gena_service_connection_free(connection);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

bool gena_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri)
{
	switch (method) {
	case HTTP_SERVER_CONNECTION_METHOD_SUBSCRIBE:
	case HTTP_SERVER_CONNECTION_METHOD_UNSUBSCRIBE:
		break;

	default:
		return false;
	}

	sha1_digest_t uri_hash;
	sha1_compute_digest(&uri_hash, (uint8_t *)uri, strlen(uri));

	struct gena_service_t *service = gena_service_manager_find_service_by_uri_hash(&uri_hash);
	if (!service) {
		return false;
	}

	/*
	 * Create connection object.
	 */
	struct gena_service_connection_t *connection = (struct gena_service_connection_t *)heap_alloc_and_zero(sizeof(struct gena_service_connection_t), PKG_OS, MEM_TYPE_OS_GENA_SERVICE_CONNECTION);
	if (!connection) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	connection->http_connection = http_connection;
	connection->conn = http_server_connection_get_tcp_connection(http_connection);
	connection->service = service;
	connection->method = method;

	/*
	 * Accept connection.
	 */
	http_server_connection_set_http_tag_list(http_connection, gena_service_connection_http_tag_list, connection);
	http_server_connection_accept(http_connection, gena_service_connection_http_event, NULL, gena_service_connection_tcp_close_callback, connection);
	return true;
}
