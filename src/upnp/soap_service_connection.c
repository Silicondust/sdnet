/*
 * ./src/upnp/soap_service_connection.c
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

THIS_FILE("soap_service_connection");

#define SOAP_SERVICE_MAX_SUBSCRIPTION_PERIOD 1800

const char http_result_soap_error[] = "500 UPnP SOAP Error";
const char soap_result_invalid_action[] = "401 Invalid Action";
const char soap_result_invalid_args[] = "402 Invalid Args";
const char soap_result_action_failed[] = "501 Action Failed";
const char soap_result_argument_value_invalid[] = "600 Argument Value Invalid";
const char soap_result_argument_value_out_of_range[] = "601 Argument Value Out of Range";

static http_parser_error_t soap_service_connection_http_tag_expect(void *arg, struct netbuf *nb);
static http_parser_error_t soap_service_connection_http_tag_host(void *arg, struct netbuf *nb);
static http_parser_error_t soap_service_connection_http_tag_soapaction(void *arg, struct netbuf *nb);

static const struct http_parser_tag_lookup_t soap_service_connection_http_tag_list[] = {
	{"EXPECT", soap_service_connection_http_tag_expect},
	{"HOST", soap_service_connection_http_tag_host},
	{"SOAPACTION", soap_service_connection_http_tag_soapaction},
	{NULL, NULL}
};

struct soap_service_connection_t *soap_service_connection_ref(struct soap_service_connection_t *connection)
{
	connection->refs++;
	return connection;
}

ref_t soap_service_connection_deref(struct soap_service_connection_t *connection)
{
	connection->refs--;
	if (connection->refs != 0) {
		return connection->refs;
	}

	if (connection->complete != SOAP_SERVICE_CONNECTION_COMPLETE_OK) {
		log_warning(log_class_upnp, "transaction did not complete %u (%s:%u)", connection->complete, __this_file, __LINE__);
	}

	DEBUG_ASSERT(!connection->conn, "connection still active on free");

	soap_action_args_release_and_reset(&connection->action_args);
	xml_parser_deref(connection->xml_parser);

	heap_free(connection);
	return 0;
}

void soap_service_connection_close_and_deref(struct soap_service_connection_t *connection)
{
	http_server_connection_close(connection->http_connection);
	connection->http_connection = NULL;
	connection->conn = NULL;

	soap_service_connection_deref(connection);
}

static void soap_service_connection_tcp_close_callback(void *arg)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;
	DEBUG_TRACE("connection close");

	upnp_error_tcp_unexpected_close(__this_file, __LINE__);
	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_TCP_CLOSE;

	connection->http_connection = NULL;
	connection->conn = NULL;

	soap_service_connection_deref(connection);
}

bool soap_service_connection_can_send(struct soap_service_connection_t *connection)
{
	return (tcp_connection_can_send(connection->conn) == TCP_OK);
}

/* all paths set connection->complete */
bool soap_service_connection_send_http_header(struct soap_service_connection_t *connection, const char *http_result_str, const char *content_type, size_t content_length)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		return false;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 %s\r\n", http_result_str);
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", SOAP_SERVER_NAME);
	success &= netbuf_sprintf(txnb, "Connection: close\r\n");
	success &= netbuf_sprintf(txnb, "Ext:\r\n");
	if (content_type) {
		success &= netbuf_sprintf(txnb, "Content-Type: %s\r\n", content_type);
	}
	if (content_length != 0xFFFFFFFF) {
		success &= netbuf_sprintf(txnb, "Content-Length: %u\r\n", content_length);
	}
	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		netbuf_free(txnb);
		return false;
	}

	netbuf_set_pos_to_start(txnb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, txnb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_TCP_ERROR;
		netbuf_free(txnb);
		return false;
	}

	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_SEND_HEADER_OK;
	netbuf_free(txnb);
	return true;
}

/* all paths set connection->complete */
bool soap_service_connection_send_payload(struct soap_service_connection_t *connection, struct netbuf *txnb)
{
	tcp_error_t tcp_error = tcp_connection_send_netbuf(connection->conn, txnb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_TCP_ERROR;
		return false;
	}

	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_OK;
	return true;
}

/* all paths set connection->complete */
void soap_service_connection_send_error_result(struct soap_service_connection_t *connection, const char *http_result_str, const char *soap_result_str)
{
	if (!soap_result_str) {
		if (!soap_service_connection_send_http_header(connection, http_result_str, http_content_type_xml, 0)) { /* connection->complete set */
			return;
		}
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_OK;
		return;
	}

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		return;
	}

	if (!soap_message_response_error(txnb, soap_result_str)) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		netbuf_free(txnb);
		return;
	}

	size_t content_length = netbuf_get_remaining(txnb);
	if (!soap_service_connection_send_http_header(connection, http_result_str, http_content_type_xml, content_length)) { /* connection->complete set */
		netbuf_free(txnb);
		return;
	}

	soap_service_connection_send_payload(connection, txnb); /* connection->complete set */
	netbuf_free(txnb);
}

static xml_parser_error_t soap_service_connection_xml_parser_callback(void *arg, xml_parser_event_t event, struct netbuf *nb)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;
	return soap_action_args_xml_parser_callback(&connection->action_args, connection->action->action_name, event, nb);
}

/* error paths set connection->complete */
static http_parser_error_t soap_service_connection_recv_payload(struct soap_service_connection_t *connection, struct netbuf *nb)
{
	xml_parser_recv_netbuf(connection->xml_parser, nb);

	switch (connection->action_args.parser_result) {
	case SOAP_XML_PARSER_RESULT_OK:
		return HTTP_PARSER_OK;

	case SOAP_XML_PARSER_RESULT_ENOMEM:
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;

	default:
	case SOAP_XML_PARSER_RESULT_EPARSE:
		soap_service_connection_send_error_result(connection, http_result_soap_error, soap_result_invalid_args); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;
	}
}

static http_parser_error_t soap_service_connection_http_tag_expect(void *arg, struct netbuf *nb)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;

	if (netbuf_fwd_strcasecmp(nb, "100-continue") != 0) {
		DEBUG_WARN("unexpected expect value");
		return HTTP_PARSER_OK;
	}

	connection->continue_required = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t soap_service_connection_http_tag_host(void *arg, struct netbuf *nb)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;
	connection->host_detected = true;
	return HTTP_PARSER_OK;
}

/* error paths set connection->complete */
static http_parser_error_t soap_service_connection_http_tag_soapaction(void *arg, struct netbuf *nb)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;

	addr_t start_pos = netbuf_fwd_strchr(nb, '#');
	if (!start_pos) {
		DEBUG_WARN("soap action invalid");
		return HTTP_PARSER_OK;
	}
	start_pos += 1; /* Skip hash char */

	addr_t end_pos = netbuf_get_end(nb) - 1; /* Skip trailing quote char */
	if (start_pos > end_pos) {
		DEBUG_WARN("soap action invalid");
		return HTTP_PARSER_OK;
	}

	netbuf_set_pos(nb, end_pos);
	if (netbuf_fwd_read_u8(nb) != '\"') {
		DEBUG_WARN("soap action invalid");
		return HTTP_PARSER_OK;
	}

	size_t length = end_pos - start_pos;

	char action_name[128];
	if (length >= sizeof(action_name)) {
		DEBUG_WARN("soap action name too long");
		soap_service_connection_send_error_result(connection, http_result_soap_error, soap_result_invalid_action); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;
	}

	netbuf_set_pos(nb, start_pos);
	netbuf_fwd_read(nb, action_name, length);
	action_name[length] = 0;

	struct soap_service_t *service = connection->service;
	connection->action = soap_service_find_action(service, action_name);
	if (!connection->action) {
		DEBUG_WARN("unknown action %s", action_name);
		soap_service_connection_send_error_result(connection, http_result_soap_error, soap_result_invalid_action); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;
	}

	return HTTP_PARSER_OK;
}

/* error paths set connection->complete */
static http_parser_error_t soap_service_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_PROTOCOL:
		if (netbuf_fwd_strcasecmp(nb, "HTTP") != 0) {
			DEBUG_WARN("bad protocol");
			soap_service_connection_send_error_result(connection, http_result_bad_request, NULL); /* connection->complete set */
			soap_service_connection_close_and_deref(connection);
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
			soap_service_connection_send_error_result(connection, http_result_bad_request, NULL); /* connection->complete set */
			soap_service_connection_close_and_deref(connection);
			return HTTP_PARSER_ESTOP;
		}
		if (!connection->service || !connection->action) {
			soap_service_connection_send_error_result(connection, http_result_bad_request, NULL); /* connection->complete set */
			soap_service_connection_close_and_deref(connection);
			return HTTP_PARSER_ESTOP;
		}

		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RECV_HEADER_COMPLETE;
		if (connection->continue_required) {
			if (!soap_service_connection_send_http_header(connection, http_result_continue, NULL, 0xFFFFFFFF)) { /* connection->complete set */
				soap_service_connection_close_and_deref(connection);
				return HTTP_PARSER_ESTOP;
			}
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA:
		return soap_service_connection_recv_payload(connection, nb); /* connection->complete set on error */

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		if (!soap_action_args_is_valid_complete(&connection->action_args)) {
			soap_service_connection_send_error_result(connection, http_result_bad_request, NULL); /* connection->complete set */
			soap_service_connection_close_and_deref(connection);
			return HTTP_PARSER_ESTOP;
		}
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RECV_PAYLOAD_COMPLETE;
		soap_action_execute(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
		soap_service_connection_send_error_result(connection, http_result_bad_request, NULL); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		soap_service_connection_send_error_result(connection, http_result_internal_server_error, NULL); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

ipv4_addr_t soap_service_connection_get_local_ip(struct soap_service_connection_t *connection)
{
	return tcp_connection_get_local_addr(connection->conn);
}

ipv4_addr_t soap_service_connection_get_remote_ip(struct soap_service_connection_t *connection)
{
	return tcp_connection_get_remote_addr(connection->conn);
}

void *soap_service_connection_get_action_callback_arg(struct soap_service_connection_t *connection)
{
	struct soap_service_t *service = connection->service;
	return service->callback_arg;
}

bool soap_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri)
{
	switch (method) {
	case HTTP_SERVER_CONNECTION_METHOD_POST:
		break;

	default:
		return false;
	}

	sha1_digest_t uri_hash;
	sha1_compute_digest(&uri_hash, (uint8_t *)uri, strlen(uri));

	struct soap_service_t *service = soap_service_manager_find_service_by_uri_hash(&uri_hash);
	if (!service) {
		return false;
	}

	/*
	 * Create connection object.
	 */
	struct soap_service_connection_t *connection = (struct soap_service_connection_t *)heap_alloc_and_zero(sizeof(struct soap_service_connection_t), PKG_OS, MEM_TYPE_OS_SOAP_SERVICE_CONNECTION);
	if (!connection) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	connection->xml_parser = xml_parser_alloc(soap_service_connection_xml_parser_callback, connection);
	if (!connection->xml_parser) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		heap_free(connection);
		return false;
	}

	connection->http_connection = http_connection;
	connection->conn = http_server_connection_get_tcp_connection(http_connection);
	connection->service = service;
	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_TCP_ESTABLISH;
	connection->refs = 1;

	/*
	 * Accept connection.
	 */
	http_server_connection_set_http_tag_list(http_connection, soap_service_connection_http_tag_list, connection);
	http_server_connection_accept(http_connection, soap_service_connection_http_event, NULL, soap_service_connection_tcp_close_callback, connection);
	return true;
}
