/*
 * soap_client.c
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

THIS_FILE("soap_client");

#define SOAP_CLIENT_MAX_REQUESTS_PENDING 8
#define SOAP_CLIENT_REQUEST_TIMEOUT (30 * TICK_RATE)

static void soap_client_request_start(void *arg);

static void soap_client_request_free(struct soap_client_request_t *request)
{
	if (request->request_nb) {
		netbuf_free(request->request_nb);
	}
	if (request->action_name) {
		heap_free(request->action_name);
	}

	heap_free(request);
}

void soap_client_free(struct soap_client_t *client)
{
	oneshot_detach(&client->timer);
	slist_clear(struct soap_client_request_t, &client->queue, soap_client_request_free);

	if (client->conn) {
		tcp_connection_reset(client->conn);
		tcp_connection_deref(client->conn);
	}
	if (client->xml_parser) {
		xml_parser_deref(client->xml_parser);
	}
	if (client->http_parser) {
		http_parser_deref(client->http_parser);
	}
	if (client->urn) {
		heap_free(client->urn);
	}

	heap_free(client);
}

static void soap_client_request_result(struct soap_client_t *client, uint16_t upnp_result, struct soap_action_args_t *action_args)
{
	oneshot_detach(&client->timer);

	if (client->conn) {
		tcp_connection_close(client->conn);
		tcp_connection_deref(client->conn);
		client->conn = NULL;
	}

	struct soap_client_request_t *request = slist_detach_head(struct soap_client_request_t, &client->queue);

	if (request->callback) {
		request->callback(request->callback_arg, upnp_result, action_args);
	}

	soap_client_request_free(request);
	soap_action_args_release_and_reset(&client->action_args);
	xml_parser_reset(client->xml_parser);
	http_parser_reset(client->http_parser);

	if (slist_get_head(struct soap_client_request_t, &client->queue) && !oneshot_is_attached(&client->timer)) {
		oneshot_attach(&client->timer, 0, soap_client_request_start, client);
	}
}

static void soap_client_request_error(struct soap_client_t *client)
{
	DEBUG_INFO("soap_client_request_error");
	soap_client_request_result(client, 0, NULL);
}

static void soap_client_request_timeout(void *arg)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;
	DEBUG_WARN("soap_client_request_timeout");

	soap_client_request_error(client);
}

static void soap_client_request_conn_close(void *arg, tcp_close_reason_t reason)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;

	tcp_connection_deref(client->conn);
	client->conn = NULL;

	if (!soap_action_args_is_valid_complete(&client->action_args)) {
		DEBUG_WARN("soap_client_request_conn_close: remote closed connection");
		soap_client_request_error(client);
		return;
	}

	DEBUG_INFO("soap_client_request_conn_close: success");
	soap_client_request_result(client, 200, &client->action_args);
}

static xml_parser_error_t soap_client_request_xml_parser_callback_fault_message(struct soap_client_t *client, xml_parser_event_t event, struct netbuf *nb)
{
	switch (event) {
	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		if (netbuf_fwd_strcmp(nb, "errorCode") == 0) {
			client->upnp_result_parser_state = 1;
			return XML_PARSER_OK;
		}

		client->upnp_result_parser_state = 0;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		client->upnp_result_parser_state = 0;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_TEXT:
		if (client->upnp_result_parser_state == 1) {
			client->upnp_result = (uint16_t)netbuf_fwd_strtoul(nb, NULL, 10);
			client->upnp_result_parser_state = 0;
			return XML_PARSER_OK;
		}

		return XML_PARSER_OK;

	case XML_PARSER_EVENT_INTERNAL_ERROR:
	case XML_PARSER_EVENT_PARSE_ERROR:
		return XML_PARSER_ESTOP;

	default:
		return XML_PARSER_OK;
	}
}

static xml_parser_error_t soap_client_request_xml_parser_callback(void *arg, xml_parser_event_t event, struct netbuf *nb)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;

	if (client->upnp_result != 200) {
		return soap_client_request_xml_parser_callback_fault_message(client, event, nb);
	}

	struct soap_client_request_t *request = slist_get_head(struct soap_client_request_t, &client->queue);
	return soap_action_args_xml_parser_callback(&client->action_args, request->action_name, event, nb);
}

static http_parser_error_t soap_client_request_conn_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		client->upnp_result = (uint16_t)netbuf_fwd_strtoul(nb, NULL, 10);
		DEBUG_TRACE("soap_client_request_conn_http_event: %u http status code", client->upnp_result);
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA:
		xml_parser_recv_netbuf(client->xml_parser, nb);
		if (client->action_args.parser_result != SOAP_XML_PARSER_RESULT_OK) {
			soap_client_request_error(client);
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
		if (client->upnp_result != 200) {
			soap_client_request_result(client, client->upnp_result, NULL);
			return HTTP_PARSER_ESTOP;
		}
		if (!soap_action_args_is_valid_complete(&client->action_args)) {
			soap_client_request_error(client);
			return HTTP_PARSER_ESTOP;
		}
		DEBUG_TRACE("soap_client_request_conn_http_event: success");
		soap_client_request_result(client, client->upnp_result, &client->action_args);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("soap_client_request_conn_http_event: error");
		soap_client_request_error(client);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void soap_client_request_conn_recv(void *arg, struct netbuf *nb)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;
	DEBUG_TRACE("soap_client_request_conn_recv");
	http_parser_recv_netbuf(client->http_parser, nb);
}

static void soap_client_request_conn_established(void *arg)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;
	DEBUG_ASSERT(slist_get_head(struct soap_client_request_t, &client->queue), "soap_client_request_conn_established called without request");
	DEBUG_TRACE("soap_client_request_conn_established");

	/*
	 * Header.
	 */
	struct netbuf *header_nb = netbuf_alloc();
	if (!header_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		soap_client_request_error(client);
		return;
	}

	struct soap_client_request_t *request = slist_get_head(struct soap_client_request_t, &client->queue);
	size_t content_length = netbuf_get_remaining(request->request_nb);

	bool success = true;
	success &= netbuf_sprintf(header_nb, "POST %s HTTP/1.1\r\n", client->url.uri);
	success &= netbuf_sprintf(header_nb, "Host: %v:%u\r\n", client->url.ip_addr, client->url.ip_port);
	success &= netbuf_sprintf(header_nb, "SOAPACTION: \"%s#%s\"\r\n", client->urn, request->action_name);
	success &= netbuf_sprintf(header_nb, "Content-Type: %s\r\n", http_content_type_xml);
	success &= netbuf_sprintf(header_nb, "Content-Length: %u\r\n", content_length);
	success &= netbuf_sprintf(header_nb, "Connection: close\r\n");
	success &= netbuf_sprintf(header_nb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(header_nb);
		soap_client_request_error(client);
		return;
	}

	netbuf_set_pos_to_start(header_nb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(client->conn, header_nb);
	netbuf_free(header_nb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		soap_client_request_error(client);
		return;
	}

	/*
	 * Content.
	 */
	tcp_error = tcp_connection_send_netbuf(client->conn, request->request_nb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		soap_client_request_error(client);
		return;
	}

	DEBUG_TRACE("soap_client_request_conn_established: send ok");
	netbuf_free(request->request_nb);
	request->request_nb = NULL;

	/*
	 * Switch the action name to the response name for use in the response processing.
	 */
	size_t action_response_name_size = strlen(request->action_name) + 9;
	char *action_response_name = heap_alloc(action_response_name_size, PKG_OS, MEM_TYPE_OS_SOAP_CLIENT_STR);
	if (!action_response_name) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		soap_client_request_error(client);
		return;
	}

	sprintf_custom(action_response_name, action_response_name + action_response_name_size, "%sResponse", request->action_name);
	heap_free(request->action_name);
	request->action_name = action_response_name;
}

static void soap_client_request_start(void *arg)
{
	struct soap_client_t *client = (struct soap_client_t *)arg;
	DEBUG_ASSERT(slist_get_head(struct soap_client_request_t, &client->queue), "soap_client_request_start called without request");

	oneshot_attach(&client->timer, SOAP_CLIENT_REQUEST_TIMEOUT, soap_client_request_timeout, client);

	client->conn = tcp_connection_alloc();
	if (!client->conn) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		soap_client_request_error(client);
		return;
	}

	if (tcp_connection_connect(client->conn, client->url.ip_addr, client->url.ip_port, 0, 0, soap_client_request_conn_established, soap_client_request_conn_recv, soap_client_request_conn_close, client) != TCP_OK) {
		DEBUG_WARN("connect failed");
		tcp_connection_deref(client->conn);
		client->conn = NULL;
		soap_client_request_error(client);
		return;
	}
}

bool soap_client_invoke_action(struct soap_client_t *client, const char *action_name, struct netbuf *request_nb, soap_client_result_t callback, void *callback_arg)
{
	struct soap_client_request_t *request = (struct soap_client_request_t *)heap_alloc_and_zero(sizeof(struct soap_client_request_t), PKG_OS, MEM_TYPE_OS_SOAP_CLIENT_REQUEST);
	if (!request) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	request->action_name = heap_strdup(action_name, PKG_OS, MEM_TYPE_OS_SOAP_CLIENT_STR);
	request->request_nb = netbuf_clone(request_nb);
	request->callback = callback;
	request->callback_arg = callback_arg;
	if (!request->action_name || !request->request_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		soap_client_request_free(request);
		return false;
	}

	if (!slist_attach_tail_limit(struct soap_client_request_t, &client->queue, request, SOAP_CLIENT_MAX_REQUESTS_PENDING)) {
		DEBUG_WARN("too many outstanding requests");
		soap_client_request_free(request);
		return false;
	}

	if (!oneshot_is_attached(&client->timer)) {
		oneshot_attach(&client->timer, 0, soap_client_request_start, client);
	}

	return true;
}

struct soap_client_t *soap_client_alloc(struct url_t *url, const char *urn)
{
	struct soap_client_t *client = (struct soap_client_t *)heap_alloc_and_zero(sizeof(struct soap_client_t), PKG_OS, MEM_TYPE_OS_SOAP_CLIENT);
	if (!client) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	client->url = *url;
	client->urn = heap_strdup(urn, PKG_OS, MEM_TYPE_OS_SOAP_CLIENT_STR);
	client->http_parser = http_parser_alloc(soap_client_request_conn_http_event, client);
	client->xml_parser = xml_parser_alloc(soap_client_request_xml_parser_callback, client);
	if (!client->urn || !client->http_parser || !client->xml_parser) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		soap_client_free(client);
		return NULL;
	}

	oneshot_init(&client->timer);

	return client;
}
