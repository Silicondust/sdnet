/*
 * soap_action.c
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

THIS_FILE("soap_action");

soap_action_result_t soap_action_result_error(struct soap_service_connection_t *connection, const char *soap_result)
{
	soap_service_connection_send_error_result(connection, http_result_soap_error, soap_result); /* connection->complete set */
	return SOAP_ACTION_RESULT_ERROR;
}

soap_action_result_t soap_action_result_error_out_of_memory(const char *file, unsigned int line)
{
	upnp_error_out_of_memory(file, line);
	return SOAP_ACTION_RESULT_ERROR;
}

bool soap_action_raw_send_header(struct soap_service_connection_t *connection)
{
	return soap_service_connection_send_http_header(connection, http_result_ok, http_content_type_xml, 0xFFFFFFFF);
}

bool soap_action_raw_send_data(struct soap_service_connection_t *connection, struct netbuf *txnb)
{
	netbuf_set_pos_to_start(txnb);
	if (!soap_service_connection_send_payload(connection, txnb)) {
		return false;
	}

	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_SEND_PARTIAL_OK;
	return true;
}

bool soap_action_raw_send_last(struct soap_service_connection_t *connection, struct netbuf *txnb)
{
	netbuf_set_pos_to_end(txnb);
	if (!soap_message_response_end(txnb, connection)) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		return false;
	}

	netbuf_set_pos_to_start(txnb);
	return soap_service_connection_send_payload(connection, txnb);
}

void soap_action_raw_complete(struct soap_service_connection_t *connection, soap_action_result_t result)
{
	if (result == SOAP_ACTION_RESULT_ERROR) {
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
	}

	soap_service_connection_close_and_deref(connection);
}

static soap_action_result_t soap_action_execute_internal(struct soap_service_connection_t *connection, soap_action_handler_t action_handler, struct netbuf *txnb)
{
	if (!soap_message_response_begin(txnb, connection)) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		return SOAP_ACTION_RESULT_ERROR;
	}

	struct soap_service_t *service = connection->service;
	soap_action_result_t ret = action_handler(service->callback_arg, connection, &connection->action_args, txnb);
	if (ret != SOAP_ACTION_RESULT_SUCCESS) {
		return ret;
	}

	if (!soap_message_response_end(txnb, connection)) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		return SOAP_ACTION_RESULT_ERROR;
	}

	netbuf_set_pos_to_start(txnb);
	size_t content_length = netbuf_get_remaining(txnb);

	if (!soap_service_connection_send_http_header(connection, http_result_ok, http_content_type_xml, content_length)) { /* connection->complete set */
		return SOAP_ACTION_RESULT_ERROR;
	}

	soap_service_connection_send_payload(connection, txnb); /* connection->complete set */
	return SOAP_ACTION_RESULT_SUCCESS;
}

void soap_action_resume_error(struct soap_service_connection_t *connection, const char *soap_result)
{
	if (soap_result) {
		soap_service_connection_send_error_result(connection, http_result_soap_error, soap_result); /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return;
	}

	connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_ACTION_RESUME_TERMINATE;
	soap_service_connection_close_and_deref(connection);
}

void soap_action_resume_send_custom_complete_response(struct soap_service_connection_t *connection, struct netbuf *txnb)
{
	netbuf_set_pos_to_start(txnb);
	size_t content_length = netbuf_get_remaining(txnb);

	if (!soap_service_connection_send_http_header(connection, http_result_ok, http_content_type_xml, content_length)) { /* connection->complete set */
		soap_service_connection_close_and_deref(connection);
		return;
	}

	soap_service_connection_send_payload(connection, txnb); /* connection->complete set */
	soap_service_connection_close_and_deref(connection);
}

void soap_action_resume(struct soap_service_connection_t *connection, soap_action_handler_t action_handler)
{
	const struct soap_action_descriptor_t *action = connection->action; 
	if (action != &soap_action_descriptor_query_state_variable) {
		DEBUG_INFO("action %s", action->action_name);
	}

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		connection->complete = SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR;
		soap_service_connection_close_and_deref(connection);
		return;
	}

	soap_action_result_t ret = soap_action_execute_internal(connection, action_handler, txnb);

	netbuf_free(txnb);

	if (ret != SOAP_ACTION_RESULT_PAUSE) {
		soap_service_connection_close_and_deref(connection);
	}
}

void soap_action_execute(struct soap_service_connection_t *connection)
{
	const struct soap_action_descriptor_t *action = connection->action; 
	soap_action_resume(connection, action->action_handler);
}

soap_action_result_t soap_var_a_arg_type(void *arg, struct soap_service_connection_t *connection, struct netbuf *txnb)
{
	return soap_message_add_var_property_sprintf(txnb, "");
}

static soap_action_result_t soap_action_query_state_variable(void *arg, struct soap_service_connection_t *connection, struct soap_action_args_t *action_args, struct netbuf *txnb)
{
	bool success = true;
	const char *var_name = soap_action_args_get_string(action_args, "varName", &success);
	if (!success) {
		DEBUG_WARN("QueryStateVariable invalid args");
		return soap_action_result_error(connection, soap_result_invalid_args); /* connection->complete set */
	}

	struct soap_service_t *service = connection->service;
	const struct soap_var_descriptor_t *var = soap_service_find_var(service, var_name);
	if (!var) {
		DEBUG_WARN("QueryStateVariable %s not found", var_name);
		return soap_action_result_error(connection, soap_result_argument_value_invalid); /* connection->complete set */
	}

	DEBUG_TRACE("QueryStateVariable %s", var_name);
	return var->var_handler(arg, connection, txnb);
}

struct soap_action_descriptor_t soap_action_descriptor_query_state_variable =
	{"QueryStateVariable", soap_action_query_state_variable};

void soap_action_query_state_variable_self_test(const struct soap_var_descriptor_t *var, void *callback_arg)
{
	DEBUG_TRACE("self test of var %s", var->var_name);

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	if (var->var_handler(callback_arg, NULL, txnb) != SOAP_ACTION_RESULT_SUCCESS) {
		DEBUG_ERROR("self test of var %s reported error", var->var_name);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	char *str = heap_netbuf_strdup(txnb, PKG_OS, MEM_TYPE_OS_SOAP_ACTION_VAR_NAME);
	if (!str) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	DEBUG_INFO("self test of var %s = %s", var->var_name, str);

	heap_free(str);
	netbuf_free(txnb);
}
