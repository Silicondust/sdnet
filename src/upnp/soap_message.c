/*
 * soap_message.c
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

THIS_FILE("soap_message");

static const char soap_message_prefix_xml[] =
	"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>"
	"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	"<soap:Body>"
	"<u:%s%s xmlns:u=\"%s\">";

static const char soap_message_suffix_xml[] =
	"</u:%s%s>"
	"</soap:Body>"
	"</soap:Envelope>";

static const char soap_message_error_xml[] =
	"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>"
	"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	"<soap:Body>"
	"<soap:Fault>"
	"<faultcode>soap:Client</faultcode>"
	"<faultstring>UPnPError</faultstring>"
	"<detail>"
	"<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">"
	"<errorCode>%u</errorCode>"
	"<errorDescription>%s</errorDescription>"
	"</UPnPError>"
	"</detail>"
	"</soap:Fault>"
	"</soap:Body>"
	"</soap:Envelope>";

bool soap_message_add_property_nb_no_escape(struct netbuf *txnb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");

	if (!netbuf_sprintf(txnb, "<%s>", name)) {
		return false;
	}

	size_t len = netbuf_get_remaining(val_nb);
	if (len > 0) {
		if (!netbuf_fwd_make_space(txnb, len)) {
			return false;
		}

		netbuf_fwd_copy(txnb, val_nb, len);
	}

	return netbuf_sprintf(txnb, "</%s>", name);
}

bool soap_message_add_property_nb_escape(struct netbuf *txnb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");
	size_t len = netbuf_get_remaining(val_nb);

	char *val = (char *)heap_alloc(len + 1, PKG_OS, MEM_TYPE_OS_SOAP_MESSAGE_STR);
	if (!val) {
		return false;
	}

	if (len > 0) {
		netbuf_fwd_read(val_nb, val, len);
	}

	val[len] = 0;
	bool success = soap_message_add_property_sprintf(txnb, name, "%s", val);
	heap_free(val);

	return success;
}

bool soap_message_add_property_nb_encode_base64(struct netbuf *txnb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");

	bool success = true;
	success &= netbuf_sprintf(txnb, "<%s>", name);
	success &= base64_encode_netbuf_to_netbuf2(val_nb, netbuf_get_remaining(val_nb), txnb);
	success &= netbuf_sprintf(txnb, "</%s>", name);
	return success;
}

bool soap_message_add_property_sprintf(struct netbuf *txnb, const char *name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	bool success = true;
	success &= netbuf_sprintf(txnb, "<%s>", name);
	success &= netbuf_vsprintf_xml(txnb, fmt, ap);
	success &= netbuf_sprintf(txnb, "</%s>", name);

	va_end(ap);
	return success;
}

soap_action_result_t soap_message_add_var_property_nb_no_escape(struct netbuf *txnb, struct netbuf *val_nb)
{
	bool success = soap_message_add_property_nb_no_escape(txnb, "return", val_nb);
	return (success) ? SOAP_ACTION_RESULT_SUCCESS : soap_action_result_error_out_of_memory(__this_file, __LINE__);
}

soap_action_result_t soap_message_add_var_property_nb_escape(struct netbuf *txnb, struct netbuf *val_nb)
{
	bool success = soap_message_add_property_nb_escape(txnb, "return", val_nb);
	return (success) ? SOAP_ACTION_RESULT_SUCCESS : soap_action_result_error_out_of_memory(__this_file, __LINE__);
}

soap_action_result_t soap_message_add_var_property_nb_encode_base64(struct netbuf *txnb, struct netbuf *val_nb)
{
	bool success = soap_message_add_property_nb_encode_base64(txnb, "return", val_nb);
	return (success) ? SOAP_ACTION_RESULT_SUCCESS : soap_action_result_error_out_of_memory(__this_file, __LINE__);
}

soap_action_result_t soap_message_add_var_property_sprintf(struct netbuf *txnb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	bool success = true;
	success &= netbuf_sprintf(txnb, "<return>");
	success &= netbuf_vsprintf_xml(txnb, fmt, ap);
	success &= netbuf_sprintf(txnb, "</return>");

	va_end(ap);
	return (success) ? SOAP_ACTION_RESULT_SUCCESS : soap_action_result_error_out_of_memory(__this_file, __LINE__);
}

bool soap_message_request_begin(struct netbuf *txnb, const char *urn, const char *action_name)
{
	return netbuf_sprintf(txnb, soap_message_prefix_xml, action_name, "", urn);
}

bool soap_message_request_end(struct netbuf *txnb, const char *action_name)
{
	bool success = netbuf_sprintf(txnb, soap_message_suffix_xml, action_name, "");
	netbuf_set_pos_to_start(txnb);
	return success;
}

bool soap_message_response_begin(struct netbuf *txnb, struct soap_service_connection_t *connection)
{
	return netbuf_sprintf(txnb, soap_message_prefix_xml, connection->action->action_name, "Response", connection->service->urn);
}

bool soap_message_response_end(struct netbuf *txnb, struct soap_service_connection_t *connection)
{
	bool success = netbuf_sprintf(txnb, soap_message_suffix_xml, connection->action->action_name, "Response");
	netbuf_set_pos_to_start(txnb);
	return success;
}

bool soap_message_response_error(struct netbuf *txnb, const char *soap_result_str)
{
	uint16_t soap_error_val = (uint16_t)strtoul(soap_result_str, NULL, 10);
	DEBUG_ASSERT(soap_error_val != 0, "invalue soap_error_str %s", soap_result_str);

	const char *soap_error_str = strchr(soap_result_str, ' ');
	DEBUG_ASSERT(soap_error_str, "invalue soap_error_str %s", soap_result_str);
	soap_result_str++;

	bool success = netbuf_sprintf(txnb, soap_message_error_xml, soap_error_val, soap_error_str);
	netbuf_set_pos_to_start(txnb);
	return success;
}
