/*
 * soap.h
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define SOAP_SERVER_NAME UPNP_SERVER_NAME

typedef enum {
	SOAP_ACTION_RESULT_ERROR = 0,
	SOAP_ACTION_RESULT_SUCCESS,
	SOAP_ACTION_RESULT_PAUSE,
} soap_action_result_t;

struct soap_service_t;
struct soap_service_connection_t;
struct soap_action_args_t;
struct soap_client_t;

typedef soap_action_result_t (*soap_action_handler_t)(void *arg, struct soap_service_connection_t *connection, struct soap_action_args_t *action_args, struct netbuf *txnb);
typedef soap_action_result_t (*soap_var_handler_t)(void *arg, struct soap_service_connection_t *connection, struct netbuf *txnb);
typedef void (*soap_client_result_t)(void *arg, uint16_t upnp_result, struct soap_action_args_t *action_args);

struct soap_action_descriptor_t {
	const char *action_name;
	soap_action_handler_t action_handler;
};

struct soap_var_descriptor_t {
	const char *var_name;
	soap_var_handler_t var_handler;
};

extern const char http_result_soap_error[];
extern const char soap_result_invalid_action[];
extern const char soap_result_invalid_args[];
extern const char soap_result_action_failed[];
extern const char soap_result_argument_value_invalid[];
extern const char soap_result_argument_value_out_of_range[];

extern void soap_service_manager_init(struct http_server_t *http_server);
extern uint16_t soap_service_manager_get_port(void);
extern struct soap_service_t *soap_service_manager_add_service(const char *uri, const char *urn, const struct soap_action_descriptor_t *action_list, const struct soap_var_descriptor_t *var_list, void *callback_arg);

extern struct soap_service_connection_t *soap_service_connection_ref(struct soap_service_connection_t *connection);
extern ref_t soap_service_connection_deref(struct soap_service_connection_t *connection);
extern bool soap_service_connection_can_send(struct soap_service_connection_t *connection);
extern void soap_service_connection_get_local_ip(struct soap_service_connection_t *connection, ip_addr_t *result);
extern void soap_service_connection_get_remote_ip(struct soap_service_connection_t *connection, ip_addr_t *result);
extern void *soap_service_connection_get_action_callback_arg(struct soap_service_connection_t *connection);

extern bool soap_action_args_get_bool(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern uint8_t soap_action_args_get_u8(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern uint16_t soap_action_args_get_u16(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern uint32_t soap_action_args_get_u32(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern int32_t soap_action_args_get_s32(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern const char *soap_action_args_get_string(struct soap_action_args_t *action_args, const char *name, bool *psuccess);
extern struct netbuf *soap_action_args_string_to_netbuf(const char *str);

extern soap_action_result_t soap_var_a_arg_type(void *arg, struct soap_service_connection_t *connection, struct netbuf *txnb);

extern soap_action_result_t soap_action_result_error(struct soap_service_connection_t *connection, const char *soap_result);
extern soap_action_result_t soap_action_result_error_out_of_memory(const char *file, unsigned int line);
extern void soap_action_resume(struct soap_service_connection_t *connection, soap_action_handler_t action_handler);
extern void soap_action_resume_send_custom_complete_response(struct soap_service_connection_t *connection, struct netbuf *txnb);
extern void soap_action_resume_error(struct soap_service_connection_t *connection, const char *soap_result);

extern bool soap_action_raw_send_header(struct soap_service_connection_t *connection);
extern bool soap_action_raw_send_data(struct soap_service_connection_t *connection, struct netbuf *txnb);
extern bool soap_action_raw_send_last(struct soap_service_connection_t *connection, struct netbuf *txnb);
extern void soap_action_raw_complete(struct soap_service_connection_t *connection, soap_action_result_t result);

extern bool soap_message_request_begin(struct netbuf *txnb, const char *urn, const char *action_name);
extern bool soap_message_request_end(struct netbuf *txnb, const char *action_name);
extern bool soap_message_response_begin(struct netbuf *txnb, struct soap_service_connection_t *connection);
extern bool soap_message_response_end(struct netbuf *txnb, struct soap_service_connection_t *connection);
extern bool soap_message_response_error(struct netbuf *txnb, const char *soap_result_str);
extern bool soap_message_add_property_nb_no_escape(struct netbuf *txnb, const char *name, struct netbuf *val_nb);
extern bool soap_message_add_property_nb_escape(struct netbuf *txnb, const char *name, struct netbuf *val_nb);
extern bool soap_message_add_property_nb_encode_base64(struct netbuf *txnb, const char *name, struct netbuf *val_nb);
extern bool soap_message_add_property_sprintf(struct netbuf *txnb, const char *name, const char *fmt, ...);
extern soap_action_result_t soap_message_add_var_property_nb_no_escape(struct netbuf *txnb, struct netbuf *val_nb);
extern soap_action_result_t soap_message_add_var_property_nb_escape(struct netbuf *txnb, struct netbuf *val_nb);
extern soap_action_result_t soap_message_add_var_property_nb_encode_base64(struct netbuf *txnb, struct netbuf *val_nb);
extern soap_action_result_t soap_message_add_var_property_sprintf(struct netbuf *txnb, const char *fmt, ...);

extern struct soap_client_t *soap_client_alloc(struct url_t *url, const char *urn);
extern void soap_client_free(struct soap_client_t *client);
extern bool soap_client_invoke_action(struct soap_client_t *client, const char *action_name, struct netbuf *request_nb, soap_client_result_t callback, void *callback_arg);

/* Internal. */
#define SOAP_SERVICE_CONNECTION_COMPLETE_RESOURCE_ERROR 10
#define SOAP_SERVICE_CONNECTION_COMPLETE_TCP_CLOSE 11
#define SOAP_SERVICE_CONNECTION_COMPLETE_TCP_ERROR 12
#define SOAP_SERVICE_CONNECTION_COMPLETE_ACTION_RESUME_TERMINATE 13

#define SOAP_SERVICE_CONNECTION_COMPLETE_TCP_ESTABLISH 200
#define SOAP_SERVICE_CONNECTION_COMPLETE_TCP_RECV 201
#define SOAP_SERVICE_CONNECTION_COMPLETE_RECV_HEADER_COMPLETE 202
#define SOAP_SERVICE_CONNECTION_COMPLETE_RECV_PAYLOAD_COMPLETE 203
#define SOAP_SERVICE_CONNECTION_COMPLETE_SEND_HEADER_OK 204
#define SOAP_SERVICE_CONNECTION_COMPLETE_SEND_PARTIAL_OK 205
#define SOAP_SERVICE_CONNECTION_COMPLETE_OK 255

typedef enum {
	SOAP_XML_PARSER_RESULT_OK = 0,
	SOAP_XML_PARSER_RESULT_ENOMEM,
	SOAP_XML_PARSER_RESULT_EPARSE
} soap_xml_parser_result_t;

struct soap_action_arg_t {
	struct slist_prefix_t slist_prefix;
	const char *name;
	const char *value;
};

struct soap_action_args_t {
	struct slist_t arg_list;
	soap_xml_parser_result_t parser_result;
	uint8_t parser_state;
	uint8_t parser_element_level;
	struct netbuf *parser_name_nb;
	struct netbuf_queue parser_value_nb_list;
};

struct soap_client_request_t {
	struct slist_prefix_t slist_prefix;
	char *action_name;
	struct netbuf *request_nb;
	soap_client_result_t callback;
	void *callback_arg;
};

struct soap_client_t {
	struct url_t url;
	char *urn;
	struct slist_t queue;
	struct oneshot timer;
	struct http_parser_t *http_parser;
	struct xml_parser_t *xml_parser;
	struct tcp_connection *conn;
	struct soap_action_args_t action_args;
	uint16_t upnp_result;
	uint8_t upnp_result_parser_state;
};

struct soap_service_t {
	struct slist_prefix_t slist_prefix;
	sha1_digest_t uri_hash;
	const char *urn;
	const struct soap_action_descriptor_t *action_list;
	const struct soap_var_descriptor_t *var_list;
	void *callback_arg;
};

struct soap_service_connection_t {
	struct slist_prefix_t slist_prefix;
	struct http_server_connection_t *http_connection;
	struct tcp_connection *conn;
	struct soap_service_t *service;
	struct xml_parser_t *xml_parser;
	const struct soap_action_descriptor_t *action;
	struct soap_action_args_t action_args;
	bool host_required;
	bool host_detected;
	bool continue_required;
	uint8_t complete;
	ref_t refs;
};

struct soap_service_manager_t {
	struct slist_t service_list;
	struct http_server_t *http_server;
};

extern struct soap_service_t *soap_service_manager_find_service_by_uri_hash(sha1_digest_t *uri_hash);
extern void soap_service_manager_query_state_variable_self_test(void);

extern struct soap_service_t *soap_service_alloc(const char *uri, const char *urn, const struct soap_action_descriptor_t *action_list, const struct soap_var_descriptor_t *var_list, void *callback_arg);
extern const struct soap_action_descriptor_t *soap_service_find_action(struct soap_service_t *service, const char *action_name);
extern const struct soap_var_descriptor_t *soap_service_find_var(struct soap_service_t *service, const char *var_name);

extern http_server_probe_result_t soap_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri);
extern void soap_service_connection_close_and_deref(struct soap_service_connection_t *connection);
extern bool soap_service_connection_send_http_header(struct soap_service_connection_t *connection, const char *http_result_str, const char *content_type, size_t content_length);
extern bool soap_service_connection_send_payload(struct soap_service_connection_t *connection, struct netbuf *txnb);
extern void soap_service_connection_send_error_result(struct soap_service_connection_t *connection, const char *http_result_str, const char *soap_result_str);

extern void soap_action_args_release_and_reset(struct soap_action_args_t *action_args);
extern xml_parser_error_t soap_action_args_xml_parser_callback(struct soap_action_args_t *action_args, const char *action_name, xml_parser_event_t event, struct netbuf *nb);
extern bool soap_action_args_is_valid_complete(struct soap_action_args_t *action_args);

extern struct soap_action_descriptor_t soap_action_descriptor_query_state_variable;
extern void soap_action_execute(struct soap_service_connection_t *connection);
extern void soap_action_query_state_variable_self_test(const struct soap_var_descriptor_t *var, void *callback_arg);
