/*
 * http_server.h
 *
 * Copyright © 2015-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct http_server_connection_t;
struct http_server_service_t;
struct http_server_t;

typedef enum {
	HTTP_SERVER_CONNECTION_METHOD_NONE = 0,
	HTTP_SERVER_CONNECTION_METHOD_GET,
	HTTP_SERVER_CONNECTION_METHOD_HEAD,
	HTTP_SERVER_CONNECTION_METHOD_POST,
	HTTP_SERVER_CONNECTION_METHOD_SUBSCRIBE,
	HTTP_SERVER_CONNECTION_METHOD_UNSUBSCRIBE,
} http_server_connection_method_t;

typedef enum {
	HTTP_SERVER_PROBE_RESULT_NO_MATCH = 0,
	HTTP_SERVER_PROBE_RESULT_MATCH,
	HTTP_SERVER_PROBE_RESULT_CLOSE,
} http_server_probe_result_t;

typedef http_server_probe_result_t (*http_server_service_probe_func_t)(void *arg, struct http_server_connection_t *connection, http_server_connection_method_t method, const char *uri);
typedef http_parser_error_t (*http_server_connection_http_event_func_t)(void *arg, http_parser_event_t event, struct netbuf *nb);
typedef void (*http_server_connection_send_resume_func_t)(void *arg);
typedef void (*http_server_connection_close_func_t)(void *arg);

extern struct http_server_t *http_server_instance_alloc(uint16_t port);
extern struct http_server_service_t *http_server_register_service(struct http_server_t *http_server, http_server_service_probe_func_t probe, void *callback_arg);
extern void http_server_network_reset(struct http_server_t *http_server);
extern uint16_t http_server_get_port(struct http_server_t *http_server);

extern void http_server_connection_accept(struct http_server_connection_t *connection, http_server_connection_http_event_func_t http_event, http_server_connection_send_resume_func_t send_resume, http_server_connection_close_func_t close, void *callback_arg);
extern void http_server_connection_close(struct http_server_connection_t *connection);
extern void http_server_connection_set_http_tag_list(struct http_server_connection_t *connection, const struct http_parser_tag_lookup_t *webserver_connection_http_tag_list, void *callback_arg);
extern void http_server_connection_disable_timeout(struct http_server_connection_t *connection);
extern ipv4_addr_t http_server_connection_get_remote_addr(struct http_server_connection_t *connection);
extern struct tcp_connection *http_server_connection_get_tcp_connection(struct http_server_connection_t *connection);

struct http_server_connection_t {
	struct slist_prefix_t slist_prefix;
	struct tcp_connection *conn;
	struct http_server_t *http_server;
	struct http_parser_t *http_parser;
	http_server_connection_method_t method;
	ticks_t connection_timeout;

	http_server_connection_http_event_func_t http_event;
	http_server_connection_send_resume_func_t send_resume;
	http_server_connection_close_func_t close;
	void *callback_arg;
};

struct http_server_service_t {
	struct slist_prefix_t slist_prefix;
	http_server_service_probe_func_t probe;
	void *callback_arg;
};

struct http_server_t {
	struct slist_t service_list;
	struct slist_t connection_list;
	struct oneshot connection_timer;
	struct tcp_socket *listen_sock;
};
