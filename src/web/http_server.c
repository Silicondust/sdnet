/*
 * http_server.c
 *
 * Copyright © 2015-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("http_server");

#define HTTP_SERVER_DEFAULT_CONNECTION_TIMEOUT (TICK_RATE * 10)

struct http_server_connection_method_lookup_t {
	const char *method_str;
	http_server_connection_method_t method;
};

static const struct http_server_connection_method_lookup_t http_server_connection_method_lookup[] =
{
	{ "GET", HTTP_SERVER_CONNECTION_METHOD_GET },
	{ "HEAD", HTTP_SERVER_CONNECTION_METHOD_HEAD },
	{ "POST", HTTP_SERVER_CONNECTION_METHOD_POST },
	{ "SUBSCRIBE", HTTP_SERVER_CONNECTION_METHOD_SUBSCRIBE },
	{ "UNSUBSCRIBE", HTTP_SERVER_CONNECTION_METHOD_UNSUBSCRIBE },
	{ NULL, HTTP_SERVER_CONNECTION_METHOD_NONE },
};

static void http_server_add_connection(struct http_server_t *http_server, struct http_server_connection_t *connection);

static void http_server_connection_free(struct http_server_connection_t *connection)
{
	struct http_server_t *http_server = connection->http_server;
	(void)slist_detach_item(struct http_server_connection_t, &http_server->connection_list, connection);

	if (connection->conn) {
		tcp_connection_close(connection->conn);
		tcp_connection_deref(connection->conn);
	}

	http_parser_deref(connection->http_parser);
	heap_free(connection);
}

static void http_server_connection_notify_close_and_free(struct http_server_connection_t *connection)
{
	if (connection->close) {
		connection->close(connection->callback_arg);
	}

	http_server_connection_free(connection);
}

static void http_server_connection_timeout(void *arg)
{
	struct http_server_t *http_server = (struct http_server_t *)arg;
	ticks_t current_time = timer_get_ticks();

	while (1) {
		struct http_server_connection_t *connection = slist_get_head(struct http_server_connection_t, &http_server->connection_list);
		if (!connection) {
			return;
		}

		if (connection->connection_timeout > current_time) {
			oneshot_attach(&http_server->connection_timer, connection->connection_timeout - current_time, http_server_connection_timeout, http_server);
			return;
		}

		DEBUG_WARN("connection timeout");
		http_server_connection_notify_close_and_free(connection);
	}
}

static void http_server_connection_tcp_close(void *arg, tcp_close_reason_t reason)
{
	struct http_server_connection_t *connection = (struct http_server_connection_t *)arg;

	tcp_connection_deref(connection->conn);
	connection->conn = NULL;

	http_server_connection_notify_close_and_free(connection);
}

void http_server_connection_close(struct http_server_connection_t *connection)
{
	http_server_connection_free(connection);
}

void http_server_connection_set_timeout(struct http_server_connection_t *connection, ticks_t duration)
{
	struct http_server_t *http_server = connection->http_server;
	(void)slist_detach_item(struct http_server_connection_t, &http_server->connection_list, connection);

	connection->connection_timeout = timer_get_ticks() + duration;

	http_server_add_connection(connection->http_server, connection);
}

void http_server_connection_disable_timeout(struct http_server_connection_t *connection)
{
	struct http_server_t *http_server = connection->http_server;
	(void)slist_detach_item(struct http_server_connection_t, &http_server->connection_list, connection);

	connection->connection_timeout = TICKS_INFINITE;

	http_server_add_connection(connection->http_server, connection);
}

uint32_t http_server_connection_get_remote_addr(struct http_server_connection_t *connection, ip_addr_t *result)
{
	return tcp_connection_get_remote_addr(connection->conn, result);
}

struct tcp_connection *http_server_connection_get_tcp_connection(struct http_server_connection_t *connection)
{
	return connection->conn;
}

void http_server_connection_set_http_tag_list(struct http_server_connection_t *connection, const struct http_parser_tag_lookup_t *http_tag_list, void *callback_arg)
{
	http_parser_set_tag_list(connection->http_parser, http_tag_list, callback_arg);
}

void http_server_connection_accept(struct http_server_connection_t *connection, http_server_connection_http_event_func_t http_event, http_server_connection_close_func_t close, void *callback_arg)
{
	connection->http_event = http_event;
	connection->close = close;
	connection->callback_arg = callback_arg;
}

static http_parser_error_t http_server_connection_http_method_event(struct http_server_connection_t *connection, struct netbuf *nb)
{
	const struct http_server_connection_method_lookup_t *entry = http_server_connection_method_lookup;
	while (entry->method_str) {
		if (netbuf_fwd_strcasecmp(nb, entry->method_str) == 0) {
			connection->method = entry->method;
			return HTTP_PARSER_OK;
		}

		entry++;
	}

	http_server_connection_notify_close_and_free(connection);
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t http_server_connection_http_uri_event(struct http_server_connection_t *connection, struct netbuf *nb)
{
	struct url_t url;
	if (!url_parse_nb(&url, nb)) {
		http_server_connection_notify_close_and_free(connection);
		return HTTP_PARSER_ESTOP;
	}

	struct http_server_t *http_server = connection->http_server;
	struct http_server_service_t *service = slist_get_head(struct http_server_service_t, &http_server->service_list);
	while (service) {
		http_server_probe_result_t result = service->probe(service->callback_arg, connection, connection->method, url.uri);
		if (result == HTTP_SERVER_PROBE_RESULT_MATCH) {
			return HTTP_PARSER_OK;
		}
		if (result == HTTP_SERVER_PROBE_RESULT_CLOSE) {
			break;
		}

		service = slist_get_next(struct http_server_service_t, service);
	}

	http_server_connection_notify_close_and_free(connection);
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t http_server_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct http_server_connection_t *connection = (struct http_server_connection_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_METHOD:
		return http_server_connection_http_method_event(connection, nb);

	case HTTP_PARSER_EVENT_URI:
		return http_server_connection_http_uri_event(connection, nb);

	default:
		if (!connection->http_event) {
			http_server_connection_notify_close_and_free(connection);
			return HTTP_PARSER_ESTOP;
		}

		return connection->http_event(connection->callback_arg, event, nb);
	}
}

static void http_server_connection_tcp_recv(void *arg, struct netbuf *nb)
{
	struct http_server_connection_t *connection = (struct http_server_connection_t *)arg;
	http_parser_recv_netbuf(connection->http_parser, nb);
}

static void http_server_connection_establish(void *arg)
{
}

static void http_server_add_connection(struct http_server_t *http_server, struct http_server_connection_t *connection)
{
	struct http_server_connection_t **pprev = slist_get_phead(struct http_server_connection_t, &http_server->connection_list);
	struct http_server_connection_t *entry = slist_get_head(struct http_server_connection_t, &http_server->connection_list);
	while (entry) {
		if (entry->connection_timeout > connection->connection_timeout) {
			break;
		}

		pprev = slist_get_pnext(struct http_server_connection_t, entry);
		entry = slist_get_next(struct http_server_connection_t, entry);
	}

	slist_insert_pprev(struct http_server_connection_t, pprev, connection);

	if (slist_get_head(struct http_server_connection_t, &http_server->connection_list) == connection) {
		ticks_t current_time = timer_get_ticks();
		ticks_t delay = (connection->connection_timeout > current_time) ? connection->connection_timeout - current_time : 0;

		oneshot_detach(&http_server->connection_timer);
		oneshot_attach(&http_server->connection_timer, delay, http_server_connection_timeout, http_server);
	}
}

static void http_server_sock_accept(void *arg, const ip_addr_t *remote_addr, uint32_t ipv6_scope_id)
{
	struct http_server_listen_t *listen = (struct http_server_listen_t *)arg;
	struct http_server_t *http_server = listen->http_server;

	struct http_server_connection_t *connection = (struct http_server_connection_t *)heap_alloc_and_zero(sizeof(struct http_server_connection_t), PKG_OS, MEM_TYPE_OS_HTTP_SERVER_CONNECTION);
	if (!connection) {
		DEBUG_ERROR("out of memory");
		tcp_socket_reject(listen->listen_sock);
		return;
	}

	connection->conn = tcp_connection_alloc();
	if (!connection->conn) {
		DEBUG_ERROR("out of memory");
		heap_free(connection);
		tcp_socket_reject(listen->listen_sock);
		return;
	}

	uint8_t ttl = ip_addr_is_public(remote_addr) ? http_server->public_ttl : http_server->default_ttl;
	tcp_connection_set_ttl(connection->conn, ttl);

	connection->http_parser = http_parser_alloc(http_server_connection_http_event, connection);
	if (!connection->http_parser) {
		DEBUG_ERROR("out of memory");
		tcp_connection_deref(connection->conn);
		heap_free(connection);
		tcp_socket_reject(listen->listen_sock);
		return;
	}

	connection->http_server = http_server;
	connection->connection_timeout = timer_get_ticks() + HTTP_SERVER_DEFAULT_CONNECTION_TIMEOUT;
	http_server_add_connection(http_server, connection);

	tcp_socket_accept(listen->listen_sock, connection->conn, http_server_connection_establish, http_server_connection_tcp_recv, http_server_connection_tcp_close, connection);
}

uint16_t http_server_get_port(struct http_server_t *http_server)
{
	return http_server->listen_port;
}

void http_server_set_default_ttl(struct http_server_t *http_server, uint8_t default_ttl, uint8_t public_ttl)
{
	http_server->default_ttl = default_ttl;
	http_server->public_ttl = public_ttl;
}

void http_server_network_reset(struct http_server_t *http_server)
{
	DEBUG_INFO("http_server_network_reset");

	while (1) {
		struct http_server_connection_t *connection = slist_get_head(struct http_server_connection_t, &http_server->connection_list);
		if (!connection) {
			break;
		}

		http_server_connection_notify_close_and_free(connection);
	}
}

struct http_server_service_t *http_server_register_service(struct http_server_t *http_server, http_server_service_probe_func_t probe, void *callback_arg)
{
	struct http_server_service_t *service = (struct http_server_service_t *)heap_alloc_and_zero(sizeof(struct http_server_service_t), PKG_OS, MEM_TYPE_OS_HTTP_SERVER_SERVICE);
	if (!service) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	service->probe = probe;
	service->callback_arg = callback_arg;

	slist_attach_head(struct http_server_service_t, &http_server->service_list, service);
	return service;
}

struct http_server_t *http_server_instance_alloc(uint16_t port)
{
	struct http_server_t *http_server = (struct http_server_t *)heap_alloc_and_zero(sizeof(struct http_server_t), PKG_OS, MEM_TYPE_OS_HTTP_SERVER);
	if (!http_server) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	oneshot_init(&http_server->connection_timer);
	http_server->default_ttl = 64;
	http_server->public_ttl = 64;

	http_server->ipv4.http_server = http_server;
	http_server->ipv4.listen_sock = tcp_socket_alloc(IP_MODE_IPV4);
	if (http_server->ipv4.listen_sock) {
		tcp_socket_listen(http_server->ipv4.listen_sock, port, http_server_sock_accept, &http_server->ipv4);
		if (port == 0) {
			port = tcp_socket_get_port(http_server->ipv4.listen_sock);
		}
	}

#if defined(IPV6_SUPPORT)
	http_server->ipv6.http_server = http_server;
	http_server->ipv6.listen_sock = tcp_socket_alloc(IP_MODE_IPV6);
	if (http_server->ipv6.listen_sock) {
		tcp_socket_listen(http_server->ipv6.listen_sock, port, http_server_sock_accept, &http_server->ipv6);
		if (port == 0) {
			port = tcp_socket_get_port(http_server->ipv6.listen_sock);
		}
	}
#endif

	http_server->listen_port = port;

	return http_server;
}
