/*
 * ./src/webserver/webserver_page_proxy.c
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

THIS_FILE("webserver_page_proxy");

#define WEBSERVER_PAGE_PROXY_USER_AGENT "Silicondust Test/Development"

struct webserver_page_proxy_state_t {
	struct webserver_connection_t *connection;
	struct dns_lookup_t *server_dns;
	struct tcp_connection *server_conn;
	char *server_name;
	char *server_uri;
	uint16_t server_port;
	bool data_received;
};

void webserver_page_proxy_free(struct webserver_connection_t *connection, void *state)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)state;
	if (!page_state) {
		return;
	}

	if (page_state->server_dns) {
		dns_lookup_deref(page_state->server_dns);
	}

	if (page_state->server_conn) {
		tcp_connection_close(page_state->server_conn);
		tcp_connection_deref(page_state->server_conn);
	}

	if (page_state->server_name) {
		heap_free(page_state->server_name);
	}

	if (page_state->server_uri) {
		heap_free(page_state->server_uri);
	}

	heap_free(page_state);
}

static void webserver_page_proxy_server_close(void *inst, tcp_close_reason_t reason)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)inst;

	tcp_connection_deref(page_state->server_conn);
	page_state->server_conn = NULL;

	if (!page_state->data_received) {
		webserver_connection_send_error(page_state->connection, http_result_service_unavailable, NULL);
	}

	webserver_connection_free(page_state->connection);
}

static void webserver_page_proxy_server_recv(void *inst, bool urg, struct netbuf *nb)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)inst;

	page_state->data_received = true;

	if (!webserver_connection_send_payload(page_state->connection, nb)) {
		DEBUG_WARN("send failed");
		return;
	}
}

static void webserver_page_proxy_server_est(void *inst)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)inst;

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		webserver_connection_free(page_state->connection);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "GET %s HTTP/1.1\r\n", page_state->server_uri);
	success &= netbuf_sprintf(txnb, "Host: %s\r\n", page_state->server_name);
	if (page_state->server_port == 80) {
		success &= netbuf_sprintf(txnb, "User-Agent: %s\r\n", WEBSERVER_PAGE_PROXY_USER_AGENT);
	} else {
		success &= netbuf_sprintf(txnb, "User-Agent: %s:%u\r\n", WEBSERVER_PAGE_PROXY_USER_AGENT, page_state->server_port);
	}
	success &= netbuf_sprintf(txnb, "Connection: close\r\n");
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		DEBUG_ERROR("out of memory");
		webserver_connection_free(page_state->connection);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);

	if (tcp_connection_send_netbuf(page_state->server_conn, false, txnb) != TCP_OK) {
		DEBUG_ERROR("send failed");
		netbuf_free(txnb);
		return;
	}

	netbuf_free(txnb);
}

static void webserver_page_server_dns_callback(void *arg, ipv4_addr_t ip)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)arg;
	dns_lookup_deref(page_state->server_dns);
	page_state->server_dns = NULL;

	if (ip == 0) {
		DEBUG_WARN("dns returned fail");
		webserver_connection_send_error(page_state->connection, http_result_service_unavailable, NULL);
		webserver_connection_free(page_state->connection);
		return;
	}

	DEBUG_INFO("server ip = %lx", ip);

	page_state->server_conn = tcp_connection_alloc();
	if (!page_state->server_conn) {
		DEBUG_ERROR("out of memory");
		webserver_connection_free(page_state->connection);
		return;
	}

	if (tcp_connection_connect(page_state->server_conn, stack_idi, ip, page_state->server_port, 0, 0, webserver_page_proxy_server_recv, NULL, NULL, webserver_page_proxy_server_est, webserver_page_proxy_server_close, page_state) != TCP_OK) {
		DEBUG_ERROR("connect failed");
		tcp_connection_deref(page_state->server_conn);
		page_state->server_conn = NULL;
		webserver_connection_free(page_state->connection);
		return;
	}
}

webserver_page_result_t webserver_page_proxy_start(struct webserver_connection_t *connection, const char *server_name, uint16_t server_port, const char *server_uri, void **pstate)
{
	struct webserver_page_proxy_state_t *page_state = (struct webserver_page_proxy_state_t *)heap_alloc_and_zero(sizeof(struct webserver_page_proxy_state_t), PKG_WEBSERVER, MEM_TYPE_WEBSERVER_PAGE_PROXY_STATE);
	if (!page_state) {
		DEBUG_ERROR("out of memory");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	page_state->connection = connection;
	*pstate = page_state;

	page_state->server_port = server_port;
	page_state->server_name = heap_strdup(server_name, PKG_WEBSERVER, MEM_TYPE_WEBSERVER_PAGE_PROXY_NAME);
	page_state->server_uri = heap_strdup(server_uri, PKG_WEBSERVER, MEM_TYPE_WEBSERVER_PAGE_PROXY_URI);
	if (!page_state->server_name || !page_state->server_uri) {
		DEBUG_ERROR("out of memory");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	page_state->server_dns = dns_lookup_alloc();
	if (!page_state->server_dns) {
		DEBUG_ERROR("dns alloc failed");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	if (!dns_lookup_gethostbyname(page_state->server_dns, server_name, webserver_page_server_dns_callback, page_state)) {
		DEBUG_INFO("dns call failed");
		webserver_connection_send_error(connection, http_result_service_unavailable, NULL);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	return WEBSERVER_PAGE_RESULT_PAUSE;
}
