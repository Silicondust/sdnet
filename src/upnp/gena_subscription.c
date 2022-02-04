/*
 * gena_subscription.c
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

THIS_FILE("gena_subscription");

/*
 * UPnP standard specifies 30 second timeout.
 */
#define GENA_SUBSCRIPTION_CONN_NOTIFY_TIMEOUT (TICK_RATE * 30)

static void gena_subscription_connect(void *arg);

void gena_subscription_free(struct gena_subscription_t *subscription)
{
	oneshot_detach(&subscription->connection_timer);
	gena_service_remove_subscription(subscription->service, subscription);

	while (netbuf_queue_get_head(&subscription->tx_queue)) {
		netbuf_free(netbuf_queue_detach_head(&subscription->tx_queue));
	}

	if (subscription->conn) {
		tcp_connection_close(subscription->conn);
		tcp_connection_deref(subscription->conn);
	}

	http_parser_deref(subscription->http_parser);
	heap_free(subscription->callback_uri);
	heap_free(subscription);
}

static void gena_subscription_conn_close(void *arg, tcp_close_reason_t reason)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;
	DEBUG_WARN("remote closed connection");

	tcp_connection_deref(subscription->conn);
	subscription->conn = NULL;
}

static void gena_subscription_conn_notify_timeout(void *arg)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;
	DEBUG_ASSERT(netbuf_queue_get_head(&subscription->tx_queue), "connection timeout with nothing to send");
	DEBUG_WARN("notify failure");

	if (subscription->unsubscribe) {
		gena_subscription_free(subscription);
		return;
	}

	if (subscription->conn) {
		tcp_connection_close(subscription->conn);
		tcp_connection_deref(subscription->conn);
		subscription->conn = NULL;
	}

	http_parser_reset(subscription->http_parser);

	while (netbuf_queue_get_head(&subscription->tx_queue)) {
		netbuf_free(netbuf_queue_detach_head(&subscription->tx_queue));
	}

	subscription->last_notify_successful = false;
}

static void gena_subscription_conn_notify_success(struct gena_subscription_t *subscription)
{
	DEBUG_ASSERT(netbuf_queue_get_head(&subscription->tx_queue), "connection established with nothing to send");

	if (subscription->unsubscribe) {
		gena_subscription_free(subscription);
		return;
	}

	if (subscription->conn) {
		tcp_connection_close(subscription->conn);
		tcp_connection_deref(subscription->conn);
		subscription->conn = NULL;
	}

	oneshot_detach(&subscription->connection_timer);
	http_parser_reset(subscription->http_parser);
	netbuf_free(netbuf_queue_detach_head(&subscription->tx_queue));

	subscription->last_notify_successful = true;
	subscription->sequence++;
	if (subscription->sequence == 0) {
		subscription->sequence = 1;
	}

	if (netbuf_queue_get_head(&subscription->tx_queue)) {
		oneshot_attach(&subscription->connection_timer, subscription->service->max_update_rate, gena_subscription_connect, subscription);
	}
}

static http_parser_error_t gena_subscription_conn_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_STATUS_CODE:
		if (netbuf_fwd_strncmp(nb, "200", 3) == 0) {
			DEBUG_TRACE("gena_subscription_conn_header_event: 200");
			return HTTP_PARSER_OK;
		}
		if (netbuf_fwd_strncmp(nb, "4", 1) == 0) {
			DEBUG_WARN("4xx status code - terminating subscription");
			gena_subscription_free(subscription);
			return HTTP_PARSER_ESTOP;
		}
		DEBUG_WARN("non-ok status code - will retry");
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		DEBUG_TRACE("gena_subscription_conn_header_event: success");
		gena_subscription_conn_notify_success(subscription);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		DEBUG_INFO("gena_subscription_conn_header_event: error");
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

static void gena_subscription_conn_recv(void *arg, struct netbuf *nb)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;
	DEBUG_TRACE("gena_subscription_conn_recv: recv");
	http_parser_recv_netbuf(subscription->http_parser, nb);
}

static void gena_subscription_conn_established(void *arg)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;
	DEBUG_ASSERT(netbuf_queue_get_head(&subscription->tx_queue), "connection established with nothing to send");
	DEBUG_TRACE("gena_subscription_conn_established");

	/*
	 * Header.
	 */
	struct netbuf *header_nb = netbuf_alloc();
	if (!header_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	struct netbuf *content_nb_peek = netbuf_queue_get_head(&subscription->tx_queue);
	size_t content_length = netbuf_get_remaining(content_nb_peek);

	char sid_str[37];
	guid_write_string(&subscription->sid, sid_str);

	bool success = true;
	success &= netbuf_sprintf(header_nb, "NOTIFY %s HTTP/1.1\r\n", subscription->callback_uri);
	success &= netbuf_sprintf(header_nb, "Host: %v:%u\r\n", subscription->callback_ip, subscription->callback_port);
	success &= netbuf_sprintf(header_nb, "NT: upnp:event\r\n");
	success &= netbuf_sprintf(header_nb, "NTS: upnp:propchange\r\n");
	success &= netbuf_sprintf(header_nb, "SID: uuid:%s\r\n", sid_str);
	success &= netbuf_sprintf(header_nb, "SEQ: %u\r\n", subscription->sequence);
	success &= netbuf_sprintf(header_nb, "Content-Type: %s\r\n", http_content_type_xml);
	success &= netbuf_sprintf(header_nb, "Content-Length: %u\r\n", content_length);
	success &= netbuf_sprintf(header_nb, "Connection: close\r\n");
	success &= netbuf_sprintf(header_nb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(header_nb);
		return;
	}

	netbuf_set_pos_to_start(header_nb);
	tcp_error_t tcp_error = tcp_connection_send_netbuf(subscription->conn, header_nb);
	netbuf_free(header_nb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		return;
	}

	/*
	 * Content.
	 */
	struct netbuf *content_nb = netbuf_clone(content_nb_peek);
	if (!content_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	tcp_error = tcp_connection_send_netbuf(subscription->conn, content_nb);
	netbuf_free(content_nb);
	if (tcp_error != TCP_OK) {
		upnp_error_tcp_error(tcp_error, __this_file, __LINE__);
		return;
	}

	DEBUG_TRACE("gena_subscription_conn_established: send ok");
}

static void gena_subscription_connect(void *arg)
{
	struct gena_subscription_t *subscription = (struct gena_subscription_t *)arg;
	DEBUG_ASSERT(!subscription->conn, "connect called with conn already allocated");

	oneshot_attach(&subscription->connection_timer, GENA_SUBSCRIPTION_CONN_NOTIFY_TIMEOUT, gena_subscription_conn_notify_timeout, subscription);

	subscription->conn = tcp_connection_alloc();
	if (!subscription->conn) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	if (tcp_connection_connect(subscription->conn, subscription->callback_ip, subscription->callback_port, 0, 0, gena_subscription_conn_established, gena_subscription_conn_recv, gena_subscription_conn_close, subscription) != TCP_OK) {
		DEBUG_WARN("connect failed");
		tcp_connection_deref(subscription->conn);
		subscription->conn = NULL;
		return;
	}
}

bool gena_subscription_enqueue_message(struct gena_subscription_t *subscription, uint8_t queue_policy, struct netbuf *notify_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(notify_nb) == netbuf_get_start(notify_nb), "pos not at start");

	struct netbuf *message_clone = netbuf_clone(notify_nb);
	if (!message_clone) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	/*
	 * Enforce queue limit.
	 * The top/first message is never deleted as it may be the initial message or may be in progress.
	 */
	if (!subscription->last_notify_successful) {
		queue_policy = GENA_MESSAGE_QUEUE_POLICY_SINGLE;
	}

	struct netbuf *first = netbuf_queue_detach_head(&subscription->tx_queue);

	while (netbuf_queue_get_count(&subscription->tx_queue) >= queue_policy) {
		netbuf_free(netbuf_queue_detach_head(&subscription->tx_queue));
	}

	if (first) {
		netbuf_queue_attach_head(&subscription->tx_queue, first);
	}

	netbuf_queue_attach_tail(&subscription->tx_queue, message_clone);

	if (!oneshot_is_attached(&subscription->connection_timer)) {
		ticks_t delay = (subscription->sequence == 0) ? 50 : 1;
		oneshot_attach(&subscription->connection_timer, delay, gena_subscription_connect, subscription);
	}

	return true;
}

static bool gena_subscription_start(struct gena_subscription_t *subscription)
{
	struct gena_service_t *service = subscription->service;

	struct netbuf *notify_nb = netbuf_alloc();
	if (!notify_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	bool success = true;
	success &= gena_message_begin(notify_nb);

	if (service->new_subscription_callback) {
		success &= service->new_subscription_callback(service->callback_arg, subscription, notify_nb);
	}

	success &= gena_message_end(notify_nb);
	if (!success) {
		netbuf_free(notify_nb);
		return false;
	}

	if (!gena_subscription_enqueue_message(subscription, GENA_MESSAGE_QUEUE_POLICY_SINGLE, notify_nb)) {
		netbuf_free(notify_nb);
		return false;
	}

	netbuf_free(notify_nb);
	return true;
}

ipv4_addr_t gena_subscription_get_local_ip(struct gena_subscription_t *subscription)
{
	return subscription->local_ip;
}

ipv4_addr_t gena_subscription_get_callback_ip(struct gena_subscription_t *subscription)
{
	return subscription->callback_ip;
}

void gena_subscription_unsubscribe(struct gena_subscription_t *subscription)
{
	/* UPnP requires the first state be sent even if unsubscribe is received before the first state is sent. */
	if ((subscription->sequence == 0) || subscription->conn) {
		gena_service_remove_subscription(subscription->service, subscription);
		subscription->unsubscribe = true;
		return;
	}

	gena_subscription_free(subscription);
}

void gena_subscription_renew(struct gena_subscription_t *subscription, uint32_t subscription_period)
{
	gena_service_remove_subscription(subscription->service, subscription);
	subscription->subscription_timeout = timer_get_ticks() + (ticks_t)subscription_period * TICK_RATE;
	gena_service_add_subscription(subscription->service, subscription);
}

struct gena_subscription_t *gena_subscription_accept(struct gena_service_t *service, ipv4_addr_t local_ip, ipv4_addr_t callback_ip, uint16_t callback_port, char *callback_uri, uint32_t subscription_period)
{
	/*
	 * Create connection.
	 */
	struct gena_subscription_t *subscription = gena_service_find_subscription_by_callback(service, callback_ip, callback_port, callback_uri);
	if (subscription) {
		DEBUG_INFO("deleting old subscription to the same callback target");
		gena_subscription_unsubscribe(subscription);
	}

	subscription = (struct gena_subscription_t *)heap_alloc_and_zero(sizeof(struct gena_subscription_t), PKG_OS, MEM_TYPE_OS_GENA_SUBSCRIPTION);
	if (!subscription) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	subscription->callback_uri = heap_strdup(callback_uri, PKG_OS, MEM_TYPE_OS_GENA_SUBSCRIPTION_CALLBACK_URI);
	if (!subscription->callback_uri) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		heap_free(subscription);
		return NULL;
	}

	subscription->http_parser = http_parser_alloc(gena_subscription_conn_http_event, subscription);
	if (!subscription->http_parser) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		heap_free(subscription->callback_uri);
		heap_free(subscription);
		return NULL;
	}

	subscription->service = service;
	guid_create_random(&subscription->sid);
	subscription->local_ip = local_ip;
	subscription->callback_ip = callback_ip;
	subscription->callback_port = callback_port;
	subscription->subscription_timeout = timer_get_ticks() + (ticks_t)subscription_period * TICK_RATE;
	oneshot_init(&subscription->connection_timer);

	if (!gena_subscription_start(subscription)) {
		http_parser_deref(subscription->http_parser);
		heap_free(subscription->callback_uri);
		heap_free(subscription);
		return NULL;
	}

	gena_service_add_subscription(service, subscription);
	return subscription;
}
