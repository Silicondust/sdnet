/*
 * websocket_service.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("websocket_service");

#define WEBSOCKET_MAX_LENGTH 8192

struct websocket_service_connection_t {
	struct http_server_connection_t *http_connection;
	bool http_host_required;
	bool http_host_detected;
	bool http_upgrade_websocket;
	bool http_websocket_version_good;
	char accept_str[32];

	struct netbuf *recv_nb;
	uint32_t frame_fragment_length_remaining;
	uint8_t frame_mask_key[4];
	bool frame_fin_flag;
	websocket_opcode_t frame_opcode;

	struct netbuf *frame_payload_nb;

	websocket_service_connection_recv_func_t recv_callback;
	websocket_service_connection_close_func_t close_callback;
	void *callback_arg;
};

static http_parser_error_t websocket_service_connection_http_tag_host(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t websocket_service_connection_http_tag_upgrade(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t websocket_service_connection_http_tag_websocket_version(void *arg, const char *header, struct netbuf *nb);
static http_parser_error_t websocket_service_connection_http_tag_websocket_key(void *arg, const char *header, struct netbuf *nb);

static const struct http_parser_tag_lookup_t websocket_service_connection_http_tag_list[] = {
	{"HOST", websocket_service_connection_http_tag_host},
	{"Upgrade", websocket_service_connection_http_tag_upgrade},
	{"Sec-WebSocket-Version", websocket_service_connection_http_tag_websocket_version},
	{"Sec-WebSocket-Key", websocket_service_connection_http_tag_websocket_key},
	{NULL, NULL}
};

void websocket_service_connection_free(struct websocket_service_connection_t *ws_conn)
{
	if (ws_conn->http_connection) {
		http_server_connection_close(ws_conn->http_connection);
	}

	if (ws_conn->frame_payload_nb) {
		netbuf_free(ws_conn->frame_payload_nb);
	}
	if (ws_conn->recv_nb) {
		netbuf_free(ws_conn->recv_nb);
	}

	heap_free(ws_conn);
}

static void websocket_service_connection_notify_close_and_free(struct websocket_service_connection_t *ws_conn)
{
	if (ws_conn->close_callback) {
		ws_conn->close_callback(ws_conn->callback_arg);
	}

	websocket_service_connection_free(ws_conn);
}

static void websocket_service_connection_tcp_close_callback(void *arg)
{
	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;
	DEBUG_TRACE("connection close");

	ws_conn->http_connection = NULL;
	websocket_service_connection_notify_close_and_free(ws_conn);
}

static bool websocket_service_connection_send_http_result(struct websocket_service_connection_t *ws_conn, const char *http_result_str)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "HTTP/1.1 %s\r\n", http_result_str);
	success &= netbuf_sprintf(txnb, "Server: %s\r\n", WEBSERVER_NAME);

	if (http_result_str == http_result_web_socket_protocol_handshake) {
		success &= netbuf_sprintf(txnb, "Connection: Upgrade\r\n");
		success &= netbuf_sprintf(txnb, "Sec-WebSocket-Accept: %s\r\n", ws_conn->accept_str);
		success &= netbuf_sprintf(txnb, "Upgrade: websocket\r\n");
	} else {
		success &= netbuf_sprintf(txnb, "Connection: close\r\n");
		success &= netbuf_sprintf(txnb, "Content-Length: 0\r\n");
	}

	success &= http_header_write_date_tag(txnb);
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		DEBUG_ERROR("out of memory");
		netbuf_free(txnb);
		return false;
	}

	netbuf_set_pos_to_start(txnb);
	struct tcp_connection *tcp_conn = http_server_connection_get_tcp_connection(ws_conn->http_connection);
	bool result = (tcp_connection_send_netbuf(tcp_conn, txnb) == TCP_OK);

	netbuf_free(txnb);
	return result;
}

bool websocket_service_connection_send_frame(struct websocket_service_connection_t *ws_conn, websocket_opcode_t opcode, struct netbuf *nb)
{
	size_t payload_length = netbuf_get_remaining(nb);
	size_t header_length = (payload_length >= 126) ? 4 : 2;

	if (!netbuf_rev_make_space(nb, header_length)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	if (payload_length >= 126) {
		netbuf_rev_write_u16(nb, (uint16_t)payload_length);
		payload_length = 126;
	}

	netbuf_rev_write_u8(nb, (uint8_t)payload_length);
	netbuf_rev_write_u8(nb, 0x80 | (uint8_t)opcode);

	struct tcp_connection *tcp_conn = http_server_connection_get_tcp_connection(ws_conn->http_connection);
	if (tcp_connection_send_netbuf(tcp_conn, nb) != TCP_OK) {
		DEBUG_WARN("send failed");
		return false;
	}

	return true;
}

bool websocket_service_connection_send_empty_frame(struct websocket_service_connection_t *ws_conn, websocket_opcode_t opcode)
{
	struct netbuf *nb = netbuf_alloc_with_rev_space(2);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	netbuf_rev_write_u8(nb, 0x00);
	netbuf_rev_write_u8(nb, 0x80 | (uint8_t)opcode);

	struct tcp_connection *tcp_conn = http_server_connection_get_tcp_connection(ws_conn->http_connection);
	if (tcp_connection_send_netbuf(tcp_conn, nb) != TCP_OK) {
		DEBUG_WARN("send failed");
		return false;
	}

	return true;
}

static bool websocket_service_connection_recv_frame_data(struct websocket_service_connection_t *ws_conn, struct netbuf *nb, size_t length, bool fin_flag)
{
	DEBUG_INFO("opcode=%u len=%u, fin=%u", ws_conn->frame_opcode, length, fin_flag);

	size_t mask_index = 0;
	if (ws_conn->frame_payload_nb) {
		size_t existing = netbuf_get_extent(ws_conn->frame_payload_nb);
		if (existing + length > WEBSOCKET_MAX_LENGTH) {
			DEBUG_WARN("bad length");
			websocket_service_connection_send_empty_frame(ws_conn, WEBSOCKET_OPCODE_CONNECTION_CLOSE);
			return false;
		}

		netbuf_set_pos_to_end(ws_conn->frame_payload_nb);
		if (!netbuf_fwd_make_space(ws_conn->frame_payload_nb, length)) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		mask_index = existing;
	} else {
		ws_conn->frame_payload_nb = netbuf_alloc_with_fwd_space(length);
		if (!ws_conn->frame_payload_nb) {
			DEBUG_ERROR("out of memory");
			return false;
		}
	}

	while (length--) {
		netbuf_fwd_write_u8(ws_conn->frame_payload_nb, netbuf_fwd_read_u8(nb) ^ ws_conn->frame_mask_key[mask_index++ % 4]);
	}

	if (!fin_flag) {
		return true;
	}

	struct netbuf *payload_nb = ws_conn->frame_payload_nb;
	websocket_opcode_t opcode = ws_conn->frame_opcode;
	ws_conn->frame_payload_nb = NULL;
	ws_conn->frame_opcode = 0;

	netbuf_set_pos_to_start(payload_nb);

	if (opcode == WEBSOCKET_OPCODE_PING) {
		bool result = websocket_service_connection_send_frame(ws_conn, WEBSOCKET_OPCODE_PONG, payload_nb);
		netbuf_free(payload_nb);
		return result;
	}

	bool result = ws_conn->recv_callback(ws_conn->callback_arg, opcode, payload_nb);
	netbuf_free(payload_nb);
	return result;
}

static bool websocket_service_connection_recv(struct websocket_service_connection_t *ws_conn, struct netbuf *nb)
{
	if (ws_conn->recv_nb) {
		netbuf_set_pos_to_start(ws_conn->recv_nb);
		size_t prepend_length = netbuf_get_remaining(ws_conn->recv_nb);

		if (!netbuf_rev_make_space(nb, prepend_length)) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_rev_copy(nb, ws_conn->recv_nb, prepend_length);

		netbuf_free(ws_conn->recv_nb);
		ws_conn->recv_nb = NULL;
	}

	if (ws_conn->frame_fragment_length_remaining > 0) {
		size_t remaining = netbuf_get_remaining(nb);
		if (remaining < ws_conn->frame_fragment_length_remaining) {
			return websocket_service_connection_recv_frame_data(ws_conn, nb, remaining, false);
		}
	
		if (!websocket_service_connection_recv_frame_data(ws_conn, nb, ws_conn->frame_fragment_length_remaining, ws_conn->frame_fin_flag)) {
			return false;
		}

		ws_conn->frame_fragment_length_remaining = 0;
		netbuf_set_start_to_pos(nb);
	}
		
	while (1) {
		size_t remaining = netbuf_get_remaining(nb);
		if (remaining == 0) {
			return true;
		}

		if (remaining < 2) {
			break;
		}

		uint8_t header[4];
		netbuf_fwd_read(nb, header, 2);

		websocket_opcode_t frame_opcode = (websocket_opcode_t)(header[0] & 0x0F);
		if (frame_opcode == WEBSOCKET_OPCODE_CONNECTION_CLOSE) {
			return false;
		}

		if ((frame_opcode == WEBSOCKET_OPCODE_FRAME_CONTINUATION) && (ws_conn->frame_opcode == 0)) {
			DEBUG_WARN("continuation fragment without starting fragment");
			websocket_service_connection_send_empty_frame(ws_conn, WEBSOCKET_OPCODE_CONNECTION_CLOSE);
			return false;
		}

		if (frame_opcode != WEBSOCKET_OPCODE_FRAME_CONTINUATION) {
			ws_conn->frame_opcode = frame_opcode;
		}

		ws_conn->frame_fin_flag = (bool)(header[0] >> 7);

		bool mask_flag = (bool)(header[1] >> 7);
		if (!mask_flag) {
			DEBUG_WARN("client did not indicate mask");
			websocket_service_connection_send_empty_frame(ws_conn, WEBSOCKET_OPCODE_CONNECTION_CLOSE);
			return false;
		}

		uint64_t length = header[1] & 0x7F;
		if (length == 126) {
			if (!netbuf_fwd_check_space(nb, 2)) {
				break;
			}

			length = (uint64_t)netbuf_fwd_read_u16(nb);
		} else if (length == 127) {
			if (!netbuf_fwd_check_space(nb, 8)) {
				break;
			}

			length = (size_t)netbuf_fwd_read_u64(nb);
		}

		if (length > WEBSOCKET_MAX_LENGTH) {
			DEBUG_WARN("bad length");
			websocket_service_connection_send_empty_frame(ws_conn, WEBSOCKET_OPCODE_CONNECTION_CLOSE);
		}

		if (!netbuf_fwd_check_space(nb, 4)) {
			break;
		}

		netbuf_fwd_read(nb, ws_conn->frame_mask_key, 4);
		netbuf_set_start_to_pos(nb);

		ws_conn->frame_fragment_length_remaining = (uint32_t)length;

		remaining = netbuf_get_remaining(nb);
		if (remaining < ws_conn->frame_fragment_length_remaining) {
			return websocket_service_connection_recv_frame_data(ws_conn, nb, remaining, false);
		}

		if (!websocket_service_connection_recv_frame_data(ws_conn, nb, ws_conn->frame_fragment_length_remaining, ws_conn->frame_fin_flag)) {
			return false;
		}

		ws_conn->frame_fragment_length_remaining = 0;
		netbuf_set_start_to_pos(nb);
	}

	ws_conn->recv_nb = netbuf_alloc_and_steal(nb);
	if (!ws_conn->recv_nb) {
		DEBUG_WARN("out of memory");
		return false;
	}

	return true;
}

static http_parser_error_t websocket_service_connection_http_tag_host(void *arg, const char *header, struct netbuf *nb)
{
	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;
	ws_conn->http_host_detected = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t websocket_service_connection_http_tag_upgrade(void *arg, const char *header, struct netbuf *nb)
{
	if (netbuf_fwd_strcasecmp(nb, "websocket") != 0) {
		DEBUG_WARN("upgrade not websocket");
		return HTTP_PARSER_OK;
	}

	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;
	ws_conn->http_upgrade_websocket = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t websocket_service_connection_http_tag_websocket_version(void *arg, const char *header, struct netbuf *nb)
{
	if (netbuf_fwd_strcmp(nb, "13") != 0) {
		DEBUG_WARN("unsupported version");
		return HTTP_PARSER_OK;
	}

	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;
	ws_conn->http_websocket_version_good = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t websocket_service_connection_http_tag_websocket_key(void *arg, const char *header, struct netbuf *nb)
{
	char data[128];

	size_t len = netbuf_get_remaining(nb);
	if ((len == 0) || (len + 36 > sizeof(data))) {
		DEBUG_WARN("key too long");
		return HTTP_PARSER_OK;
	}

	netbuf_fwd_read(nb, data, len);
	memcpy(data + len, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
	len += 36;

	sha1_digest_t hash;
	sha1_compute_digest(&hash, (uint8_t *)data, len);

	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;
	base64_encode_mem_to_str(hash.u8, sizeof(hash), ws_conn->accept_str, base64_encode_table);
	return HTTP_PARSER_OK;
}

static http_parser_error_t websocket_service_connection_http_event(void *arg, http_parser_event_t event, struct netbuf *nb)
{
	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)arg;

	switch (event) {
	case HTTP_PARSER_EVENT_PROTOCOL:
		if (netbuf_fwd_strcasecmp(nb, "HTTP") != 0) {
			DEBUG_WARN("bad protocol");
			websocket_service_connection_send_http_result(ws_conn, http_result_bad_request);
			websocket_service_connection_notify_close_and_free(ws_conn);
			return HTTP_PARSER_ESTOP;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_VERSION:
		if (netbuf_fwd_strcmp(nb, "1.1") >= 0) {
			ws_conn->http_host_required = true;
		}
		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_HEADER_COMPLETE:
		if (ws_conn->http_host_required && !ws_conn->http_host_detected) {
			DEBUG_WARN("no host field");
			websocket_service_connection_send_http_result(ws_conn, http_result_bad_request);
			websocket_service_connection_notify_close_and_free(ws_conn);
			return HTTP_PARSER_ESTOP;
		}

		if (!ws_conn->http_upgrade_websocket || !ws_conn->http_websocket_version_good || !ws_conn->accept_str) {
			DEBUG_WARN("missing or invalid required header");
			websocket_service_connection_send_http_result(ws_conn, http_result_bad_request);
			websocket_service_connection_notify_close_and_free(ws_conn);
			return HTTP_PARSER_ESTOP;
		}

		if (!websocket_service_connection_send_http_result(ws_conn, http_result_web_socket_protocol_handshake)) {
			websocket_service_connection_notify_close_and_free(ws_conn);
			return HTTP_PARSER_ESTOP;
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA:
		if (!websocket_service_connection_recv(ws_conn, nb)) {
			websocket_service_connection_notify_close_and_free(ws_conn);
			return HTTP_PARSER_ESTOP;
		}

		return HTTP_PARSER_OK;

	case HTTP_PARSER_EVENT_DATA_COMPLETE:
	case HTTP_PARSER_EVENT_RESET:
	case HTTP_PARSER_EVENT_PARSE_ERROR:
		websocket_service_connection_send_http_result(ws_conn, http_result_bad_request);
		websocket_service_connection_notify_close_and_free(ws_conn);
		return HTTP_PARSER_ESTOP;

	case HTTP_PARSER_EVENT_INTERNAL_ERROR:
		websocket_service_connection_send_http_result(ws_conn, http_result_internal_server_error);
		websocket_service_connection_notify_close_and_free(ws_conn);
		return HTTP_PARSER_ESTOP;

	default:
		return HTTP_PARSER_OK;
	}
}

struct websocket_service_connection_t *websocket_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, websocket_service_connection_recv_func_t recv_callback, websocket_service_connection_close_func_t close_callback, void *callback_arg)
{
	if (method != HTTP_SERVER_CONNECTION_METHOD_GET) {
		DEBUG_WARN("websocket request not http get");
		return NULL;
	}

	struct websocket_service_connection_t *ws_conn = (struct websocket_service_connection_t *)heap_alloc_and_zero(sizeof(struct websocket_service_connection_t), PKG_OS, MEM_TYPE_OS_WEBSOCKET_SERVICE_CONNECTION);
	if (!ws_conn) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	ws_conn->recv_callback = recv_callback;
	ws_conn->close_callback = close_callback;
	ws_conn->callback_arg = callback_arg;

	ws_conn->http_connection = http_connection;
	http_server_connection_set_http_tag_list(http_connection, websocket_service_connection_http_tag_list, ws_conn);
	http_server_connection_accept(http_connection, websocket_service_connection_http_event, websocket_service_connection_tcp_close_callback, ws_conn);

	return ws_conn;
}
