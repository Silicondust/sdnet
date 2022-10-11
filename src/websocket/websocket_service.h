/*
 * websocket_service.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef enum {
	WEBSOCKET_OPCODE_FRAME_CONTINUATION = 0x0,
	WEBSOCKET_OPCODE_TEXT_FRAME = 0x1,
	WEBSOCKET_OPCODE_BINARY_FRAME = 0x2,
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	WEBSOCKET_OPCODE_PING = 0x9,
	WEBSOCKET_OPCODE_PONG = 0xA,
} websocket_opcode_t;

struct websocket_service_connection_t;

typedef bool (*websocket_service_connection_recv_func_t)(void *arg, websocket_opcode_t opcode, struct netbuf *nb);
typedef void (*websocket_service_connection_close_func_t)(void *arg);

extern struct websocket_service_connection_t *websocket_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, websocket_service_connection_recv_func_t recv_callback, websocket_service_connection_close_func_t close_callback, void *callback_arg);
extern void websocket_service_connection_free(struct websocket_service_connection_t *ws_conn);
extern bool websocket_service_connection_send_frame(struct websocket_service_connection_t *ws_conn, websocket_opcode_t opcode, struct netbuf *nb);
extern bool websocket_service_connection_send_empty_frame(struct websocket_service_connection_t *ws_conn, websocket_opcode_t opcode);
