/*
 * webserver.h
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#if !defined(WEBSERVER_NAME)
#define WEBSERVER_NAME "HDHomeRun/1.0"
#endif
#if !defined(WEBSERVER_PORT)
#define WEBSERVER_PORT 80
#endif

#define WEBSERVER_CONTENT_LENGTH_UNKNOWN 0xFFFFFFFFFFFFFFFFULL

struct webserver_connection_t;

typedef enum {
	WEBSERVER_PAGE_RESULT_CLOSE = 0,
	WEBSERVER_PAGE_RESULT_CONTINUE = 1,
	WEBSERVER_PAGE_RESULT_PAUSE = 2,
	WEBSERVER_PAGE_RESULT_CAPTURE_POST = 3,
	WEBSERVER_PAGE_RESULT_MASK = 0x0F,
	WEBSERVER_PAGE_SSI_RESULT_REPEAT_LAST_SSI = 0x10
} webserver_page_result_t;

typedef webserver_page_result_t (*webserver_page_start_handler_t)(void *arg, struct webserver_connection_t *connection, http_server_connection_method_t method, struct netbuf *uri_nb, struct netbuf *params_nb, void **pstate);
typedef webserver_page_result_t (*webserver_page_post_handler_t)(void *arg, struct webserver_connection_t *connection, struct netbuf *nb, void *state);
typedef webserver_page_result_t (*webserver_page_continue_handler_t)(void *arg, struct webserver_connection_t *connection, void *state);
typedef void (*webserver_page_free_handler_t)(void *arg, struct webserver_connection_t *connection, void *state);
typedef void(*webserver_error_page_handler_t)(struct webserver_connection_t *connection, const char *http_result);
typedef bool (*webserver_uri_fixup_handler_t)(struct webserver_connection_t *connection, struct netbuf *uri_nb, struct netbuf **pparams_nb);
typedef webserver_page_result_t (*webserver_ssi_start_handler_t)(struct webserver_connection_t *connection, struct netbuf *params_nb, void **pstate);
typedef webserver_page_result_t (*webserver_ssi_tag_handler_t)(struct webserver_connection_t *connection, void *state, struct netbuf *txnb);
typedef void (*webserver_ssi_free_handler_t)(struct webserver_connection_t *connection, void *state);

extern struct webserver_t *webserver_instance_alloc(struct http_server_t *http_server);
extern void webserver_register_uri_fixup_handler(struct webserver_t *webserver, webserver_uri_fixup_handler_t uri_fixup_handler);
extern void webserver_register_error_page_handler(struct webserver_t *webserver, webserver_error_page_handler_t error_page_handler);
extern void webserver_register_ssi_handler(struct webserver_t *webserver, webserver_ssi_start_handler_t start_callback, webserver_ssi_free_handler_t free_callback, const webserver_ssi_tag_handler_t *tag_table, uint8_t tag_table_entry_count);
extern void webserver_register_page_filesystem(struct webserver_t *webserver, const char *filesystem_chroot, webserver_page_start_handler_t start_callback, webserver_page_continue_handler_t continue_callback, webserver_page_free_handler_t free_callback, void *callback_arg);
extern void webserver_register_page_custom(struct webserver_t *webserver, const char *uri, webserver_page_start_handler_t start_callback, webserver_page_post_handler_t post_callback, webserver_page_continue_handler_t continue_callback, webserver_page_free_handler_t free_callback, void *callback_arg);
extern uint16_t webserver_get_port(struct webserver_t *webserver);

extern ipv4_addr_t webserver_connection_get_local_ip(struct webserver_connection_t *connection);
extern ipv4_addr_t webserver_connection_get_remote_ip(struct webserver_connection_t *connection);
extern void *webserver_connection_get_page_callback_state(struct webserver_connection_t *connection);
extern void webserver_connection_set_additional_response_header(struct webserver_connection_t *connection, const char *additional_response_header);
extern void webserver_connection_send_error(struct webserver_connection_t *connection, const char *http_result);
extern bool webserver_connection_send_header(struct webserver_connection_t *connection, const char *http_result, const char *content_type, uint64_t content_length, uint32_t cache_duration);
extern bool webserver_connection_send_payload(struct webserver_connection_t *connection, struct netbuf *nb);
extern void webserver_connection_page_resume(struct webserver_connection_t *connection);
extern void webserver_connection_disable_timeout(struct webserver_connection_t *connection);

extern void webserver_page_filesystem_register(struct webserver_t *webserver, const char *filesystem_chroot);
extern size_t webserver_page_filesystem_ssi_getpos(struct webserver_connection_t *connection);
extern void webserver_page_filesystem_ssi_setpos(struct webserver_connection_t *connection, size_t pos);
extern void webserver_page_filesystem_ssi_advance_to_tag(struct webserver_connection_t *connection, webserver_ssi_tag_handler_t tag_handler);

extern webserver_page_result_t webserver_page_proxy_start(struct webserver_connection_t *connection, const char *server_name, uint16_t server_port, const char *server_uri, void **pstate);
extern void webserver_page_proxy_free(struct webserver_connection_t *connection, void *state);

/* Internal */
struct webserver_page_t {
	struct slist_prefix_t slist_prefix;
	sha1_digest_t uri_hash;
	webserver_page_start_handler_t start_callback;
	webserver_page_post_handler_t post_callback;
	webserver_page_continue_handler_t continue_callback;
	webserver_page_free_handler_t free_callback;
	void *callback_arg;
};

struct webserver_connection_t {
	struct slist_prefix_t slist_prefix;
	struct webserver_t *webserver;
	struct http_server_connection_t *http_connection;
	struct tcp_connection *conn;
	http_server_connection_method_t method;
	struct netbuf *uri_nb;
	struct netbuf *params_nb;
	uint64_t range_start;
	uint64_t range_last;
	uint32_t host_required:1;
	uint32_t host_detected:1;
	uint32_t range_detected:1;
	uint32_t language_header:1;
	uint32_t page_active_state:1;
	const struct webserver_page_t *page;
	void *page_callback_state;
	char *additional_response_header;
};

struct webserver_t {
	struct slist_t page_custom_list;
	struct webserver_page_t *page_filesystem;
	webserver_uri_fixup_handler_t uri_fixup_handler;
	webserver_error_page_handler_t error_page_handler;

	webserver_ssi_start_handler_t ssi_start_callback;
	webserver_ssi_free_handler_t ssi_free_callback;
	const webserver_ssi_tag_handler_t *ssi_tag_table;
	uint8_t ssi_tag_table_entry_count;

	struct http_server_t *http_server;
	struct slist_t connection_list;
	struct oneshot page_timer;
	const char *filesystem_chroot;
};

extern void webserver_add_connection(struct webserver_t *webserver, struct webserver_connection_t *connection);
extern void webserver_remove_connection(struct webserver_t *webserver, struct webserver_connection_t *connection);
extern struct webserver_page_t *webserver_find_page_handler(struct webserver_t *webserver, struct netbuf *uri_nb);
extern void webserver_start_page_timer(struct webserver_t *webserver);

extern http_server_probe_result_t webserver_connection_accept(struct webserver_t *webserver, struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri);
extern void webserver_connection_free(struct webserver_connection_t *connection);

extern const char *webserver_content_type_detect_from_ext(const char *uri);
extern const char *webserver_content_type_detect_from_ext_netbuf(struct netbuf *uri_nb);
