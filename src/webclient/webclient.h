/*
 * webclient.h
 *
 * Copyright © 2014-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct webclient_connection_t;

struct webclient_connection_stats_t {
	ticks_t first_start_time;
	ticks_t start_time;
	ticks_t dns_time;
	ticks_t establish_time;
	ticks_t header_complete_time;
	ticks_t data_start_time;
	ticks_t data_complete_time;
	ticks_t complete_time;

	uint32_t redirect_count;
	uint64_t download_size;
	ticks_t paused_duration;
};

#define WEBCLIENT_RESULT_SUCCESS 1
#define WEBCLIENT_RESULT_DNS_FAILED 2
#define WEBCLIENT_RESULT_CONNECT_FAILED 3
#define WEBCLIENT_RESULT_SEND_FAILED 4
#define WEBCLIENT_RESULT_NON_200_RESULT 5
#define WEBCLIENT_RESULT_HTTP_PARSE_ERROR 6
#define WEBCLIENT_RESULT_EARLY_CLOSE 7
#define WEBCLIENT_RESULT_TIMEOUT 8
#define WEBCLIENT_RESULT_HTTPS_FAILED 9

typedef void(*webclient_connection_redirect_callback_t)(void *arg, struct webclient_connection_t *connection, struct url_t *url);
typedef void(*webclient_connection_post_callback_t)(void *arg, struct webclient_connection_t *connection);
typedef void(*webclient_connection_data_callback_t)(void *arg, struct webclient_connection_t *connection, struct netbuf *nb);
typedef void(*webclient_connection_complete_callback_t)(void *arg, struct webclient_connection_t *connection, uint8_t result, uint16_t http_error, const char *error_str);

extern struct webclient_connection_t *webclient_connection_execute_get(struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_connection_redirect_callback_t redirect_callback, webclient_connection_data_callback_t data_callback, webclient_connection_complete_callback_t complete_callback, void *callback_arg);
extern struct webclient_connection_t *webclient_connection_execute_post(struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_connection_redirect_callback_t redirect_callback, webclient_connection_post_callback_t post_callback, webclient_connection_data_callback_t data_callback, webclient_connection_complete_callback_t complete_callback, void *callback_arg);
extern void webclient_connection_release(struct webclient_connection_t *connection);
extern void webclient_connection_set_callback_arg(struct webclient_connection_t *connection, void *callback_arg);
extern void webclient_connection_set_max_recv_nb_size(struct webclient_connection_t *connection, size_t max_recv_nb_size);
extern void webclient_connection_set_timeout(struct webclient_connection_t *connection, ticks_t timeout);
extern struct webclient_connection_stats_t *webclient_connection_get_stats(struct webclient_connection_t *connection);
extern ipv4_addr_t webclient_connection_get_local_ip(struct webclient_connection_t *connection);
extern ticks_t webclient_connection_get_timeout_time_remaining(struct webclient_connection_t *connection);
extern void webclient_connection_pause_recv(struct webclient_connection_t *connection);
extern void webclient_connection_resume_recv(struct webclient_connection_t *connection);
extern bool webclient_connection_can_post_data(struct webclient_connection_t *connection);
extern bool webclient_connection_post_data(struct webclient_connection_t *connection, struct netbuf *txnb, bool end);
