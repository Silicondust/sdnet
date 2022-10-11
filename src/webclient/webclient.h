/*
 * webclient.h
 *
 * Copyright © 2014-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * A webclient represents a single tcp or tls connection to one server at a time.
 * A webclient_operation represents a GET or a POST operation.
 *
 * Any number of webclient_operations can be enqueued for the webclient to execute and operations can be to different servers.
 * If the server supports connection pipelining and the next request is to the same server (dns name) the webclient will
 * automatically pipeline the request.
 *
 * Redirects are automatically followed. Redirects can be to the same server or to a different server.
 * Note: as any operation could result in a redirect to a different server the next operation isn't pipelined until the headers have
 * been received from the first operation.
 *
 * If a failure occurs after a pipelined operation has been sent to the server but before the server has responded the webclient will
 * automatically reconnect and resubmit the operation.
 *
 * Once all operations have been completed the webclient will keep the the connection alive for a specified period of time in case of
 * future operations.
 */

struct webclient_t;
struct webclient_operation_t;

struct webclient_operation_stats_t {
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
#define WEBCLIENT_RESULT_RESOURCE_ERROR 10

typedef void(*webclient_operation_redirect_callback_t)(void *arg, struct webclient_operation_t *operation, struct url_t *url);
typedef void(*webclient_operation_post_callback_t)(void *arg, struct webclient_operation_t *operation);
typedef void(*webclient_operation_data_callback_t)(void *arg, struct webclient_operation_t *operation, struct netbuf *nb);
typedef void(*webclient_operation_complete_callback_t)(void *arg, struct webclient_operation_t *operation, uint8_t result, uint16_t http_error, const char *error_str);

extern struct webclient_t *webclient_alloc(const char *additional_header_lines, ticks_t max_idle_time);
extern void webclient_release(struct webclient_t *webclient);
extern void webclient_set_max_recv_nb_size(struct webclient_t *webclient, size_t max_recv_nb_size);
extern void webclient_get_local_ip(struct webclient_t *webclient, ip_addr_t *result);

extern struct webclient_operation_t *webclient_operation_execute_get(struct webclient_t *webclient, struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_operation_redirect_callback_t redirect_callback, webclient_operation_data_callback_t data_callback, webclient_operation_complete_callback_t complete_callback, void *callback_arg);
extern struct webclient_operation_t *webclient_operation_execute_post(struct webclient_t *webclient, struct url_t *url, const char *additional_header_lines, const struct http_parser_tag_lookup_t *http_tag_list, webclient_operation_redirect_callback_t redirect_callback, webclient_operation_post_callback_t post_callback, webclient_operation_data_callback_t data_callback, webclient_operation_complete_callback_t complete_callback, void *callback_arg);
extern void webclient_operation_release(struct webclient_operation_t *operation);
extern void webclient_operation_set_timeout(struct webclient_operation_t *operation, ticks_t timeout);
extern struct webclient_operation_stats_t *webclient_operation_get_stats(struct webclient_operation_t *operation);
extern ticks_t webclient_operation_get_timeout_time_remaining(struct webclient_operation_t *operation);
extern void webclient_operation_pause_recv(struct webclient_operation_t *operation);
extern void webclient_operation_resume_recv(struct webclient_operation_t *operation);
extern bool webclient_operation_can_post_data(struct webclient_operation_t *operation);
extern bool webclient_operation_post_data(struct webclient_operation_t *operation, struct netbuf *txnb, bool end);
