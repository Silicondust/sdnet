/*
 * webclient_internal.h
 *
 * Copyright © 2014-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define WEBCLIENT_PIPELINE_STATE_NULL 0
#define WEBCLIENT_PIPELINE_STATE_CURRENT_OPERATION_BUSY 1
#define WEBCLIENT_PIPELINE_STATE_CAN_PIPELINE 2

struct webclient_operation_t {
	struct slist_prefix_t slist_prefix;
	struct webclient_t *webclient;

	struct url_t url;
	char *additional_header_lines;
	const struct http_parser_tag_lookup_t *http_tag_list;
	struct oneshot post_callback_timer;
	struct oneshot timeout_timer;
	ticks_t timeout_to_apply;
	int refs;

	webclient_operation_redirect_callback_t redirect_callback;
	webclient_operation_post_callback_t post_callback;
	webclient_operation_data_callback_t data_callback;
	webclient_operation_complete_callback_t complete_callback;
	void *callback_arg;

	struct webclient_operation_stats_t stats;
	uint64_t stats_last_pause_time;
};

struct webclient_t {
	char *additional_header_lines;
	char dns_name[64];
	struct dns_lookup_t *dns_lookup;
	struct tcp_connection *tcp_conn;
	struct tls_client_connection_t *tls_conn;
	struct http_parser_t *http_parser;
	struct http_parser_tag_lookup_t *http_tag_list_allocated;
	struct oneshot execute_timer;
	struct oneshot disconnect_timer;
	ticks_t max_idle_time;
	size_t max_recv_nb_size;
	uint16_t http_result;
	uint8_t pipeline_state;
	uint64_t data_on_dead_operation;
	bool redirect_url_updated;
	bool expect_100_continue;
	bool keep_alive_accepted;
	bool must_close;

	struct webclient_operation_t *current_operation;
	struct webclient_operation_t *pipelined_operation;
	struct slist_t future_operations;
};

extern void webclient_release_operation(struct webclient_t *webclient, struct webclient_operation_t *operation);
extern void webclient_timeout_operation(struct webclient_t *webclient, struct webclient_operation_t *operation);
extern void webclient_add_operation(struct webclient_t *webclient, struct webclient_operation_t *operation);
extern bool webclient_can_post_data(struct webclient_t *webclient);
extern bool webclient_post_data(struct webclient_t *webclient, struct netbuf *txnb, bool end);
extern void webclient_pause_recv(struct webclient_t *webclient);
extern void webclient_resume_recv(struct webclient_t *webclient);

extern struct webclient_operation_t *webclient_operation_ref(struct webclient_operation_t *operation);
extern int webclient_operation_deref(struct webclient_operation_t *operation);
extern void webclient_operation_signal_complete_and_deref(struct webclient_operation_t *operation, uint8_t result, uint16_t http_error, const char *error_str);
extern void webclient_operation_schedule_post_callback(struct webclient_operation_t *operation);
extern void webclient_operation_pipelined_to_current(struct webclient_operation_t *operation);
