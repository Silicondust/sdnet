/*
 * http_result.h
 *
 * Copyright © 2011-2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern const char http_result_continue[];
extern const char http_result_web_socket_protocol_handshake[];
extern const char http_result_ok[];
extern const char http_result_partial_content[];
extern const char http_result_temporary_redirect[];
extern const char http_result_permanent_redirect[];
extern const char http_result_bad_request[];
extern const char http_result_forbidden[];
extern const char http_result_not_found[];
extern const char http_result_not_acceptable[];
extern const char http_result_precondition_failed[];
extern const char http_result_requested_range_not_satisfiable[];
extern const char http_result_internal_server_error[];
extern const char http_result_bad_gateway[];
extern const char http_result_service_unavailable[];

extern const char http_content_type_html[];
extern const char http_content_type_xml[];
extern const char http_content_type_json[];

struct http_header_content_range_t {
	uint64_t start;
	uint64_t last;
	uint64_t total;
};

extern bool http_header_write_cache_control(struct netbuf *header_nb, uint32_t duration);
extern bool http_header_write_content_range(struct netbuf *header_nb, struct http_header_content_range_t *content_range);
extern bool http_header_write_date_tag(struct netbuf *header_nb);

extern bool http_response_encode_chunked(struct netbuf *nb);
extern bool http_response_encode_chunked_end(struct netbuf *nb);
