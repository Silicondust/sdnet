/*
 * http_result.c
 *
 * Copyright © 2011-2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("http_result");

const char http_result_continue[] = "100 Continue";
const char http_result_web_socket_protocol_handshake[] = "101 Web Socket Protocol Handshake";
const char http_result_ok[] = "200 OK";
const char http_result_partial_content[] = "206 Partial Content";
const char http_result_temporary_redirect[] = "307 Temporary Redirect";
const char http_result_permanent_redirect[] = "308 Permanent Redirect";
const char http_result_bad_request[] = "400 Bad Request";
const char http_result_forbidden[] = "403 Forbidden";
const char http_result_not_found[] = "404 Not Found";
const char http_result_not_acceptable[] = "406 Not Acceptable";
const char http_result_precondition_failed[] = "412 Precondition Failed";
const char http_result_requested_range_not_satisfiable[] = "416 Requested Range Not Satisfiable";
const char http_result_internal_server_error[] = "500 Internal Server Error";
const char http_result_bad_gateway[] = "502 Bad Gateway";
const char http_result_service_unavailable[] = "503 Service Unavailable";

const char http_content_type_html[] = "text/html; charset=\"utf-8\"";
const char http_content_type_xml[] = "text/xml; charset=\"utf-8\"";
const char http_content_type_json[] = "application/json; charset=\"utf-8\"";

bool  http_header_write_cache_control(struct netbuf *header_nb, uint32_t duration)
{
	if (duration == 0) {
		return netbuf_sprintf(header_nb, "Cache-Control: no-cache\r\n");
	}

	return netbuf_sprintf(header_nb, "Cache-Control: max-age=%u\r\n", duration);
}

bool  http_header_write_content_range(struct netbuf *header_nb, struct http_header_content_range_t *content_range)
{
	bool success = true;
	success &= netbuf_sprintf(header_nb, "Content-Range: bytes ");

	if (content_range->last == 0) {
		success &= netbuf_sprintf(header_nb, "*");
	} else {
		success &= netbuf_sprintf(header_nb, "%llu-%llu", content_range->start, content_range->last);
	}

	if (content_range->total == 0) {
		success &= netbuf_sprintf(header_nb, "/*\r\n");
	} else {
		success &= netbuf_sprintf(header_nb, "/%llu\r\n", content_range->total);
	}

	return success;
}

bool http_header_write_date_tag(struct netbuf *header_nb)
{
	struct tm current_tm;
	unix_time_to_tm(unix_time(), &current_tm);

	/* Date/time not known = non-fatal error. */
	if (current_tm.tm_year <= 113) {
		DEBUG_TRACE("date/time not known (year=%u)", current_tm.tm_year);
		return true;
	}

	static char day_of_week_lookup[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	static char month_lookup[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

	return netbuf_sprintf(header_nb, "Date: %s, %02u %s %u %02u:%02u:%02u GMT\r\n",
		day_of_week_lookup[current_tm.tm_wday],
		current_tm.tm_mday, month_lookup[current_tm.tm_mon], current_tm.tm_year + 1900,
		current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec
	);
}

bool http_response_encode_chunked(struct netbuf *nb)
{
	size_t chunk_length = netbuf_get_extent(nb);
	DEBUG_ASSERT(chunk_length > 0, "zero length data");

	/*
	 * Prefix.
	 */
	char prefix_str[16];
	sprintf(prefix_str, "%X\r\n", (unsigned int)chunk_length);
	size_t prefix_str_len = strlen(prefix_str);

	netbuf_set_pos_to_start(nb);
	if (!netbuf_rev_make_space(nb, prefix_str_len)) {
		return false;
	}

	netbuf_rev_write(nb, prefix_str, prefix_str_len);

	/*
	 * Suffix.
	 */
	netbuf_set_pos_to_end(nb);
	return netbuf_sprintf(nb, "\r\n");
}

bool http_response_encode_chunked_end(struct netbuf *nb)
{
	netbuf_set_pos_to_end(nb);
	return netbuf_sprintf(nb, "0\r\n\r\n");
}
