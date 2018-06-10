/*
 * webserver.c
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("webserver");

static void webserver_page_timer_callback(void *arg)
{
	struct webserver_t *webserver = (struct webserver_t *)arg;
	ticks_t delay = TICKS_INFINITE;

	struct webserver_connection_t *connection = slist_get_head(struct webserver_connection_t, &webserver->connection_list);
	while (connection) {
		if (!connection->page_active_state) {
			connection = slist_get_next(struct webserver_connection_t, connection);
			continue;
		}

		const struct webserver_page_t *page = connection->page;
		DEBUG_ASSERT(page, "page not set");
		DEBUG_ASSERT(page->continue_callback, "no continue callback");

		if (tcp_connection_can_send(connection->conn) != TCP_OK) {
			#if defined(IP3K)
			delay = min(delay, 10); /* ipOS does not support send_resume callback */
			#endif
			connection = slist_get_next(struct webserver_connection_t, connection);
			continue;
		}

		webserver_page_result_t ret = page->continue_callback(page->callback_arg, connection, connection->page_callback_state);
		if (ret == WEBSERVER_PAGE_RESULT_CLOSE) {
			struct webserver_connection_t *closing_connection = connection;
			connection = slist_get_next(struct webserver_connection_t, connection);
			webserver_connection_free(closing_connection);
			continue;
		}
		if (ret == WEBSERVER_PAGE_RESULT_PAUSE) {
			connection->page_active_state = false;
			connection = slist_get_next(struct webserver_connection_t, connection);
			continue;
		}

		DEBUG_ASSERT(ret == WEBSERVER_PAGE_RESULT_CONTINUE, "unexpected result");
		delay = 0;
		connection = slist_get_next(struct webserver_connection_t, connection);
	}

	if (delay == TICKS_INFINITE) {
		return;
	}

	oneshot_attach(&webserver->page_timer, delay, webserver_page_timer_callback, webserver);
}

void webserver_start_page_timer(struct webserver_t *webserver)
{
	oneshot_detach(&webserver->page_timer);
	oneshot_attach(&webserver->page_timer, 0, webserver_page_timer_callback, webserver);
}

void webserver_remove_connection(struct webserver_t *webserver, struct webserver_connection_t *connection)
{
	(void)slist_detach_item(struct webserver_connection_t, &webserver->connection_list, connection);
}

void webserver_add_connection(struct webserver_t *webserver, struct webserver_connection_t *connection)
{
	slist_attach_tail(struct webserver_connection_t, &webserver->connection_list, connection);
}

static bool webserver_http_service_probe(void *arg, struct http_server_connection_t *connection, http_server_connection_method_t method, const char *uri)
{
	struct webserver_t *webserver = (struct webserver_t *)arg;
	return webserver_connection_accept(webserver, connection, method, uri);
}

struct webserver_page_t *webserver_find_page_handler(struct webserver_t *webserver, struct netbuf *uri_nb)
{
	struct webserver_page_t *page = slist_get_head(struct webserver_page_t, &webserver->page_custom_list);
	if (!page) {
		return webserver->page_filesystem;
	}

	sha1_digest_t uri_hash;
	sha1_compute_digest_netbuf(&uri_hash, uri_nb, netbuf_get_remaining(uri_nb));
	netbuf_set_pos_to_start(uri_nb);

	while (page) {
		if (sha1_compare_digest(&page->uri_hash, &uri_hash)) {
			return page;
		}

		page = slist_get_next(struct webserver_page_t, page);
	}

	return webserver->page_filesystem;
}

static struct webserver_page_t *webserver_create_page(webserver_page_start_handler_t start_callback, webserver_page_continue_handler_t continue_callback, webserver_page_free_handler_t free_callback, void *callback_arg)
{
	struct webserver_page_t *page = (struct webserver_page_t *)heap_alloc_and_zero(sizeof(struct webserver_page_t), PKG_OS, MEM_TYPE_OS_WEBSERVER_PAGE);
	if (!page) {
		return NULL;
	}

	page->start_callback = start_callback;
	page->continue_callback = continue_callback;
	page->free_callback = free_callback;
	page->callback_arg = callback_arg;

	return page;
}

void webserver_register_page_custom(struct webserver_t *webserver, const char *uri, webserver_page_start_handler_t start_callback, webserver_page_continue_handler_t continue_callback, webserver_page_free_handler_t free_callback, void *callback_arg)
{
	struct webserver_page_t *page = webserver_create_page(start_callback, continue_callback, free_callback, callback_arg);
	if (!page) {
		return;
	}

	sha1_compute_digest(&page->uri_hash, (uint8_t *)uri, strlen(uri));
	slist_attach_head(struct webserver_page_t, &webserver->page_custom_list, page);
}

void webserver_register_page_filesystem(struct webserver_t *webserver, const char *filesystem_chroot, webserver_page_start_handler_t start_callback, webserver_page_continue_handler_t continue_callback, webserver_page_free_handler_t free_callback, void *callback_arg)
{
	DEBUG_ASSERT(!webserver->page_filesystem, "filesystem page handler already registered");
	struct webserver_page_t *page = webserver_create_page(start_callback, continue_callback, free_callback, callback_arg);
	if (!page) {
		return;
	}

	webserver->page_filesystem = page;
	webserver->filesystem_chroot = filesystem_chroot;
}

void webserver_register_ssi_handler(struct webserver_t *webserver, webserver_ssi_start_handler_t start_callback, webserver_ssi_free_handler_t free_callback, const webserver_ssi_tag_handler_t *tag_table, uint8_t tag_table_entry_count)
{
	webserver->ssi_start_callback = start_callback;
	webserver->ssi_free_callback = free_callback;
	webserver->ssi_tag_table = tag_table;
	webserver->ssi_tag_table_entry_count = tag_table_entry_count;
}

void webserver_register_error_page_handler(struct webserver_t *webserver, webserver_error_page_handler_t error_page_handler)
{
	webserver->error_page_handler = error_page_handler;
}

void webserver_register_uri_fixup_handler(struct webserver_t *webserver, webserver_uri_fixup_handler_t uri_fixup_handler)
{
	webserver->uri_fixup_handler = uri_fixup_handler;
}

uint16_t webserver_get_port(struct webserver_t *webserver)
{
	return http_server_get_port(webserver->http_server);
}

struct webserver_t *webserver_instance_alloc(struct http_server_t *http_server)
{
	struct webserver_t *webserver = (struct webserver_t *)heap_alloc_and_zero(sizeof(struct webserver_t), PKG_OS, MEM_TYPE_OS_WEBSERVER);
	if (!webserver) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	webserver->http_server = http_server;
	http_server_register_service(http_server, webserver_http_service_probe, webserver);

	oneshot_init(&webserver->page_timer);

	return webserver;
}
