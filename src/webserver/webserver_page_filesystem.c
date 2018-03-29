/*
 * ./src/webserver/webserver_page_filesystem.c
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

THIS_FILE("webserver_page_filesystem");

struct webserver_page_filesystem_state_t {
	struct appfs_file_t *file;
	size_t block_length_remaining;
	void *ssi_callback_state;
};

static void webserver_page_filesystem_free(void *arg, struct webserver_connection_t *connection, void *state)
{
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)state;
	if (!page_state) {
		return;
	}

	struct webserver_t *webserver = connection->webserver;
	if (page_state->ssi_callback_state && webserver->ssi_free_callback) {
		webserver->ssi_free_callback(connection, page_state->ssi_callback_state);
	}

	appfs_file_close(page_state->file);
	heap_free(page_state);
}

size_t webserver_page_filesystem_ssi_getpos(struct webserver_connection_t *connection)
{
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)webserver_connection_get_page_callback_state(connection);
	return appfs_file_getpos(page_state->file);
}

void webserver_page_filesystem_ssi_setpos(struct webserver_connection_t *connection, size_t pos)
{
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)webserver_connection_get_page_callback_state(connection);
	appfs_file_setpos(page_state->file, pos);
}

void webserver_page_filesystem_ssi_advance_to_tag(struct webserver_connection_t *connection, webserver_ssi_tag_handler_t tag_handler)
{
	struct webserver_t *webserver = connection->webserver;
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)webserver_connection_get_page_callback_state(connection);
	size_t remaining = appfs_file_get_remaining(page_state->file);

	while (1) {
		if (remaining == 0) {
			DEBUG_ERROR("tag not found");
			return;
		}

		uint8_t index = appfs_file_read_u8(page_state->file);
		remaining--;

		if (index == 0xFF) {
			if (remaining < 2) {
				DEBUG_ERROR("file decode error");
				appfs_file_seek(page_state->file, (ssize_t)remaining);
				return;
			}

			size_t block_length = (size_t)appfs_file_read_u16(page_state->file);
			remaining -= 2;

			if (block_length > remaining) {
				DEBUG_ERROR("file decode error");
				appfs_file_seek(page_state->file, (ssize_t)remaining);
				return;
			}

			appfs_file_seek(page_state->file, (ssize_t)block_length);
			remaining -= block_length;
			continue;
		}

		if (index >= webserver->ssi_tag_table_entry_count) {
			DEBUG_ASSERT(0, "tag out of range");
			appfs_file_seek(page_state->file, (ssize_t)remaining);
			return;
		}

		if (webserver->ssi_tag_table[index] == tag_handler) {
			DEBUG_TRACE("advance_to_tag success");
			break;
		}
	}
}

static webserver_page_result_t webserver_page_filesystem_execute_tag(struct webserver_connection_t *connection, uint8_t index, struct webserver_page_filesystem_state_t *page_state, struct netbuf *txnb)
{
	struct webserver_t *webserver = connection->webserver;
	if (index >= webserver->ssi_tag_table_entry_count) {
		DEBUG_ASSERT(0, "tag out of range");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	const webserver_ssi_tag_handler_t handler = webserver->ssi_tag_table[index];
	if (!handler) {
		DEBUG_ASSERT(0, "tag not implemented");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	webserver_page_result_t ret = handler(connection, page_state->ssi_callback_state, txnb);

	if (ret & WEBSERVER_PAGE_SSI_RESULT_REPEAT_LAST_SSI) {
		appfs_file_seek(page_state->file, -1);
	}

	return (webserver_page_result_t)(ret & WEBSERVER_PAGE_RESULT_MASK);
}

static webserver_page_result_t webserver_page_filesystem_continue_send(struct webserver_connection_t *connection, struct webserver_page_filesystem_state_t *page_state, struct netbuf *txnb)
{
	bool last = (appfs_file_get_remaining(page_state->file) == 0);
	if (netbuf_get_extent(txnb) == 0) {
		return (last) ? WEBSERVER_PAGE_RESULT_CLOSE : WEBSERVER_PAGE_RESULT_CONTINUE;
	}

	netbuf_set_pos_to_start(txnb);

	if (!webserver_connection_send_payload(connection, txnb)) {
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	return (last) ? WEBSERVER_PAGE_RESULT_CLOSE : WEBSERVER_PAGE_RESULT_CONTINUE;
}

static webserver_page_result_t webserver_page_filesystem_continue_basic(struct webserver_connection_t *connection, struct webserver_page_filesystem_state_t *page_state, struct netbuf *txnb)
{
	DEBUG_ASSERT(netbuf_get_extent(txnb) < TCP_TYPICAL_SEND_LENGTH, "packet already full");

	size_t chunk_length = TCP_TYPICAL_SEND_LENGTH - netbuf_get_extent(txnb);
	if (chunk_length > page_state->block_length_remaining) {
		chunk_length = page_state->block_length_remaining;
	}

	netbuf_set_pos_to_end(txnb);
	if (!netbuf_fwd_make_space(txnb, chunk_length)) {
		DEBUG_ERROR("out of memory");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	DEBUG_TRACE("sending chunk size %lu remaining %lu", chunk_length, page_state->block_length_remaining);
	appfs_file_read_netbuf(page_state->file, txnb, chunk_length);
	page_state->block_length_remaining -= chunk_length;

	return webserver_page_filesystem_continue_send(connection, page_state, txnb);
}

static webserver_page_result_t webserver_page_filesystem_continue_internal(struct webserver_connection_t *connection, struct webserver_page_filesystem_state_t *page_state, struct netbuf *txnb)
{
	if (page_state->block_length_remaining > 0) {
		return webserver_page_filesystem_continue_basic(connection, page_state, txnb);
	}

	if (appfs_file_get_remaining(page_state->file) == 0) {
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	uint8_t index = appfs_file_read_u8(page_state->file);
	if (index != 0xFF) {
		webserver_page_result_t ret = webserver_page_filesystem_execute_tag(connection, index, page_state, txnb);
		if (ret != WEBSERVER_PAGE_RESULT_CONTINUE) {
			DEBUG_ASSERT(netbuf_get_extent(txnb) == 0, "unexpected data for return code");
			return ret;
		}

		if (netbuf_get_extent(txnb) >= TCP_TYPICAL_SEND_LENGTH) {
			return webserver_page_filesystem_continue_send(connection, page_state, txnb);
		}

		if (appfs_file_get_remaining(page_state->file) == 0) {
			return webserver_page_filesystem_continue_send(connection, page_state, txnb);
		}

		index = appfs_file_read_u8(page_state->file);
		if (index != 0xFF) {
			appfs_file_seek(page_state->file, -1);
			return webserver_page_filesystem_continue_send(connection, page_state, txnb);
		}
	}

	if (appfs_file_get_remaining(page_state->file) < 2) {
		DEBUG_ERROR("file decode error");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	page_state->block_length_remaining = (size_t)appfs_file_read_u16(page_state->file);
	if (page_state->block_length_remaining == 0) {
		DEBUG_ERROR("file decode error");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}
	if (page_state->block_length_remaining > appfs_file_get_remaining(page_state->file)) {
		DEBUG_ERROR("file decode error");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	return webserver_page_filesystem_continue_basic(connection, page_state, txnb);
}

static webserver_page_result_t webserver_page_filesystem_continue(void *arg, struct webserver_connection_t *connection, void *state)
{
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)state;

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	webserver_page_result_t ret = webserver_page_filesystem_continue_internal(connection, page_state, txnb);

	netbuf_free(txnb);
	return ret;
}

static bool webserver_page_filesystem_detect_ssi(struct appfs_file_t *file)
{
	if (appfs_file_size(file) < 6) {
		return false;
	}

	char buffer[8];
	appfs_file_setpos(file, 0);
	appfs_file_read(file, buffer, 6);
	buffer[6] = 0;

	if (strcmp(buffer, "#!ssi\n") != 0) {
		appfs_file_setpos(file, 0);
		return false;
	}

	/* Leave position after header. */
	return true;
}

static webserver_page_result_t webserver_page_filesystem_start(void *arg, struct webserver_connection_t *connection, struct netbuf *uri_nb, struct netbuf *params_nb, void **pstate)
{
	/*
	 * Open file.
	 */
	char *filename = heap_netbuf_strdup(uri_nb, PKG_OS, MEM_TYPE_OS_WEBSERVER_PAGE_FILESYSTEM_FILENAME);
	if (!filename) {
		DEBUG_ERROR("out of memory");
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	DEBUG_INFO("%v %s", webserver_connection_get_remote_ip(connection), filename);

	struct appfs_file_t *file = appfs_file_open(filename, connection->webserver->filesystem_chroot);
	if (!file) {
		DEBUG_INFO("'%s' not found", filename);
		heap_free(filename);
		webserver_connection_send_error(connection, http_result_not_found);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	bool ssi = webserver_page_filesystem_detect_ssi(file);
	const char *content_type = webserver_content_type_detect_from_ext(filename);
	uint64_t content_length = (ssi) ? WEBSERVER_CONTENT_LENGTH_UNKNOWN : appfs_file_size(file);
	uint32_t cache_duration = (ssi) ? 0 : 1800;
	heap_free(filename);

	/*
	 * Send header.
	 */
	if (!webserver_connection_send_header(connection, http_result_ok, content_type, content_length, cache_duration)) {
		appfs_file_close(file);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	if (connection->method == HTTP_SERVER_CONNECTION_METHOD_HEAD) {
		appfs_file_close(file);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	/*
	 * Page state.
	 */
	struct webserver_page_filesystem_state_t *page_state = (struct webserver_page_filesystem_state_t *)heap_alloc_and_zero(sizeof(struct webserver_page_filesystem_state_t), PKG_OS, MEM_TYPE_OS_WEBSERVER_PAGE_FILESYSTEM_STATE);
	if (!page_state) {
		DEBUG_ERROR("out of memory");
		appfs_file_close(file);
		return WEBSERVER_PAGE_RESULT_CLOSE;
	}

	page_state->file = file;
	page_state->block_length_remaining = appfs_file_get_remaining(file);
	*pstate = page_state;

	/*
	 * SSI.
	 */
	if (!ssi) {
		return WEBSERVER_PAGE_RESULT_CONTINUE;
	}

	DEBUG_TRACE("ssi mode");
	page_state->block_length_remaining = 0;

	struct webserver_t *webserver = connection->webserver;
	if (webserver->ssi_start_callback) {
		if (webserver->ssi_start_callback(connection, params_nb, &page_state->ssi_callback_state) == WEBSERVER_PAGE_RESULT_CLOSE) {
			return WEBSERVER_PAGE_RESULT_CLOSE;
		}
	}

	return WEBSERVER_PAGE_RESULT_CONTINUE;
}

void webserver_page_filesystem_register(struct webserver_t *webserver, const char *filesystem_chroot)
{
	webserver_register_page_filesystem(webserver, filesystem_chroot, webserver_page_filesystem_start, webserver_page_filesystem_continue, webserver_page_filesystem_free, NULL);
}
