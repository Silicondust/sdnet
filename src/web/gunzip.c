/*
 * gunzip.c
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>
#include <zlib.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("gunzip");

#define GUNZIP_STATE_READY 0
#define GUNZIP_STATE_COMPLETE 1
#define GUNZIP_STATE_ERROR 2
#define GUNZIP_STATE_CALLBACK_RETURNED_FALSE 3

struct gunzip_t {
	z_stream strm;
	uint8_t state;

	gunzip_output_callback_func_t output_callback;
	void *callback_arg;

	uint8_t output_buffer[2048];
};

void gunzip_free(struct gunzip_t *gunzip)
{
	inflateEnd(&gunzip->strm);
	heap_free(gunzip);
}

void gunzip_reset(struct gunzip_t *gunzip)
{
	gunzip->state = GUNZIP_STATE_READY;
	gunzip->strm.next_in = NULL;
	gunzip->strm.avail_in = 0;

	inflateReset(&gunzip->strm);
}

static bool gunzip_invoke_callback(struct gunzip_t *gunzip, uint8_t status, uint8_t *ptr, uint8_t *end)
{
	if (!gunzip->output_callback) {
		return false;
	}

	return gunzip->output_callback(gunzip->callback_arg, status, ptr, end);
}

static bool gunzip_process(struct gunzip_t *gunzip, uint8_t *ptr, uint8_t *end)
{
	int flush = (ptr == NULL);

	while (1) {
		gunzip->strm.next_in = ptr; /* may be NULL */
		gunzip->strm.avail_in = (uInt)(end - ptr); /* may be NULL minus NULL = 0 */
		gunzip->strm.next_out = gunzip->output_buffer;
		gunzip->strm.avail_out = (uInt)sizeof(gunzip->output_buffer);

		int ret = inflate(&gunzip->strm, flush);
		DEBUG_ASSERT((gunzip->strm.next_in >= ptr) && (gunzip->strm.next_in <= end), "inflate corrupted next_in");

		ptr = gunzip->strm.next_in;
		gunzip->strm.next_in = NULL;
		gunzip->strm.avail_in = 0;

		if ((ret != Z_OK) && (ret != Z_STREAM_END)) {
			DEBUG_WARN("inflate error %d", ret);
			gunzip->state = GUNZIP_STATE_ERROR;
			gunzip_invoke_callback(gunzip, GUNZIP_STATUS_ERROR, NULL, NULL);
			return false;
		}

		if (gunzip->strm.next_out > gunzip->output_buffer) {
			/* clear state before the callback in case the callback frees the gunzip object */
			gunzip->state = GUNZIP_STATE_CALLBACK_RETURNED_FALSE;
			if (!gunzip_invoke_callback(gunzip, GUNZIP_STATUS_DATA, gunzip->output_buffer, gunzip->strm.next_out)) {
				return false;
			}

			gunzip->state = GUNZIP_STATE_READY;
		}

		if (ret == Z_STREAM_END) {
			if (ptr < end) {
				DEBUG_WARN("trailing data");
			}

			gunzip->state = GUNZIP_STATE_COMPLETE;
			gunzip_invoke_callback(gunzip, GUNZIP_STATUS_COMPLETE, NULL, NULL);
			return true;
		}

		if (gunzip->strm.next_out == gunzip->output_buffer) {
			if (ptr < end) {
				DEBUG_WARN("inflate did not consume input data");
				gunzip->state = GUNZIP_STATE_ERROR;
				gunzip_invoke_callback(gunzip, GUNZIP_STATUS_ERROR, NULL, NULL);
				return false;
			}

			if (flush) {
				DEBUG_WARN("inflate expects more data after eof");
				gunzip->state = GUNZIP_STATE_ERROR;
				gunzip_invoke_callback(gunzip, GUNZIP_STATUS_ERROR, NULL, NULL);
				return false;
			}

			return true; /* wait for more input data */
		}
	}
}

bool gunzip_input_eof(struct gunzip_t *gunzip)
{
	if (gunzip->state != GUNZIP_STATE_READY) {
		return (gunzip->state == GUNZIP_STATE_COMPLETE);
	}

	return gunzip_process(gunzip, NULL, NULL);
}

bool gunzip_input_data(struct gunzip_t *gunzip, uint8_t *ptr, uint8_t *end)
{
	if (gunzip->state != GUNZIP_STATE_READY) {
		DEBUG_WARN("input data after error/complete");
		return false;
	}

	return gunzip_process(gunzip, ptr, end);
}

static voidpf gunzip_zalloc(voidpf opaque, uInt items, uInt size)
{
	return heap_alloc(items * size, PKG_OS, MEM_TYPE_OS_GUNZIP_ZALLOC);
}

static void gunzip_zfree(voidpf opaque, voidpf address)
{
	heap_free(address);
}

void gunzip_register_callbacks(struct gunzip_t *gunzip, gunzip_output_callback_func_t output_callback, void *callback_arg)
{
	gunzip->output_callback = output_callback;
	gunzip->callback_arg = callback_arg;
}

struct gunzip_t *gunzip_alloc(void)
{
	struct gunzip_t *gunzip = (struct gunzip_t *)heap_alloc_and_zero(sizeof(struct gunzip_t), PKG_OS, MEM_TYPE_OS_GUNZIP);
	if (!gunzip) {
		return NULL;
	}

	gunzip->strm.zalloc = gunzip_zalloc;
	gunzip->strm.zfree = gunzip_zfree;

	int window_bits = 15;
	window_bits |= 16; /* gzip mode */

	int ret = inflateInit2(&gunzip->strm, window_bits);
	if (ret != Z_OK) {
		DEBUG_WARN("inflateInit error %d", ret);
		heap_free(gunzip);
		return NULL;
	}

	return gunzip;
}
