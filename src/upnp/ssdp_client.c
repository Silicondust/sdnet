/*
 * ssdp_client.c
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("ssdp_client");

static struct ssdp_client_manager_t ssdp_client_manager;

static http_parser_error_t ssdp_client_manager_http_tag_st(void *arg, struct netbuf *nb);
static http_parser_error_t ssdp_client_manager_http_tag_nts(void *arg, struct netbuf *nb);
static http_parser_error_t ssdp_client_manager_http_tag_usn(void *arg, struct netbuf *nb);
static http_parser_error_t ssdp_client_manager_http_tag_location(void *arg, struct netbuf *nb);

const struct http_parser_tag_lookup_t ssdp_client_manager_notify_http_tag_list[] = {
	{"NT", ssdp_client_manager_http_tag_st},
	{"NTS", ssdp_client_manager_http_tag_nts},
	{"USN", ssdp_client_manager_http_tag_usn},
	{"LOCATION", ssdp_client_manager_http_tag_location},
	{NULL, NULL}
};

const struct http_parser_tag_lookup_t ssdp_client_manager_response_http_tag_list[] = {
	{"ST", ssdp_client_manager_http_tag_st},
	{"USN", ssdp_client_manager_http_tag_usn},
	{"LOCATION", ssdp_client_manager_http_tag_location},
	{NULL, NULL}
};

static void ssdp_client_send_msearch(struct ssdp_client_t *client)
{
	DEBUG_INFO("sending M-SEARCH for %s", client->st);

	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	bool success = true;
	success &= netbuf_sprintf(txnb, "M-SEARCH * HTTP/1.1\r\n");
	success &= netbuf_sprintf(txnb, "Host: 239.255.255.250:%u\r\n", SSDP_SERVICE_PORT);
	success &= netbuf_sprintf(txnb, "ST: %s\r\n", client->st);
	success &= netbuf_sprintf(txnb, "MAN: \"ssdp:discover\"\r\n");
	success &= netbuf_sprintf(txnb, "MX: 2\r\n");
	success &= netbuf_sprintf(txnb, "\r\n");
	if (!success) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		netbuf_free(txnb);
		return;
	}

	netbuf_set_pos_to_start(txnb);
	udp_socket_send_netbuf(ssdp_manager.sock, SSDP_MULTICAST_IP, SSDP_SERVICE_PORT, 4, UDP_TOS_DEFAULT, txnb);
	netbuf_free(txnb);
}

static void ssdp_client_manager_msearch_timer_callback(void *arg)
{
	ticks_t current_time = timer_get_ticks();
	ticks_t next_time = TICKS_INFINITE;

	struct ssdp_client_t *client = slist_get_head(struct ssdp_client_t, &ssdp_client_manager.client_list);
	while (client) {
		if (current_time >= client->msearch_send_time) {
			ssdp_client_send_msearch(client);
			client->msearch_send_count++;

			if (client->msearch_send_count >= 2) {
				client->msearch_send_time = TICKS_INFINITE;
			} else {
				client->msearch_send_time = current_time + (2 * TICK_RATE) + (random_get32() % TICK_RATE);
			}
		}

		if (client->msearch_send_time < next_time) {
			next_time = client->msearch_send_time;
		}

		client = slist_get_next(struct ssdp_client_t, client);
	}

	if (next_time != TICKS_INFINITE) {
		oneshot_attach(&ssdp_client_manager.msearch_timer, next_time - current_time, ssdp_client_manager_msearch_timer_callback, NULL);
	}
}

static void ssdp_client_device_free(struct ssdp_client_device_t *device)
{
	upnp_descriptor_deref(device->descriptor);
	heap_free(device);
}

static struct ssdp_client_device_t *ssdp_client_device_alloc(void)
{
	struct ssdp_client_device_t *device = (struct ssdp_client_device_t *)heap_alloc_and_zero(sizeof(struct ssdp_client_device_t), PKG_OS, MEM_TYPE_OS_SSDP_CLIENT_DEVICE);
	if (!device) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	device->ip_addr = ssdp_client_manager.location.ip_addr;
	device->usn_hash = ssdp_client_manager.usn_hash;

	device->descriptor = upnp_descriptor_manager_descriptor_alloc(&ssdp_client_manager.location);
	if (!device->descriptor) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		heap_free(device);
		return NULL;
	}

	return device;
}

static http_parser_error_t ssdp_client_manager_http_tag_st(void *arg, struct netbuf *nb)
{
	if (ssdp_client_manager.st_found) {
		heap_free(ssdp_client_manager.st_found);
	}

	ssdp_client_manager.st_found = heap_netbuf_strdup(nb, PKG_OS, MEM_TYPE_OS_SSDP_CLIENT_STR);
	if (!ssdp_client_manager.st_found) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return HTTP_PARSER_OK;
	}

	return HTTP_PARSER_OK;
}

static http_parser_error_t ssdp_client_manager_http_tag_nts(void *arg, struct netbuf *nb)
{
	if (netbuf_fwd_strcmp(nb, "ssdp:alive") == 0) {
		DEBUG_TRACE("ssdp notify alive");
		ssdp_client_manager.notify_alive = true;
		return HTTP_PARSER_OK;
	}

	if (netbuf_fwd_strcmp(nb, "ssdp:byebye") == 0) {
		DEBUG_TRACE("ssdp notify byebye");
		ssdp_client_manager.notify_byebye = true;
		return HTTP_PARSER_OK;
	}

	DEBUG_INFO("unexpected NTS str");
	DEBUG_PRINT_NETBUF_TEXT(nb, 0);
	return HTTP_PARSER_ESTOP;
}

static http_parser_error_t ssdp_client_manager_http_tag_usn(void *arg, struct netbuf *nb)
{
	sha1_compute_digest_netbuf(&ssdp_client_manager.usn_hash, nb, netbuf_get_remaining(nb));
	ssdp_client_manager.usn_detected = true;
	return HTTP_PARSER_OK;
}

static http_parser_error_t ssdp_client_manager_http_tag_location(void *arg, struct netbuf *nb)
{
	url_parse_nb(&ssdp_client_manager.location, nb);
	return HTTP_PARSER_OK;
}

static void ssdp_client_manager_recv_complete_client(struct ssdp_client_t *client)
{
	struct ssdp_client_device_t *device = slist_get_head(struct ssdp_client_device_t, &client->device_list);
	while (device) {
		if (sha1_compare_digest(&ssdp_client_manager.usn_hash, &device->usn_hash)) {
			break;
		}
		device = slist_get_next(struct ssdp_client_device_t, device);
	}

	if (ssdp_client_manager.notify_byebye) {
		if (!device) {
			return;
		}

		(void)slist_detach_item(struct ssdp_client_device_t, &client->device_list, device);
		ssdp_client_device_free(device);
		return;
	}

	if (!device) {
		DEBUG_INFO("found match @ %v", ssdp_client_manager.location.ip_addr);

		device = ssdp_client_device_alloc();
		if (!device) {
			return;
		}

		slist_attach_head(struct ssdp_client_device_t, &client->device_list, device);

		/* Check if device is alrady known due to another operation. */
		if (!device->descriptor->loader && client->callback) {
			client->callback(client->callback_arg, device->descriptor);
		}
	}

	device->last_seen = timer_get_ticks();

	/* Stop m-search searching for a specific device and it was found. */
	if (strncmp(client->st, "uuid:", 5) == 0) {
		client->msearch_send_time = TICKS_INFINITE;
	}
}

static void ssdp_client_manager_recv_complete(ipv4_addr_t remote_ip)
{
	if (!ssdp_client_manager.usn_detected) {
		DEBUG_WARN("no usn in packet");
		return;
	}
	if (!ssdp_client_manager.st_found) {
		DEBUG_WARN("no st/nt in packet");
		return;
	}
	if (!ssdp_client_manager.notify_alive && !ssdp_client_manager.notify_byebye) {
		DEBUG_WARN("no alive/byebye in packet");
		return;
	}

	if (ssdp_client_manager.notify_alive) {
		if (ssdp_client_manager.location.uri[0] == 0) {
			DEBUG_WARN("no location in packet");
			return;
		}

		if (ssdp_client_manager.location.ip_addr == 0) {
			ssdp_client_manager.location.ip_addr = remote_ip;
		}
		if (ssdp_client_manager.location.ip_port == 0) {
			ssdp_client_manager.location.ip_port = 80;
		}

		if (ssdp_client_manager.location.ip_addr != remote_ip) {
			DEBUG_WARN("ip miss-match in location");
			return;
		}
	}

	struct ssdp_client_t *client = slist_get_head(struct ssdp_client_t, &ssdp_client_manager.client_list);
	while (client) {
		if (strcasecmp(client->st, ssdp_client_manager.st_found) == 0) {
			ssdp_client_manager_recv_complete_client(client);
		}
		client = slist_get_next(struct ssdp_client_t, client);
	}
}

static void ssdp_client_manager_recv_complete_reset(void)
{
	if (ssdp_client_manager.st_found) {
		heap_free(ssdp_client_manager.st_found);
		ssdp_client_manager.st_found = NULL;
	}

	ssdp_client_manager.notify_alive = false;
	ssdp_client_manager.notify_byebye = false;
	ssdp_client_manager.usn_detected = false;
	ssdp_client_manager.location.uri[0] = 0;
}

void ssdp_client_manager_notify_recv_complete(ipv4_addr_t remote_ip, uint16_t remote_port)
{
	ssdp_client_manager_recv_complete(remote_ip);
	ssdp_client_manager_recv_complete_reset();
}

void ssdp_client_manager_response_recv_complete(ipv4_addr_t remote_ip, uint16_t remote_port)
{
	ssdp_client_manager.notify_alive = true;
	ssdp_client_manager_recv_complete(remote_ip);
	ssdp_client_manager_recv_complete_reset();
}

void ssdp_client_manager_stop(void)
{
	oneshot_detach(&ssdp_client_manager.msearch_timer);
}

void ssdp_client_manager_start(void)
{
	ticks_t current_time = timer_get_ticks();

	struct ssdp_client_t *client = slist_get_head(struct ssdp_client_t, &ssdp_client_manager.client_list);
	while (client) {
		client->msearch_send_count = 0;
		client->msearch_send_time = current_time + (random_get32() % (10 * TICK_RATE));
		client = slist_get_next(struct ssdp_client_t, client);
	}

	ssdp_client_manager_msearch_timer_callback(NULL);
}

void ssdp_client_manager_upnp_descriptor_complete(struct upnp_descriptor_t *descriptor)
{
	struct ssdp_client_t *client = slist_get_head(struct ssdp_client_t, &ssdp_client_manager.client_list);
	while (client) {
		if (!client->callback) {
			client = slist_get_next(struct ssdp_client_t, client);
			continue;
		}

		struct ssdp_client_device_t *device = slist_get_head(struct ssdp_client_device_t, &client->device_list);
		while (device) {
			if (device->descriptor == descriptor) {
				client->callback(client->callback_arg, device->descriptor);
			}
			device = slist_get_next(struct ssdp_client_device_t, device);
		}

		client = slist_get_next(struct ssdp_client_t, client);
	}
}

struct ssdp_client_t *ssdp_client_manager_add_client(const char *st, ssdp_client_callback_t callback, void *callback_arg)
{
	struct ssdp_client_t *client = (struct ssdp_client_t *)heap_alloc_and_zero(sizeof(struct ssdp_client_t), PKG_OS, MEM_TYPE_OS_SSDP_CLIENT);
	if (!client) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	client->st = heap_strdup(st, PKG_OS, MEM_TYPE_OS_SSDP_CLIENT_STR);
	if (!client->st) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		free(client);
		return NULL;
	}

	client->callback = callback;
	client->callback_arg = callback_arg;

	slist_attach_tail(struct ssdp_client_t, &ssdp_client_manager.client_list, client);

	if (ssdp_manager.local_ip) {
		oneshot_detach(&ssdp_client_manager.msearch_timer);
		ssdp_client_manager_msearch_timer_callback(NULL);
	}

	return client;
}

void ssdp_client_manager_init(void)
{
	oneshot_init(&ssdp_client_manager.msearch_timer);
}
