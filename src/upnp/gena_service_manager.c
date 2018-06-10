/*
 * gena_service_manager.c
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

THIS_FILE("gena_service_manager");

struct gena_service_manager_t gena_service_manager;

static bool gena_service_manager_http_service_probe(void *arg, struct http_server_connection_t *connection, http_server_connection_method_t method, const char *uri)
{
	return gena_service_connection_accept(connection, method, uri);
}

struct gena_service_t *gena_service_manager_find_service_by_uri_hash(sha1_digest_t *uri_hash)
{
	struct gena_service_t *service = slist_get_head(struct gena_service_t, &gena_service_manager.service_list);
	while (service) {
		if (sha1_compare_digest(&service->uri_hash, uri_hash)) {
			return service;
		}

		service = slist_get_next(struct gena_service_t, service);
	}

	return NULL;
}

struct gena_service_t *gena_service_manager_add_service(const char *uri, gena_service_new_subscription_callback_t new_subscription_callback, void *callback_arg, uint32_t default_subscription_period)
{
	struct gena_service_t *service = gena_service_alloc(uri, new_subscription_callback, callback_arg, default_subscription_period);
	if (!service) {
		return NULL;
	}

	slist_attach_tail(struct gena_service_t, &gena_service_manager.service_list, service);
	return service;
}

uint16_t gena_service_manager_get_port(void)
{
	return http_server_get_port(gena_service_manager.http_server);
}

void gena_service_manager_network_reset(void)
{
	DEBUG_INFO("gena_service_manager_network_reset");

	/*
	 * Free subscriptions.
	 */
	struct gena_service_t *service = slist_get_head(struct gena_service_t, &gena_service_manager.service_list);
	while (service) {
		gena_service_network_reset(service);
		service = slist_get_next(struct gena_service_t, service);
	}
}

void gena_service_manager_init(struct http_server_t *http_server)
{
	gena_service_manager.http_server = http_server;
	http_server_register_service(http_server, gena_service_manager_http_service_probe, NULL);
}
