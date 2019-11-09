/*
 * soap_service_manager.c
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

THIS_FILE("soap_service_manager");

static struct soap_service_manager_t soap_service_manager;

void soap_service_manager_query_state_variable_self_test(void)
{
	struct soap_service_t *service = slist_get_head(struct soap_service_t, &soap_service_manager.service_list);
	while (service) {
		const struct soap_var_descriptor_t *var = service->var_list;
		while (var->var_name) {
			soap_action_query_state_variable_self_test(var, service->callback_arg);
			var++;
		}

		service = slist_get_next(struct soap_service_t, service);
	}
}

static http_server_probe_result_t soap_service_manager_http_service_probe(void *arg, struct http_server_connection_t *connection, http_server_connection_method_t method, const char *uri)
{
	return soap_service_connection_accept(connection, method, uri);
}

struct soap_service_t *soap_service_manager_find_service_by_uri_hash(sha1_digest_t *uri_hash)
{
	struct soap_service_t *service = slist_get_head(struct soap_service_t, &soap_service_manager.service_list);
	while (service) {
		if (sha1_compare_digest(&service->uri_hash, uri_hash)) {
			return service;
		}

		service = slist_get_next(struct soap_service_t, service);
	}

	return NULL;
}

struct soap_service_t *soap_service_manager_add_service(const char *uri, const char *urn, const struct soap_action_descriptor_t *action_list, const struct soap_var_descriptor_t *var_list, void *callback_arg)
{
	struct soap_service_t *service = soap_service_alloc(uri, urn, action_list, var_list, callback_arg);
	if (!service) {
		return NULL;
	}

	slist_attach_tail(struct soap_service_t, &soap_service_manager.service_list, service);
	return service;
}

uint16_t soap_service_manager_get_port(void)
{
	return http_server_get_port(soap_service_manager.http_server);
}

void soap_service_manager_init(struct http_server_t *http_server)
{
	soap_service_manager.http_server = http_server;
	http_server_register_service(http_server, soap_service_manager_http_service_probe, NULL);
}
