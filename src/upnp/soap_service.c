/*
 * soap_service.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("soap_service");

const struct soap_action_descriptor_t *soap_service_find_action(struct soap_service_t *service, const char *action_name)
{
	if (strcmp(soap_action_descriptor_query_state_variable.action_name, action_name) == 0) {
		return &soap_action_descriptor_query_state_variable;
	}

	const struct soap_action_descriptor_t *action = service->action_list;
	while (action->action_name) {
		if (strcmp(action->action_name, action_name) == 0) {
			return action;
		}

		action++;
	}

	return NULL;
}

const struct soap_var_descriptor_t *soap_service_find_var(struct soap_service_t *service, const char *var_name)
{
	const struct soap_var_descriptor_t *var = service->var_list;
	while (var->var_name) {
		if (strcmp(var->var_name, var_name) == 0) {
			return var;
		}

		var++;
	}

	return NULL;
}

struct soap_service_t *soap_service_alloc(const char *uri, const char *urn, const struct soap_action_descriptor_t *action_list, const struct soap_var_descriptor_t *var_list, void *callback_arg)
{
	struct soap_service_t *service = (struct soap_service_t *)heap_alloc_and_zero(sizeof(struct soap_service_t), PKG_OS, MEM_TYPE_OS_SOAP_SERVICE);
	if (!service) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	sha1_compute_digest(&service->uri_hash, (uint8_t *)uri, strlen(uri));
	service->urn = urn;
	service->action_list = action_list;
	service->var_list = var_list;
	service->callback_arg = callback_arg;

	return service;
}
