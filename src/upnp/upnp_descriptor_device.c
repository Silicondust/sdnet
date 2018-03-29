/*
 * ./src/upnp/upnp_descriptor_device.c
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

THIS_FILE("upnp_descriptor_device");

void upnp_descriptor_device_free(struct upnp_descriptor_device_t *device)
{
	slist_clear(struct upnp_descriptor_device_param_t, &device->param_list, heap_free);
	slist_clear(struct upnp_descriptor_device_service_t, &device->service_list, heap_free);
	heap_free(device); 
}

const char *upnp_descriptor_device_lookup_param_by_name_hash(struct upnp_descriptor_device_t *device, uint32_t name_hash)
{
	struct upnp_descriptor_device_param_t *param = slist_get_head(struct upnp_descriptor_device_param_t, &device->param_list);
	while (param) {
		if (param->name_hash == name_hash) {
			return param->value;
		}

		param = slist_get_next(struct upnp_descriptor_device_param_t, param);
	}

	return NULL;
}

const char *upnp_descriptor_device_lookup_param(struct upnp_descriptor_device_t *device, const char *name)
{
	uint32_t name_hash = hash32_create(name, strlen(name));
	return upnp_descriptor_device_lookup_param_by_name_hash(device, name_hash);
}

struct upnp_descriptor_device_service_t *upnp_descriptor_device_lookup_service(struct upnp_descriptor_device_t *device, const char *service_type)
{
	uint32_t service_type_hash = hash32_create(service_type, strlen(service_type));

	struct upnp_descriptor_device_service_t *service = slist_get_head(struct upnp_descriptor_device_service_t, &device->service_list);
	while (service) {
		if (service->service_type_hash == service_type_hash) {
			return service;
		}

		service = slist_get_next(struct upnp_descriptor_device_service_t, service);
	}

	return NULL;
}

bool upnp_descriptor_device_add_param(struct upnp_descriptor_device_t *device, const char *name, struct netbuf *value_nb)
{
	size_t value_len = netbuf_get_remaining(value_nb);

	struct upnp_descriptor_device_param_t *param = (struct upnp_descriptor_device_param_t *)heap_alloc(sizeof(struct upnp_descriptor_device_param_t) + value_len + 1, PKG_OS, MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE_PARAM);
	if (!param) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	memset(&param->slist_prefix, 0, sizeof(param->slist_prefix));
	param->name_hash = hash32_create((void *)name, strlen(name));

	char *value = (char *)(param + 1);
	netbuf_fwd_read(value_nb, value, value_len);
	value[value_len] = 0;
	param->value = value;

	slist_attach_tail(struct upnp_descriptor_device_param_t, &device->param_list, param);
	return true;
}

bool upnp_descriptor_device_add_service(struct upnp_descriptor_device_t *device, struct upnp_descriptor_device_service_t *service_info)
{
	struct upnp_descriptor_device_service_t *service = (struct upnp_descriptor_device_service_t *)heap_alloc(sizeof(struct upnp_descriptor_device_service_t), PKG_OS, MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE_SERVICE);
	if (!service) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return false;
	}

	*service = *service_info;

	slist_attach_tail(struct upnp_descriptor_device_service_t, &device->service_list, service);
	return true;
}

struct upnp_descriptor_device_t *upnp_descriptor_device_alloc(void)
{
 	struct upnp_descriptor_device_t *device = (struct upnp_descriptor_device_t *)heap_alloc_and_zero(sizeof(struct upnp_descriptor_device_t), PKG_OS, MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE);
	if (!device) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	return device;
}
