/*
 * upnp_descriptor.c
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

THIS_FILE("upnp_descriptor");

static struct upnp_descriptor_manager_t upnp_descriptor_manager;

struct upnp_descriptor_t *upnp_descriptor_ref(struct upnp_descriptor_t *descriptor)
{
	descriptor->refs++;
	return descriptor;
}

ref_t upnp_descriptor_deref(struct upnp_descriptor_t *descriptor)
{
	descriptor->refs--;
	if (descriptor->refs != 0) {
		return descriptor->refs;
	}

	(void)slist_detach_item(struct upnp_descriptor_t, &upnp_descriptor_manager.descriptor_list, descriptor);

	if (descriptor->loader) {
		upnp_descriptor_loader_free(descriptor->loader);
	}

	slist_clear(struct upnp_descriptor_device_t, &descriptor->device_list, upnp_descriptor_device_free);

	heap_free(descriptor);
	return 0;
}

static struct upnp_descriptor_device_t *upnp_descriptor_find_device_by_param(struct upnp_descriptor_t *descriptor, const char *name, const char *value)
{
	uint64_t name_hash = hash64_create(name, strlen(name));

	struct upnp_descriptor_device_t *device = slist_get_head(struct upnp_descriptor_device_t, &descriptor->device_list);
	while (device) {
		const char *lookup_value = upnp_descriptor_device_lookup_param_by_name_hash(device, name_hash);
		if (!lookup_value) {
			device = slist_get_next(struct upnp_descriptor_device_t, device);
			continue;
		}

		DEBUG_INFO("%s = %s", name, lookup_value);
		if (strcasecmp(lookup_value, value) == 0) {
			return device;
		}

		device = slist_get_next(struct upnp_descriptor_device_t, device);
	}

	return NULL;
}

struct upnp_descriptor_device_t *upnp_descriptor_find_device_by_device_type(struct upnp_descriptor_t *descriptor, const char *device_type)
{
	return upnp_descriptor_find_device_by_param(descriptor, "deviceType", device_type);
}

struct upnp_descriptor_device_t *upnp_descriptor_find_device_by_udn(struct upnp_descriptor_t *descriptor, const char *udn)
{
	return upnp_descriptor_find_device_by_param(descriptor, "UDN", udn);
}

void upnp_descriptor_detection_complete(struct upnp_descriptor_t *descriptor)
{
	upnp_descriptor_loader_free(descriptor->loader);
	descriptor->loader = NULL;

	ssdp_client_manager_upnp_descriptor_complete(descriptor);
}

struct upnp_descriptor_t *upnp_descriptor_manager_descriptor_alloc(struct url_t *descriptor_url)
{
	uint64_t device_url_hash = hash64_create(&descriptor_url->ipv6_scope_id, sizeof(descriptor_url->ipv6_scope_id));
	device_url_hash = hash64_append(device_url_hash , &descriptor_url->ip_addr, sizeof(descriptor_url->ip_addr));
	device_url_hash = hash64_append(device_url_hash, &descriptor_url->ip_port, sizeof(descriptor_url->ip_port));
	device_url_hash = hash64_append(device_url_hash, descriptor_url->uri, strlen(descriptor_url->uri));

	struct upnp_descriptor_t *descriptor = slist_get_head(struct upnp_descriptor_t, &upnp_descriptor_manager.descriptor_list);
	while (descriptor) {
		if (descriptor->device_url_hash == device_url_hash) {
			return upnp_descriptor_ref(descriptor);
		}

		descriptor = slist_get_next(struct upnp_descriptor_t, descriptor);
	}

	descriptor = (struct upnp_descriptor_t *)heap_alloc_and_zero(sizeof(struct upnp_descriptor_t), PKG_OS, MEM_TYPE_OS_UPNP_DESCRIPTOR);
	if (!descriptor) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	descriptor->loader = upnp_descriptor_loader_alloc(descriptor, descriptor_url);
	if (!descriptor->loader) {
		heap_free(descriptor);
		return NULL;
	}

	descriptor->device_url_hash = device_url_hash;
	descriptor->refs = 1;

	slist_attach_head(struct upnp_descriptor_t, &upnp_descriptor_manager.descriptor_list, descriptor);
	return descriptor;
}
