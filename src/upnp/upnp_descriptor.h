/*
 * upnp_descriptor.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct upnp_descriptor_t;
struct upnp_descriptor_loader_t;
struct upnp_descriptor_device_t;

extern struct upnp_descriptor_t *upnp_descriptor_manager_descriptor_alloc(struct url_t *descriptor_url);

extern struct upnp_descriptor_t *upnp_descriptor_ref(struct upnp_descriptor_t *descriptor);
extern ref_t upnp_descriptor_deref(struct upnp_descriptor_t *descriptor);
extern struct upnp_descriptor_device_t *upnp_descriptor_find_device_by_device_type(struct upnp_descriptor_t *descriptor, const char *device_type);
extern struct upnp_descriptor_device_t *upnp_descriptor_find_device_by_udn(struct upnp_descriptor_t *descriptor, const char *udn);

extern const char *upnp_descriptor_device_lookup_param(struct upnp_descriptor_device_t *device, const char *name);
extern struct upnp_descriptor_device_service_t *upnp_descriptor_device_lookup_service(struct upnp_descriptor_device_t *device, const char *service_type);

/* Internal */
struct upnp_descriptor_device_param_t {
	struct slist_prefix_t slist_prefix;
	uint32_t name_hash;
	const char *value;
};

struct upnp_descriptor_device_service_t {
	struct slist_prefix_t slist_prefix;
	uint32_t service_type_hash;
	struct url_t control_url;
};

struct upnp_descriptor_device_t {
	struct slist_prefix_t slist_prefix;
	struct slist_t param_list;
	struct slist_t service_list;
};

struct upnp_descriptor_t {
	struct slist_prefix_t slist_prefix;
	struct slist_t device_list;
	struct upnp_descriptor_loader_t *loader;
	ipv4_addr_t ip_addr;
	uint32_t device_url_hash;
	ref_t refs;
};

struct upnp_descriptor_manager_t {
	struct slist_t descriptor_list;
};

extern void upnp_descriptor_detection_complete(struct upnp_descriptor_t *descriptor);

extern struct upnp_descriptor_loader_t *upnp_descriptor_loader_alloc(struct upnp_descriptor_t *descriptor, struct url_t *descriptor_url);
extern void upnp_descriptor_loader_free(struct upnp_descriptor_loader_t *loader);

extern struct upnp_descriptor_device_t *upnp_descriptor_device_alloc(void);
extern void upnp_descriptor_device_free(struct upnp_descriptor_device_t *device);
extern const char *upnp_descriptor_device_lookup_param_by_name_hash(struct upnp_descriptor_device_t *device, uint32_t name_hash);
extern bool upnp_descriptor_device_add_param(struct upnp_descriptor_device_t *device, const char *name, struct netbuf *value_nb);
extern bool upnp_descriptor_device_add_service(struct upnp_descriptor_device_t *device, struct upnp_descriptor_device_service_t *service_info);
