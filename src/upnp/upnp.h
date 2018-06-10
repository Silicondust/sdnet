/*
 * upnp.h
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define UPNP_SERVER_NAME "HDHomeRun/1.0 UPnP/1.0"

struct ssdp_service_t;
struct soap_service_t;
struct gena_service_t;
struct upnp_descriptor_t;

struct upnp_service_t {
	struct ssdp_service_t *ssdp_service;
	struct soap_service_t *soap_service;
	struct gena_service_t *gena_service;
};

extern char log_class_upnp[];
extern void upnp_error_out_of_memory(const char *file, unsigned int line);
extern void upnp_error_tcp_error(tcp_error_t tcp_error, const char *file, unsigned int line);
extern void upnp_error_tcp_unexpected_close(const char *file, unsigned int line);
