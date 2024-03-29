/*
 * ssdp.h
 *
 * Copyright © 2011-2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define SSDP_SERVER_NAME UPNP_SERVER_NAME
#define SSDP_SERVICE_PORT 1900

extern void ssdp_manager_init(uint16_t webserver_port);
extern void ssdp_manager_network_start(void);
extern void ssdp_manager_network_stop(void);

struct ssdp_service_t;
extern const char ssdp_service_root_device_urn[];
extern struct ssdp_service_t *ssdp_service_manager_add_service(struct guid *uuid, const char *urn, const char *device_xml_uri);
extern void ssdp_service_manager_resend_notify_now(void);

struct ssdp_client_t;
typedef void (*ssdp_client_callback_t)(void *arg, struct upnp_descriptor_t *descriptor);
extern struct ssdp_client_t *ssdp_client_manager_add_client(const char *st, ssdp_client_callback_t callback, void *callback_arg);

/* Internal. */
typedef void (*ssdp_manager_recv_complete_func_t)(const ip_addr_t *remote_ip, uint16_t remote_port, uint32_t ipv6_scope_id);

struct ssdp_service_discover_reply_t {
	struct slist_prefix_t slist_prefix;
	struct ssdp_service_t *service;
	ip_addr_t remote_ip;
	uint16_t remote_port;
	uint32_t ipv6_scope_id;
	ticks_t send_time;
};

struct ssdp_service_t {
	struct slist_prefix_t slist_prefix;
	struct ssdp_service_t *discover_next;
	struct guid uuid;
	const char *urn;
	const char *device_xml_uri;
};

struct ssdp_service_manager_t {
	struct slist_t service_list;
	/* Notify */
	struct oneshot notify_timer;
	struct ssdp_service_t *next_notify;
	bool initial_byebye;
	bool resend_notify;
	/* Discover */
	struct oneshot discover_reply_timer;
	struct slist_t discover_reply_list;
	bool discover_mode;
	bool mx_present;
	uint16_t max_delay;
	struct ssdp_service_t *discover_list;
};

struct ssdp_client_device_t {
	struct slist_prefix_t slist_prefix;
	struct upnp_descriptor_t *descriptor;
	sha1_digest_t usn_hash;
	ticks_t last_seen;
};

struct ssdp_client_t {
	struct slist_prefix_t slist_prefix;
	struct slist_t device_list;
	char *st;
	uint8_t msearch_send_count;
	ticks_t msearch_send_time;
	ssdp_client_callback_t callback;
	void *callback_arg;
};

struct ssdp_client_manager_t {
	struct slist_t client_list;
	struct oneshot msearch_timer;
	/* Processing */
	bool notify_alive;
	bool notify_byebye;
	bool usn_detected;
	char *st_found;
	sha1_digest_t usn_hash;
	struct url_t location;
};

struct ssdp_manager_transport_t {
	struct udp_socket *sock;
	const ip_addr_t *multicast_ip;
};

struct ssdp_manager_t {
	struct ssdp_manager_transport_t ipv4;
	struct ssdp_manager_transport_t ipv6;
	struct http_parser_t *http_parser;
	uint16_t webserver_port;
	bool running;
	ssdp_manager_recv_complete_func_t recv_complete;
};

extern struct ssdp_manager_t ssdp_manager;

extern void ssdp_service_manager_init(void);
extern void ssdp_service_manager_network_start(void);
extern void ssdp_service_manager_network_stop(void);
extern void ssdp_service_manager_msearch_recv_complete(const ip_addr_t *remote_ip, uint16_t remote_port, uint32_t ipv6_scope_id);
extern const struct http_parser_tag_lookup_t ssdp_service_manager_msearch_http_tag_list[];

extern void ssdp_client_manager_init(void);
extern void ssdp_client_manager_network_start(void);
extern void ssdp_client_manager_network_stop(void);
extern void ssdp_client_manager_notify_recv_complete(const ip_addr_t *remote_ip, uint16_t remote_port, uint32_t ipv6_scope_id);
extern void ssdp_client_manager_response_recv_complete(const ip_addr_t *remote_ip, uint16_t remote_port, uint32_t ipv6_scope_id);
extern const struct http_parser_tag_lookup_t ssdp_client_manager_notify_http_tag_list[];
extern const struct http_parser_tag_lookup_t ssdp_client_manager_response_http_tag_list[];
extern void ssdp_client_manager_upnp_descriptor_complete(struct upnp_descriptor_t *descriptor);
