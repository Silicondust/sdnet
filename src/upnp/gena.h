/*
 * gena.h
 *
 * Copyright © 2011-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define GENA_SERVER_NAME UPNP_SERVER_NAME

#define GENA_DEFAULT_SUBSCRIPTION_PERIOD_DRI 1800
#define GENA_DEFAULT_SUBSCRIPTION_PERIOD_DLNA 300
#define GENA_MAX_SUBSCRIPTION_PERIOD 1800

#define GENA_MESSAGE_QUEUE_POLICY_SINGLE 1
#define GENA_MESSAGE_QUEUE_POLICY_FIFO 5

struct gena_service_t;
struct gena_subscription_t;

typedef bool (*gena_service_new_subscription_callback_t)(void *arg, struct gena_subscription_t *subscription, struct netbuf *notify_nb);
typedef bool (*gena_service_notify_vars_callback_t)(void *arg, struct netbuf *notify_nb);

extern void gena_service_manager_init(struct http_server_t *http_server);
extern uint16_t gena_service_manager_get_port(void);
extern struct gena_service_t *gena_service_manager_add_service(const char *uri, gena_service_new_subscription_callback_t new_subscription_callback, void *callback_arg, uint32_t default_subscription_period);
extern void gena_service_manager_network_reset(void);

extern bool gena_service_has_subscriptions(struct gena_service_t *service);
extern void gena_service_enqueue_message(struct gena_service_t *service, uint8_t queue_policy, struct netbuf *notify_nb);
extern void gena_service_enqueue_message_specific_ip(struct gena_service_t *service, ipv4_addr_t specific_ip, uint8_t queue_policy, struct netbuf *notify_nb);
extern void gena_service_notify_vars(struct gena_service_t *service, uint8_t queue_policy, gena_service_notify_vars_callback_t notify_vars_callback, void *callback_arg);

extern ipv4_addr_t gena_subscription_get_local_ip(struct gena_subscription_t *subscription);
extern ipv4_addr_t gena_subscription_get_callback_ip(struct gena_subscription_t *subscription);

extern bool gena_message_begin(struct netbuf *notify_nb);
extern bool gena_message_end(struct netbuf *notify_nb);
extern bool gena_message_add_property_nb_no_escape(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb);
extern bool gena_message_add_property_nb_escape(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb);
extern bool gena_message_add_property_nb_encode_base64(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb);
extern bool gena_message_add_property_sprintf(struct netbuf *notify_nb, const char *name, const char *fmt, ...);

/* Internal. */
struct gena_subscription_t {
	struct slist_prefix_t slist_prefix;
	struct gena_service_t *service;
	struct guid sid;
	ipv4_addr_t local_ip;
	ipv4_addr_t callback_ip;
	uint16_t callback_port;
	char *callback_uri;
	uint32_t sequence;
	struct netbuf_queue tx_queue;
	struct oneshot connection_timer;
	struct tcp_connection *conn; /* May be NULL. */
	struct http_parser_t *http_parser;
	ticks_t subscription_timeout;
	bool last_notify_successful;
	bool unsubscribe;
};

struct gena_service_t {
	struct slist_prefix_t slist_prefix;
	struct slist_t subscription_list;
	struct oneshot subscription_timer;
	uint32_t default_subscription_period;
	ticks_t max_update_rate;
	sha1_digest_t uri_hash;
	gena_service_new_subscription_callback_t new_subscription_callback;
	void *callback_arg;
};

struct gena_service_connection_t {
	struct slist_prefix_t slist_prefix;
	struct http_server_connection_t *http_connection;
	struct tcp_connection *conn;
	struct gena_service_t *service;
	http_server_connection_method_t method;
	bool precondition_failed;
	bool callback_present;
	bool nt_present;
	bool sid_present;
	struct guid sid;
	ipv4_addr_t callback_ip;
	uint16_t callback_port;
	char *callback_uri;
	uint32_t subscription_period;
};

struct gena_service_manager_t {
	struct slist_t service_list;
	struct http_server_t *http_server;
};

extern struct gena_service_t *gena_service_manager_find_service_by_uri_hash(sha1_digest_t *uri_hash);

extern struct gena_service_t *gena_service_alloc(const char *uri, gena_service_new_subscription_callback_t new_subscription_callback, void *callback_arg, uint32_t default_subscription_period);
extern struct gena_subscription_t *gena_service_find_subscription_by_sid(struct gena_service_t *service, struct guid *sid);
extern struct gena_subscription_t *gena_service_find_subscription_by_callback(struct gena_service_t *service, ipv4_addr_t callback_ip, uint16_t callback_port, char *callback_uri);
extern void gena_service_add_subscription(struct gena_service_t *service, struct gena_subscription_t *subscription);
extern void gena_service_remove_subscription(struct gena_service_t *service, struct gena_subscription_t *subscription);
extern void gena_service_network_reset(struct gena_service_t *service);

extern bool gena_service_connection_accept(struct http_server_connection_t *http_connection, http_server_connection_method_t method, const char *uri);
extern void gena_service_connection_free(struct gena_service_connection_t *connection);

extern struct gena_subscription_t *gena_subscription_accept(struct gena_service_t *service, ipv4_addr_t local_ip, ipv4_addr_t callback_ip, uint16_t callback_port, char *callback_uri, uint32_t subscription_period);
extern void gena_subscription_renew(struct gena_subscription_t *subscription, uint32_t subscription_period);
extern void gena_subscription_unsubscribe(struct gena_subscription_t *subscription);
extern void gena_subscription_free(struct gena_subscription_t *subscription);
extern bool gena_subscription_enqueue_message(struct gena_subscription_t *subscription, uint8_t queue_policy, struct netbuf *notify_nb);
