/*
 * gena_service.c
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

THIS_FILE("gena_service");

#define GENA_SERVICE_MAX_SUBSCRIPTION_COUNT 16

static void gena_service_subscription_timeout(void *arg)
{
	struct gena_service_t *service = (struct gena_service_t *)arg;
	ticks_t current_time = timer_get_ticks();

	while (1) {
		struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
		if (!subscription) {
			return;
		}

		if (subscription->subscription_timeout > current_time) {
			oneshot_attach(&service->subscription_timer, subscription->subscription_timeout - current_time, gena_service_subscription_timeout, service);
			return;
		}

		DEBUG_INFO("subscription timeout");
		gena_subscription_unsubscribe(subscription);
	}
}

void gena_service_enqueue_message(struct gena_service_t *service, uint8_t queue_policy, struct netbuf *notify_nb)
{
	struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
	while (subscription) {
		gena_subscription_enqueue_message(subscription, queue_policy, notify_nb);
		subscription = slist_get_next(struct gena_subscription_t, subscription);
	}
}

void gena_service_enqueue_message_specific_ip(struct gena_service_t *service, const ip_addr_t *specific_ip, uint8_t queue_policy, struct netbuf *notify_nb)
{
	struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
	while (subscription) {
		if (ip_addr_cmp(&subscription->callback_ip, specific_ip)) {
			gena_subscription_enqueue_message(subscription, queue_policy, notify_nb);
		}
		subscription = slist_get_next(struct gena_subscription_t, subscription);
	}
}

void gena_service_notify_vars(struct gena_service_t *service, uint8_t queue_policy, gena_service_notify_vars_callback_t notify_vars_callback, void *callback_arg)
{
	struct netbuf *notify_nb = netbuf_alloc();
	if (!notify_nb) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return;
	}

	bool success = true;
	success &= gena_message_begin(notify_nb);
	success &= notify_vars_callback(callback_arg, notify_nb);
	success &= gena_message_end(notify_nb);
	if (!success) {
		netbuf_free(notify_nb);
		return;
	}

	gena_service_enqueue_message(service, queue_policy, notify_nb);
	netbuf_free(notify_nb);
}

struct gena_subscription_t *gena_service_find_subscription_by_sid(struct gena_service_t *service, struct guid *sid)
{
	struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
	while (subscription) {
		if (memcmp(&subscription->sid, sid, sizeof(struct guid)) == 0) {
			return subscription;
		}

		subscription = slist_get_next(struct gena_subscription_t, subscription);
	}

	return NULL;
}

struct gena_subscription_t *gena_service_find_subscription_by_callback(struct gena_service_t *service, const ip_addr_t *callback_ip, uint16_t callback_port, uint32_t callback_ipv6_scope_id, char *callback_uri)
{
	struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
	while (subscription) {
		if (ip_addr_cmp(&subscription->callback_ip, callback_ip) && (subscription->callback_port == callback_port) && (subscription->callback_ipv6_scope_id == callback_ipv6_scope_id) && (strcmp(subscription->callback_uri, callback_uri) == 0)) {
			return subscription;
		}

		subscription = slist_get_next(struct gena_subscription_t, subscription);
	}

	return NULL;
}

bool gena_service_has_subscriptions(struct gena_service_t *service)
{
	return (slist_get_head(struct gena_subscription_t, &service->subscription_list) != NULL);
}

void gena_service_remove_subscription(struct gena_service_t *service, struct gena_subscription_t *subscription)
{
	(void)slist_detach_item(struct gena_subscription_t, &service->subscription_list, subscription);
}

static int8_t gena_service_add_subscription_insert_before(struct gena_subscription_t *list_item, struct gena_subscription_t *item)
{
	return (list_item->subscription_timeout > item->subscription_timeout);
}

void gena_service_add_subscription(struct gena_service_t *service, struct gena_subscription_t *subscription)
{
	/*
	 * Max subscriptions enforcement.
	 * Delete closest-to-timeout subscription that was not successful on the last attempt, or closest-to-timeout if all are successfully communicating.
	 * List is in order of timeout, closest first.
	 */
	struct gena_subscription_t *p = slist_get_head(struct gena_subscription_t, &service->subscription_list);
	struct gena_subscription_t *discard = p;
	uint32_t count = 0;

	while (p) {
		if (!p->last_notify_successful) {
			discard = p;
			break;
		}
		count++;
		p = slist_get_next(struct gena_subscription_t, p);
	}

	while (p) {
		count++;
		p = slist_get_next(struct gena_subscription_t, p);
	}

	if (count >= GENA_SERVICE_MAX_SUBSCRIPTION_COUNT) {
		gena_subscription_unsubscribe(discard);
	}

	/*
	 * Insert in timeout order.
	 */
	slist_insert_custom(struct gena_subscription_t, &service->subscription_list, subscription, gena_service_add_subscription_insert_before);

	/*
	 * Start timer.
	 */
	if (slist_get_head(struct gena_subscription_t, &service->subscription_list) == subscription) {
		oneshot_detach(&service->subscription_timer);
		gena_service_subscription_timeout(service);
	}
}

void gena_service_network_reset(struct gena_service_t *service)
{
	while (1) {
		struct gena_subscription_t *subscription = slist_get_head(struct gena_subscription_t, &service->subscription_list);
		if (!subscription) {
			break;
		}
		gena_subscription_free(subscription);
	}
}

struct gena_service_t *gena_service_alloc(const char *uri, gena_service_new_subscription_callback_t new_subscription_callback, void *callback_arg, uint32_t default_subscription_period)
{
	struct gena_service_t *service = (struct gena_service_t *)heap_alloc_and_zero(sizeof(struct gena_service_t), PKG_OS, MEM_TYPE_OS_GENA_SERVICE);
	if (!service) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	oneshot_init(&service->subscription_timer);
	service->default_subscription_period = default_subscription_period;
	service->max_update_rate = 1;
	sha1_compute_digest(&service->uri_hash, (uint8_t *)uri, strlen(uri));
	service->new_subscription_callback = new_subscription_callback;
	service->callback_arg = callback_arg;

	return service;
}
