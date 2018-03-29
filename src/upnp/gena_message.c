/*
 * ./src/upnp/gena_message.c
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

THIS_FILE("gena_message");

static const char gena_message_prefix_xml[] =
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	"<e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">";

static const char gena_message_suffix_xml[] =
	"</e:propertyset>";

bool gena_message_add_property_nb_no_escape(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");

	if (!netbuf_sprintf(notify_nb, "<e:property><%s>", name)) {
		return false;
	}

	size_t len = netbuf_get_remaining(val_nb);
	if (len > 0) {
		if (!netbuf_fwd_make_space(notify_nb, len)) {
			return false;
		}

		netbuf_fwd_copy(notify_nb, val_nb, len);
	}

	return netbuf_sprintf(notify_nb, "</%s></e:property>", name);
}

bool gena_message_add_property_nb_escape(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");

	char *val = heap_netbuf_strdup(val_nb, PKG_OS, MEM_TYPE_OS_GENA_MESSAGE_STR);
	if (!val) {
		return false;
	}

	bool success = gena_message_add_property_sprintf(notify_nb, name, "%s", val);
	heap_free(val);

	return success;
}

bool gena_message_add_property_nb_encode_base64(struct netbuf *notify_nb, const char *name, struct netbuf *val_nb)
{
	DEBUG_ASSERT(netbuf_get_pos(val_nb) == netbuf_get_start(val_nb), "pos not at start");

	bool success = true;
	success &= netbuf_sprintf(notify_nb, "<e:property><%s>", name);
	success &= base64_encode_netbuf_to_netbuf2(val_nb, netbuf_get_remaining(val_nb), notify_nb);
	success &= netbuf_sprintf(notify_nb, "</%s></e:property>", name);
	return success;
}

bool gena_message_add_property_sprintf(struct netbuf *notify_nb, const char *name, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	bool success = true;
	success &= netbuf_sprintf(notify_nb, "<e:property><%s>", name);
	success &= netbuf_vsprintf_xml(notify_nb, fmt, ap);
	success &= netbuf_sprintf(notify_nb, "</%s></e:property>", name);

	va_end(ap);
	return success;
}

bool gena_message_end(struct netbuf *notify_nb)
{
	bool success = netbuf_sprintf(notify_nb, gena_message_suffix_xml);
	netbuf_set_pos_to_start(notify_nb);
	return success;
}

bool gena_message_begin(struct netbuf *notify_nb)
{
	return netbuf_sprintf(notify_nb, gena_message_prefix_xml);
}
