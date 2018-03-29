/*
 * ./src/upnp/upnp.c
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

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("upnp");

char log_class_upnp[] = "UPnP";

void upnp_error_out_of_memory(const char *file, unsigned int line)
{
	log_error(log_class_upnp, "resource error (%s:%u)", file, line);
}

void upnp_error_tcp_error(tcp_error_t tcp_error, const char *file, unsigned int line)
{
	log_warning(log_class_upnp, "tcp error %d (%s:%u)", tcp_error, file, line);
}

void upnp_error_tcp_unexpected_close(const char *file, unsigned int line)
{
	log_warning(log_class_upnp, "tcp unexpected close (%s:%u)", file, line);
}
