/*
 * os.h
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <windows/os_include.h>
#include <default/netbuf.h>

#define FILE_ASYNC_SUPPORT 1

#include <os_enums.h>
#include <utils/byteswap_le.h>
#include <utils/mem_int.h>
#include <text/char.h>
#include <utils/bcd.h>
#include <utils/base64.h>
#include <utils/guid.h>
#include <text/doprint_custom.h>
#include <text/sprintf_custom.h>
#include <text/sscanf_custom.h>
#include <heap.h>
#include <flash/flash.h>
#include <thread/thread.h>
#include <timer/timer.h>
#include <unix_time/unix_time.h>
#include <utils/hash32.h>
#include <utils/slist.h>
#include <utils/dlist.h>
#include <utils/hmap.h>
#include <thread/mqueue.h>
#include <netbuf.h>
#include <text/netbuf_sprintf.h>
#include <text/netbuf_sscanf.h>
#include <timer/oneshot.h>
#include <crypto/random.h>
#include <net/ip_datalink.h>
#include <net/igmp.h>
#include <net/dns_lookup.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <crypto/crypto.h>
#include <appfs/appfs.h>
#include <file/dir_change_notification.h>
#include <file/dir_utils.h>
#include <file/windows/dir_utils.h>
#include <file/file_utils.h>
#include <file/filename_utils.h>
#include <debug.h>
#include <log.h>
#include <thread/long_task.h>
#include <web/json_parser.h>
#include <web/http_parser.h>
#include <web/http_result.h>
#include <web/url.h>
#include <web/url_params.h>
#include <web/xml_parser.h>
#include <web/http_server.h>
#include <webclient/webclient.h>
#include <webserver/webserver.h>
#include <upnp/upnp.h>
#include <upnp/ssdp.h>
#include <upnp/soap.h>
#include <upnp/gena.h>
#include <upnp/upnp_descriptor.h>
#include <daemon/daemon.h>
#include <daemon/windows/daemon.h>

#include <thread/windows/thread.h>
#include <thread/windows/spinlock.h>
#include <windows/system.h>
#include <timer/windows/timer.h>
#include <crypto/windows/crypto.h>
#include <net/windows/tcp.h>

#define OS_NAME "Windows"
