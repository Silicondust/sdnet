/*
 * os.h
 *
 * Copyright © 2007-2014 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os_config.h>
#include <linux/os_include.h>
#include <linux/arch.h>
#include <linux/system.h>
#include <default/netbuf.h>

#include <os_enums.h>
#include <linux/byteswap.h>
#include <utils/byteswap_le.h>
#include <utils/mem_int.h>
#include <text/char.h>
#include <utils/bcd.h>
#include <utils/base36.h>
#include <utils/base64.h>
#include <utils/guid.h>
#include <net/ip_addr.h>
#include <text/doprint_custom.h>
#include <text/sprintf_custom.h>
#include <text/sscanf_custom.h>
#include <heap.h>
#include <flash/flash.h>
#include <thread/thread.h>
#include <timer/timer.h>
#include <unix_time/unix_time.h>
#include <utils/hash64.h>
#include <utils/slist.h>
#include <utils/dlist.h>
#include <utils/hmap.h>
#include <utils/nvlist.h>
#include <thread/mqueue.h>
#include <thread/mqueue2.h>
#include <netbuf.h>
#include <text/netbuf_sprintf.h>
#include <text/netbuf_sscanf.h>
#include <timer/oneshot.h>
#include <crypto/random.h>
#include <crypto/crypto.h>
#include <crypto/crypto_hash.h>
#include <crypto/pkcs1_v15.h>
#include <crypto/der.h>
#include <crypto/x509.h>
#include <crypto/libtom/mpi.h>
#include <net/ip_interface.h>
#include <net/libc/ip_interface.h>
#include <net/ip_managed.h>
#include <net/igmp.h>
#include <net/dhcp_client.h>
#include <net/dhcp_server.h>
#include <net/dhcp_usbd.h>
#include <net/dhcp_common.h>
#include <net/dns_lookup.h>
#include <net/dns_responder.h>
#include <net/mdns_responder.h>
#include <net/ntp_server.h>
#include <net/udp.h>
#include <net/udp_dhcp.h>
#include <net/tcp.h>
#include <net/tls_prf.h>
#include <net/tls_client.h>
#include <net/tls_server.h>
#include <appfs/appfs.h>
#include <file/dir_change_notification.h>
#include <file/dir_utils.h>
#include <file/file_utils.h>
#include <file/file_wasync.h>
#include <file/file_sendfile.h>
#include <file/linux/dir_utils.h>
#include <file/linux/file_utils.h>
#include <file/linux/hdparm.h>
#include <file/linux/gpt.h>
#include <file/linux/nvme.h>
#include <file/filename_utils.h>
#include <debug.h>
#include <log.h>
#include <thread/long_task.h>
#include <io/gpio.h>
#include <exe_args.h>
#include <io/i2c_master.h>
#include <io/spi_master.h>
#include <web/gunzip.h>
#include <web/json_parser.h>
#include <web/json_process.h>
#include <web/http_parser.h>
#include <web/http_result.h>
#include <web/language.h>
#include <web/url.h>
#include <web/url_params.h>
#include <web/url_unescape.h>
#include <web/xml_parser.h>
#include <web/xml_process.h>
#include <web/http_server.h>
#include <webclient/webclient.h>
#include <webserver/webserver.h>
#include <websocket/websocket_service.h>
#include <upnp/upnp.h>
#include <upnp/ssdp.h>
#include <upnp/soap.h>
#include <upnp/gena.h>
#include <upnp/upnp_descriptor.h>
#include <daemon/daemon.h>
#include <linux/dmidecode.h>

#include <thread/pthread/spinlock.h>
#include <thread/linux/thread.h>
#include <net/libc/tcp.h>
#include <net/libc/udp.h>

#if defined(TB100)
#include <timer/tb100/timer.h>
#else
#include <timer/linux/timer.h>
#endif

#if defined(ANDROID)
#define OS_NAME "Android"
#else
#define OS_NAME "Linux"
#endif
