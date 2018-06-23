/*
 * os_enums.h
 *
 * Copyright © 2012-2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

enum {
	PKG_OS = 128,
};

enum {
	MEM_TYPE_OS_NETBUF = 1,
	MEM_TYPE_OS_FILE = 2,
	MEM_TYPE_OS_FILE_NAME = 3,
	MEM_TYPE_OS_LONGTASK_ITEM = 4,
	MEM_TYPE_OS_I2C = 5,
	MEM_TYPE_OS_DNS_LOOKUP = 6,
	MEM_TYPE_OS_DNS_LOOKUP_NAME = 7,
	MEM_TYPE_OS_UDP_SOCKET = 8,
	MEM_TYPE_OS_TCP_SOCKET = 9,
	MEM_TYPE_OS_TCP_CONNECTION = 10,
	MEM_TYPE_OS_THREAD = 11,
	MEM_TYPE_OS_THREAD_SIGNAL = 12,
	MEM_TYPE_OS_LOG_LINE = 13,
	MEM_TYPE_OS_LOG_READER = 14,
	MEM_TYPE_OS_HMAP_ARRAY = 15,
	MEM_TYPE_OS_DNS_ENTRY = 16,
	MEM_TYPE_OS_MQUEUE = 17,
	MEM_TYPE_OS_MQUEUE_ITEM = 18,
	MEM_TYPE_OS_TCP_POLL = 19,
	MEM_TYPE_OS_UDP_POLL = 20,
	MEM_TYPE_OS_FLASH = 21,
	MEM_TYPE_OS_EXE_ARG = 22,
	MEM_TYPE_OS_DHCP_CLIENT = 23,
	MEM_TYPE_OS_IP_DATALINK = 24,
	MEM_TYPE_OS_SPI = 25,
	MEM_TYPE_OS_XML_PARSER = 26,
	MEM_TYPE_OS_JSON_PARSER = 27,
	MEM_TYPE_OS_HTTP_PARSER = 28,
	MEM_TYPE_OS_WEBCLIENT_CONNECTION = 29,
	MEM_TYPE_OS_FS_DIR = 30,
	MEM_TYPE_OS_DIR_CHANGE_NOTIFICATION = 31,
	MEM_TYPE_OS_TLS_CLIENT_CONNECTION = 32,
	MEM_TYPE_OS_DER_PARSER = 33,
	MEM_TYPE_OS_X509_CERTIFICATE = 34,
	MEM_TYPE_OS_WEBCLIENT_CONNECTION_STR = 35,
	MEM_TYPE_OS_GENA_SERVICE = 36,
	MEM_TYPE_OS_GENA_SUBSCRIPTION = 37,
	MEM_TYPE_OS_GENA_SUBSCRIPTION_CALLBACK_URI = 38,
	MEM_TYPE_OS_GENA_SERVICE_CONNECTION = 39,
	MEM_TYPE_OS_GENA_CONNECTION_CALLBACK_URI = 40,
	MEM_TYPE_OS_SOAP_SERVICE = 41,
	MEM_TYPE_OS_SOAP_SERVICE_CONNECTION = 42,
	MEM_TYPE_OS_SOAP_ACTION_VAR_NAME = 43,
	MEM_TYPE_OS_SOAP_ACTION_ARGS_ARG = 44,
	MEM_TYPE_OS_SOAP_MESSAGE_STR = 45,
	MEM_TYPE_OS_SSDP_SERVICE = 46,
	MEM_TYPE_OS_SSDP_REPLY = 47,
	MEM_TYPE_OS_GENA_MESSAGE_STR = 48,
	MEM_TYPE_OS_SOAP_CLIENT = 49,
	MEM_TYPE_OS_SOAP_CLIENT_STR = 50,
	MEM_TYPE_OS_SOAP_CLIENT_REQUEST = 51,
	MEM_TYPE_OS_SSDP_CLIENT = 52,
	MEM_TYPE_OS_SSDP_CLIENT_STR = 53,
	MEM_TYPE_OS_SSDP_CLIENT_DEVICE = 54,
	MEM_TYPE_OS_UPNP_DESCRIPTOR = 55,
	MEM_TYPE_OS_UPNP_DESCRIPTOR_LOADER = 56,
	MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE = 57,
	MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE_PARAM = 58,
	MEM_TYPE_OS_UPNP_DESCRIPTOR_DEVICE_SERVICE = 59,
	MEM_TYPE_OS_WEBSERVER = 60,
	MEM_TYPE_OS_WEBSERVER_PAGE = 61,
	MEM_TYPE_OS_WEBSERVER_PAGE_FILESYSTEM_FILENAME = 62,
	MEM_TYPE_OS_WEBSERVER_PAGE_FILESYSTEM_STATE = 63,
	MEM_TYPE_OS_WEBSERVER_PAGE_PROXY_STATE = 64,
	MEM_TYPE_OS_WEBSERVER_PAGE_PROXY_NAME = 65,
	MEM_TYPE_OS_WEBSERVER_PAGE_PROXY_URI = 66,
	MEM_TYPE_OS_WEBSERVER_CONNECTION = 67,
	MEM_TYPE_OS_WEBSERVER_HTTP_SERVER = 68,
	MEM_TYPE_OS_WEBSERVER_HTTP_SERVER_CONNECTION = 69,
	MEM_TYPE_OS_HTTP_SERVER = 70,
	MEM_TYPE_OS_HTTP_SERVER_SERVICE = 71,
	MEM_TYPE_OS_HTTP_SERVER_CONNECTION = 72,
	MEM_TYPE_OS_FILE_ASYNC = 73,
	MEM_TYPE_OS_RSA_KEY = 74,
	MEM_TYPE_OS_CRYPT_BUFFER = 75,
};
