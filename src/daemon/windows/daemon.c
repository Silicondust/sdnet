/*
 * daemon.c
 *
 * Copyright © 2015 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("daemon");

static uint16_t daemon_name_wstr[128];
static SERVICE_STATUS_HANDLE daemon_svc_status_handle;
static SERVICE_STATUS daemon_svc_status;

uint8_t daemon_status(const char *exe_name, const char *daemon_name)
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (!sc_manager) {
		return DAEMON_FAILED;
	}

	uint16_t daemon_name_wstr[128];
	str_utf8_to_utf16(daemon_name_wstr, daemon_name_wstr + 128, daemon_name);

	SC_HANDLE sc_service = OpenServiceW(sc_manager, (wchar_t *)daemon_name_wstr, GENERIC_READ);
	if (!sc_service) {
		DWORD error = GetLastError();
		CloseServiceHandle(sc_manager);
		if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
			return DAEMON_NOT_RUNNING;
		}

		return DAEMON_FAILED;
	}

	SERVICE_STATUS service_status;
	if (!QueryServiceStatus(sc_service, &service_status)) {
		CloseServiceHandle(sc_service);
		CloseServiceHandle(sc_manager);
		return DAEMON_FAILED;
	}

	CloseServiceHandle(sc_service);
	CloseServiceHandle(sc_manager);

	if (service_status.dwCurrentState != SERVICE_RUNNING) {
		return DAEMON_NOT_RUNNING;
	}
	
	return DAEMON_RUNNING;
}

uint8_t daemon_stop(const char *exe_name, const char *daemon_name)
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (!sc_manager) {
		return DAEMON_FAILED;
	}

	uint16_t daemon_name_wstr[128];
	str_utf8_to_utf16(daemon_name_wstr, daemon_name_wstr + 128, daemon_name);

	SC_HANDLE sc_service = OpenServiceW(sc_manager, (wchar_t *)daemon_name_wstr, GENERIC_READ | GENERIC_EXECUTE);
	if (!sc_service) {
		DWORD error = GetLastError();
		CloseServiceHandle(sc_manager);

		if (error == ERROR_ACCESS_DENIED) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	SERVICE_STATUS service_status;
	if (!ControlService(sc_service, SERVICE_CONTROL_STOP, &service_status)) {
		DWORD error = GetLastError();
		CloseServiceHandle(sc_service);
		CloseServiceHandle(sc_manager);

		if (error == ERROR_SERVICE_NOT_ACTIVE) {
			return DAEMON_NOT_RUNNING;
		}

		if (error == ERROR_ACCESS_DENIED) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	CloseServiceHandle(sc_service);
	CloseServiceHandle(sc_manager);
	return DAEMON_SUCCESS;
}

uint8_t daemon_start(const char *exe_name, const char *daemon_name)
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (!sc_manager) {
		return DAEMON_FAILED;
	}

	uint16_t daemon_name_wstr[128];
	str_utf8_to_utf16(daemon_name_wstr, daemon_name_wstr + 128, daemon_name);

	SC_HANDLE sc_service = OpenServiceW(sc_manager, (wchar_t *)daemon_name_wstr, GENERIC_READ | GENERIC_EXECUTE);
	if (!sc_service) {
		DWORD error = GetLastError();
		CloseServiceHandle(sc_manager);

		if (error == ERROR_ACCESS_DENIED) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	if (!StartServiceW(sc_service, 0, NULL)) {
		DWORD error = GetLastError();
		CloseServiceHandle(sc_service);
		CloseServiceHandle(sc_manager);

		if (error == ERROR_SERVICE_ALREADY_RUNNING) {
			return DAEMON_RUNNING;
		}

		if (error == ERROR_ACCESS_DENIED) {
			return DAEMON_ACCESS_DENIED;
		}

		return DAEMON_FAILED;
	}

	CloseServiceHandle(sc_service);
	CloseServiceHandle(sc_manager);
	return DAEMON_SUCCESS;
}

static DWORD WINAPI daemon_main_handler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl) {
	case SERVICE_CONTROL_INTERROGATE:
		SetServiceStatus(daemon_svc_status_handle, &daemon_svc_status);
		return NO_ERROR;

	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		daemon_svc_status.dwCurrentState = SERVICE_STOPPED;
		daemon_svc_status.dwControlsAccepted = 0;
		SetServiceStatus(daemon_svc_status_handle, &daemon_svc_status);
		return NO_ERROR;

	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

static void WINAPI daemon_main(DWORD argc, LPWSTR *argv)
{
	daemon_svc_status_handle = RegisterServiceCtrlHandlerExW((wchar_t *)daemon_name_wstr, daemon_main_handler, NULL);
	if (!daemon_svc_status_handle) {
		return;
	}

	daemon_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	daemon_svc_status.dwCurrentState = SERVICE_RUNNING;
	daemon_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	SetServiceStatus(daemon_svc_status_handle, &daemon_svc_status);

	os_main(0, NULL);

	daemon_svc_status.dwCurrentState = SERVICE_STOPPED;
	daemon_svc_status.dwControlsAccepted = 0;
	SetServiceStatus(daemon_svc_status_handle, &daemon_svc_status);
}

bool daemon_register_service_dispatcher(const char *daemon_name)
{
	str_utf8_to_utf16(daemon_name_wstr, daemon_name_wstr + 128, daemon_name);

	SERVICE_TABLE_ENTRYW service_table[2];
	service_table[0].lpServiceName = (wchar_t *)daemon_name_wstr;
	service_table[0].lpServiceProc = daemon_main;
	service_table[1].lpServiceName = NULL;
	service_table[1].lpServiceProc = NULL;
	return StartServiceCtrlDispatcherW(service_table);
}
