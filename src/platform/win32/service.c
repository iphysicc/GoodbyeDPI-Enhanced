/*
 * Windows Service Implementation
 */

#include <windows.h>
#include <stdio.h>
#include "../platform.h"
#include "../../goodbyedpi.h"

#define SERVICE_NAME "GoodbyeDPI"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;
static int service_argc = 0;
static char **service_argv = NULL;

/* Forward declarations */
static void WINAPI service_main_internal(DWORD argc, LPTSTR *argv);
static void WINAPI service_controlhandler(DWORD request);

int service_try_register(int argc, char *argv[]) {
    int i, ret;
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main_internal},
        {NULL, NULL}
    };

    /*
     * Save argc & argv as service_main is called with different
     * arguments, which are passed from "start" command, not
     * from the program command line.
     */
    if (!service_argc && !service_argv) {
        service_argc = argc;
        service_argv = calloc((size_t)(argc + 1), sizeof(void*));
        for (i = 0; i < argc; i++) {
            service_argv[i] = strdup(argv[i]);
        }
    }

    ret = StartServiceCtrlDispatcher(ServiceTable);

    if (service_argc && service_argv) {
        for (i = 0; i < service_argc; i++) {
            free(service_argv[i]);
        }
        free(service_argv);
        service_argv = NULL;
        service_argc = 0;
    }

    return ret ? 1 : 0;
}

static void WINAPI service_main_internal(DWORD argc, LPTSTR *argv) {
    (void)argc;
    (void)argv;

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 1;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, service_controlhandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        return;
    }

    SetServiceStatus(hStatus, &ServiceStatus);

    /* Call main with saved argc & argv */
    ServiceStatus.dwWin32ExitCode = (DWORD)main(service_argc, service_argv);
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
}

static void WINAPI service_controlhandler(DWORD request) {
    switch (request) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            deinit_all();
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            break;
        default:
            break;
    }
    SetServiceStatus(hStatus, &ServiceStatus);
}

void service_signal_stop(void) {
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
}
