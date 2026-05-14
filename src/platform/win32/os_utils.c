/*
 * Windows OS Utilities Implementation
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#define _CRT_RAND_S
#include "../platform.h"

void os_flush_dns_cache(void) {
    typedef INT_PTR (WINAPI *DnsFlushResolverCache_t)(void);
    DnsFlushResolverCache_t DnsFlushResolverCache;

    HMODULE dnsapi = LoadLibrary("dnsapi.dll");
    if (dnsapi == NULL) {
        printf("Can't load dnsapi.dll to flush DNS cache!\n");
        return;
    }

    DnsFlushResolverCache = (DnsFlushResolverCache_t)GetProcAddress(dnsapi, "DnsFlushResolverCache");
    if (DnsFlushResolverCache == NULL || !DnsFlushResolverCache())
        printf("Can't flush DNS cache!\n");
    FreeLibrary(dnsapi);
}

int os_random_uint32(uint32_t *out) {
    unsigned int val;
    if (rand_s(&val) != 0) {
        return -1;
    }
    *out = (uint32_t)val;
    return 0;
}

void os_security_init(void) {
    /* Prevent DLL hijacking */
    SetDllDirectory("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE |
                      BASE_SEARCH_PATH_PERMANENT);
}

void os_get_error_string(char *buf, size_t bufsize) {
    DWORD errorcode = GetLastError();
    LPTSTR errormessage = NULL;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)&errormessage, 0, NULL);

    if (errormessage) {
        snprintf(buf, bufsize, "Error %lu: %s", (unsigned long)errorcode, errormessage);
        LocalFree(errormessage);
    } else {
        snprintf(buf, bufsize, "Error %lu: Unknown", (unsigned long)errorcode);
    }
}
