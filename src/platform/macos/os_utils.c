/*
 * macOS OS Utilities Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../platform.h"

void os_flush_dns_cache(void) {
    /*
     * macOS DNS cache flush command varies by version:
     * - macOS 12+: dscacheutil -flushcache; sudo killall -HUP mDNSResponder
     * - macOS 10.12+: sudo killall -HUP mDNSResponder
     */
    system("dscacheutil -flushcache 2>/dev/null");
    system("killall -HUP mDNSResponder 2>/dev/null");
}

int os_random_uint32(uint32_t *out) {
    /* macOS has arc4random which is always available and doesn't need seeding */
    *out = arc4random();
    return 0;
}

void os_security_init(void) {
    /*
     * On macOS, security is primarily handled by:
     * - Code signing and notarization
     * - System Integrity Protection (SIP)
     * - App Sandbox (not applicable for CLI tools)
     *
     * Check for root privileges since we need them for divert sockets.
     */
    if (geteuid() != 0) {
        printf("WARNING: GoodbyeDPI requires root privileges for packet interception.\n"
               "Please run with sudo.\n");
    }
}

void os_get_error_string(char *buf, size_t bufsize) {
    int err = errno;
    snprintf(buf, bufsize, "Error %d: %s", err, strerror(err));
}
