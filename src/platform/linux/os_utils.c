/*
 * Linux OS Utilities Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "../platform.h"

void os_flush_dns_cache(void) {
    /*
     * Try multiple methods to flush DNS cache on Linux:
     * 1. systemd-resolve (modern systemd systems)
     * 2. resolvectl (newer systemd)
     * 3. nscd (if running)
     */
    int ret;

    ret = system("resolvectl flush-caches 2>/dev/null");
    if (ret == 0) return;

    ret = system("systemd-resolve --flush-caches 2>/dev/null");
    if (ret == 0) return;

    ret = system("nscd -i hosts 2>/dev/null");
    if (ret == 0) return;

    /* If none worked, it's not critical - DNS cache may not be running */
    printf("Note: Could not flush DNS cache (no systemd-resolved or nscd running)\n");
}

int os_random_uint32(uint32_t *out) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback: try getrandom() style */
        *out = (uint32_t)rand();
        return 0;
    }

    ssize_t n = read(fd, out, sizeof(*out));
    close(fd);

    if (n != sizeof(*out)) {
        return -1;
    }
    return 0;
}

void os_security_init(void) {
    /*
     * On Linux, security hardening is typically handled by:
     * - Running as non-root where possible (but we need root for nfqueue)
     * - seccomp filters (could be added later)
     * - Dropping capabilities after setup
     *
     * For now, just ensure we're running as root (required for nfqueue).
     */
    if (geteuid() != 0) {
        printf("WARNING: GoodbyeDPI requires root privileges for packet interception.\n"
               "Please run with sudo or as root.\n");
    }
}

void os_get_error_string(char *buf, size_t bufsize) {
    int err = errno;
    snprintf(buf, bufsize, "Error %d: %s", err, strerror(err));
}
