/*
 * Linux Service/Daemon Implementation
 *
 * Supports running as a systemd service or traditional daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "../platform.h"

static int is_systemd_service(void) {
    /* Check if we're running under systemd by checking NOTIFY_SOCKET or INVOCATION_ID */
    return (getenv("NOTIFY_SOCKET") != NULL || getenv("INVOCATION_ID") != NULL);
}

int service_try_register(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /*
     * On Linux, if running under systemd, we don't need to daemonize.
     * systemd handles process management.
     *
     * If running standalone and user passes --daemon flag, we could fork.
     * For now, we just return 0 (run as normal process).
     */

    if (is_systemd_service()) {
        /* Running under systemd - no need to daemonize */
        return 0;
    }

    /* Check for --daemon flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-D") == 0) {
            /* Traditional daemon fork */
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork failed");
                exit(EXIT_FAILURE);
            }
            if (pid > 0) {
                /* Parent exits */
                printf("GoodbyeDPI daemon started with PID %d\n", pid);
                return 1; /* Signal caller to exit */
            }

            /* Child continues */
            umask(0);
            setsid();

            /* Redirect stdio to /dev/null */
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > 2) close(devnull);
            }

            return 0; /* Continue running as daemon */
        }
    }

    return 0; /* Run as normal process */
}

void service_signal_stop(void) {
    /* Nothing special needed on Linux - signal handlers handle cleanup */
}
