/*
 * macOS Service/Daemon Implementation
 *
 * Supports running as a launchd daemon or standalone process.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../platform.h"

int service_try_register(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /*
     * On macOS, launchd manages daemons. If we're launched by launchd,
     * we just run normally (launchd handles lifecycle).
     *
     * If running standalone with --daemon flag, we can fork.
     */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-D") == 0) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork failed");
                exit(EXIT_FAILURE);
            }
            if (pid > 0) {
                printf("GoodbyeDPI daemon started with PID %d\n", pid);
                return 1;
            }

            /* Child */
            umask(0);
            setsid();

            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > 2) close(devnull);
            }

            return 0;
        }
    }

    return 0;
}

void service_signal_stop(void) {
    /* Nothing special needed on macOS */
}
