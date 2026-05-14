/*
 * Service abstraction header.
 */
#ifndef _SERVICE_H
#define _SERVICE_H

#include "goodbyedpi.h"

#ifdef _WIN32
/*
 * Windows: original service API used by goodbyedpi.c
 * The old service.c provides these functions.
 */
int service_register(int argc, char *argv[]);
void service_main(int argc, char *argv[]);
void service_controlhandler(DWORD request);
#else
/*
 * Linux/macOS: platform abstraction API
 */
#include "platform/platform.h"
/* service_try_register and service_signal_stop declared in platform.h */
#endif

#endif /* _SERVICE_H */
