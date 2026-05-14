/*
 * GoodbyeDPI — Passive DPI blocker and Active DPI circumvention utility.
 * Cross-platform header.
 */

#ifndef _GOODBYEDPI_H
#define _GOODBYEDPI_H

#define HOST_MAXLEN 253
#define MAX_PACKET_SIZE 9016

#ifndef DEBUG
#define debug(...) do {} while (0)
#else
#define debug(...) printf(__VA_ARGS__)
#endif

/* Platform-independent boolean */
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Platform-independent type aliases for compatibility with existing code */
#ifdef _WIN32
    #include <windows.h>
    #include <winsock2.h>
    /* BYTE, UINT, BOOL, HANDLE etc. already defined by windows.h */
#else
    #include <stdint.h>
    #include <arpa/inet.h>
    typedef uint8_t BYTE;
    typedef unsigned int UINT;
    typedef int BOOL;
    typedef void* HANDLE;
    typedef void* PVOID;
    typedef char* LPTSTR;
    typedef unsigned long DWORD;
    typedef unsigned short WORD;
    #define INVALID_HANDLE_VALUE ((void*)-1)
#endif

int main(int argc, char *argv[]);
void deinit_all(void);

#endif /* _GOODBYEDPI_H */
