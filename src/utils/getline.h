#ifndef _UTILS_GETLINE_H
#define _UTILS_GETLINE_H

#include <stdio.h>

/*
 * On Windows (MinGW), getline/getdelim are not available.
 * On POSIX systems (Linux, macOS), they are part of stdio.h.
 */
#ifdef _WIN32
    #define HAVE_GETDELIM 0
    #define HAVE_GETLINE 0
#else
    #define HAVE_GETDELIM 1
    #define HAVE_GETLINE 1
#endif

#if !HAVE_GETDELIM
ssize_t getdelim(char **, size_t *, int, FILE *);
#endif

#if !HAVE_GETLINE
ssize_t getline(char **, size_t *, FILE *);
#endif

#endif /* _UTILS_GETLINE_H */
