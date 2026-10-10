/*
 * LD_PRELOAD failure fixture for managed target admission/lifetime tests.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include "wine/managed_layout.h"

void *mmap( void *addr, size_t size, int prot, int flags, int fd, off_t offset )
{
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t);
    const char *setting = getenv( "PROTON_MANAGED_FAIL_RESERVED" );

    if (!real_mmap) real_mmap = dlsym( RTLD_NEXT, "mmap" );
    if (setting && !strcmp( setting, "1" ) && size == 0x730000 && (flags & MAP_FIXED) &&
        (flags & MAP_ANONYMOUS) && (uintptr_t)addr >= WINE_MANAGED_GUEST_START &&
        (uintptr_t)addr < WINE_MANAGED_GUEST_END)
    {
        static const char message[] = "managed-layout-inject: reserved mmap ENOMEM\n";
        write( 2, message, sizeof(message) - 1 );
        errno = ENOMEM;
        return MAP_FAILED;
    }
    return real_mmap( addr, size, prot, flags, fd, offset );
}

int setenv( const char *name, const char *value, int overwrite )
{
    static int (*real_setenv)(const char *, const char *, int);
    const char *setting = getenv( "PROTON_MANAGED_FAIL_CHILD_ENV" );

    if (!real_setenv) real_setenv = dlsym( RTLD_NEXT, "setenv" );
    if (setting && !strcmp( setting, "1" ) && !strcmp( name, "WINE_MANAGED_LAYOUT" ))
    {
        static const char message[] = "managed-layout-inject: child layout setenv ENOMEM\n";
        write( 2, message, sizeof(message) - 1 );
        errno = ENOMEM;
        return -1;
    }
    return real_setenv( name, value, overwrite );
}
