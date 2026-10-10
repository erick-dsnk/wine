/*
 * Test-only Linux interposer for one private-backing creation failure.
 * Fail both backing-store candidates (memfd and temporary-file fallback).
 * This library is free software; you can redistribute it and/or modify it
 * under the GNU Lesser General Public License, version 2.1 or later.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned int failures_left = 2;

ssize_t pwrite( int fd, const void *buffer, size_t count, off_t offset )
{
    static ssize_t (*next_pwrite)( int, const void *, size_t, off_t );

    if (!next_pwrite) next_pwrite = dlsym( RTLD_NEXT, "pwrite" );
    if (getenv( "WINE_PRIVATE_BACKING_INJECT_CREATE" ) && count == 1 && offset == 0x39000 &&
        failures_left)
    {
        struct stat info;
        int inspected = !fstat( fd, &info );

        failures_left--;
        fprintf( stderr, "private-backing-create-fail: hit pid=%ld fd=%d offset=%#lx left=%u inode=%llu device=%llu inspected=%d\n",
                 (long)getpid(), fd, (unsigned long)offset, failures_left,
                 inspected ? (unsigned long long)info.st_ino : 0,
                 inspected ? (unsigned long long)info.st_dev : 0, inspected );
        errno = ENOSPC;
        return -1;
    }
    return next_pwrite( fd, buffer, count, offset );
}
