/*
 * Native Linux AMD64 syscall-boundary controls for the benign live-view proof.
 * LD_PRELOAD this only in disposable fixture runs. Controls are one-shot files:
 * arm-map, arm-revoke; gate-map, gate-revoke; entered-map, entered-revoke;
 * release-map, release-revoke. No proprietary process is involved.
 * LGPL 2.1 or later; see a1b-live-private-view-pe.c.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#define ADDRESS ((void *)0x23000000)
#define SIZE 0x10000
#define MAP_FIXED_NOREPLACE_VALUE 0x100000

static long syscall6( long nr, long a1, long a2, long a3, long a4, long a5, long a6 )
{
    long result;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile ("syscall" : "=a"(result) : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
                      "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
static int marker( const char *dir, const char *name, const char *phase, int consume )
{
    char path[1024];
    long fd;
    snprintf( path, sizeof(path), "%s/%s-%s", dir, name, phase );
    fd = syscall6( SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0 );
    if (fd < 0) return 0;
    syscall6( SYS_close, fd, 0, 0, 0, 0, 0 );
    if (consume) syscall6( SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0 );
    return 1;
}
static void entered( const char *dir, const char *phase )
{
    char path[1024];
    long fd;
    snprintf( path, sizeof(path), "%s/entered-%s", dir, phase );
    fd = syscall6( SYS_openat, AT_FDCWD, (long)path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600, 0, 0 );
    if (fd >= 0)
    {
        const char evidence[] = "native syscall boundary entered\n";
        syscall6( SYS_write, fd, (long)evidence, sizeof(evidence)-1, 0, 0, 0 );
        syscall6( SYS_close, fd, 0, 0, 0, 0, 0 );
    }
}
static unsigned long long milliseconds(void)
{
    struct timespec time;
    syscall6( SYS_clock_gettime, CLOCK_MONOTONIC, (long)&time, 0, 0, 0, 0 );
    return (unsigned long long)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}
void *mmap( void *address, size_t size, int prot, int flags, int fd, off_t offset )
{
    const char *dir = getenv( "A1B_VIEW_GATE_DIR" );
    const char *role = getenv( "WINE_MANAGED_LAYOUT" );
    const char *phase = NULL;
    long result;
    if (dir && role && strstr( role, ":executor:" ) && address == ADDRESS && size == SIZE)
    {
        if ((flags & MAP_SHARED) && (flags & MAP_FIXED_NOREPLACE_VALUE))
            phase = "map";
        else if ((flags & MAP_FIXED) && !(flags & MAP_FIXED_NOREPLACE_VALUE) && prot == PROT_NONE)
            phase = "revoke";
    }
    if (phase && marker( dir, "arm", phase, 1 ))
    {
        entered( dir, phase );
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (phase && marker( dir, "gate", phase, 1 ))
    {
        struct timespec pause = { 0, 1000000 };
        unsigned long long start = milliseconds();
        entered( dir, phase );
        /* A stalled controller cannot hang the executor or target forever.
         * This 2-second bound is below the server's 5-second revoke timeout. */
        while (!marker( dir, "release", phase, 1 ) && milliseconds() - start < 2000)
            syscall6( SYS_nanosleep, (long)&pause, 0, 0, 0, 0, 0 );
    }
    result = syscall6( SYS_mmap, (long)address, size, prot, flags, fd, offset );
    if ((unsigned long)result >= (unsigned long)-4095)
    {
        errno = -result;
        return MAP_FAILED;
    }
    return (void *)result;
}
