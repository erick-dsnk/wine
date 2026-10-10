/*
 * Benign native collision helper: replace only a verified identity-backed noaccess
 * guest reservation, never an existing mapping. No target data is copied.
 * LGPL 2.1 or later; see a1b-live-private-view-pe.c.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <poll.h>
#include <sys/syscall.h>
#include <signal.h>
#include <time.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#define WINE_UNIX_LIB
#include "wine/unixlib.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
struct collision_args { UINT64 address, size; UINT action; };
static void *collision;
static size_t collision_size;
static int reservation_fd = -1;
static off_t reservation_offset;
static int watched_pidfd = -1;
/* Test-only recipient control: no runtime scheduler hooks or fabricated ACK.
 * Mask only the main's Wine system-APC notification signal. SIGQUIT stays live
 * so TerminateThread performs the real server queue cancellation. */
static NTSTATUS cancellation_barrier( unsigned int action, UINT64 phase )
{
    const char *directory = getenv( "A1B_VIEW_GATE_DIR" );
    char path[1024];
    struct timespec start, now, delay = { 0, 1000000 };
    sigset_t mask;
    int fd;
    if (!directory || phase > 1) return STATUS_INVALID_PARAMETER;
    if (action == 5)
    {
        sigemptyset( &mask ); sigaddset( &mask, SIGUSR1 );
        if (sigprocmask( SIG_BLOCK, &mask, NULL )) return STATUS_UNSUCCESSFUL;
        sigemptyset( &mask ); sigaddset( &mask, SIGQUIT );
        if (sigprocmask( SIG_UNBLOCK, &mask, NULL )) return STATUS_UNSUCCESSFUL;
        snprintf( path, sizeof(path), "%s/parked-%s", directory, phase ? "revoke" : "map" );
        if ((fd = open( path, O_WRONLY | O_CREAT | O_TRUNC, 0600 )) == -1) return STATUS_UNSUCCESSFUL;
        close( fd );
        sigprocmask( SIG_BLOCK, NULL, &mask );
        fprintf( stderr, "a1b-cancellation: native-main SIGUSR1_blocked=%d SIGQUIT_blocked=%d\n",
                 sigismember( &mask, SIGUSR1 ), sigismember( &mask, SIGQUIT ) );
    }
    else
    {
        sigprocmask( SIG_BLOCK, NULL, &mask );
        fprintf( stderr, "a1b-cancellation: native-survivor action=%u SIGUSR1_blocked=%d SIGQUIT_blocked=%d\n",
                 action, sigismember( &mask, SIGUSR1 ), sigismember( &mask, SIGQUIT ) );
        snprintf( path, sizeof(path), "%s/%s-%s", directory,
                  action == 6 ? "parked" : "kill", phase ? "revoke" : "map" );
    }
    clock_gettime( CLOCK_MONOTONIC, &start );
    do
    {
        if (action != 5 && !access( path, F_OK )) return STATUS_SUCCESS;
        nanosleep( &delay, NULL );
        clock_gettime( CLOCK_MONOTONIC, &now );
    } while (now.tv_sec - start.tv_sec < 10);
    fprintf( stderr, "a1b-cancellation: native barrier timed out action=%u phase=%s\n",
             action, phase ? "revoke" : "map" );
    return STATUS_TIMEOUT;
}
static NTSTATUS collision_call( void *arguments )
{
    struct collision_args *args = arguments;
    void *address = (void *)(ULONG_PTR)args->address, *mapped;
    size_t size = args->size;
    FILE *maps;
    char line[1024], permissions[5], extra[2];
    unsigned long start, end, offset, inode;
    unsigned int device_major, device_minor;
    BOOL reserved = FALSE;
    if (args->action == 8)
    {
        static const char *paths[] = { "/proc/self/maps", "/proc/thread-self/maps" };
        unsigned int index, count;
        for (index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index)
        {
            count = 0;
            if (!(maps = fopen( paths[index], "r" ))) return STATUS_UNSUCCESSFUL;
            while (fgets( line, sizeof(line), maps ))
            {
                ++count;
                if (sscanf( line, "%lx-%lx", &start, &end ) == 2 && start <= 0x23010000 && end > 0x23000000)
                    fprintf( stderr, "a1b-cancellation: native-survivor %s PROBE mapping %s", paths[index], line );
            }
            fclose( maps );
            fprintf( stderr, "a1b-cancellation: native-survivor %s mapping_count=%u\n", paths[index], count );
        }
        return STATUS_SUCCESS;
    }
    if (args->action >= 5 && args->action <= 7)
        return cancellation_barrier( args->action, args->address );
    if (args->action == 2)
    {
        args->address = getpid();
        return STATUS_SUCCESS;
    }
    if (args->action == 3)
    {
#ifdef SYS_pidfd_open
        if (watched_pidfd != -1) close( watched_pidfd );
        watched_pidfd = syscall( SYS_pidfd_open, (pid_t)args->address, 0 );
        return watched_pidfd == -1 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
#else
        return STATUS_NOT_SUPPORTED;
#endif
    }
    if (args->action == 4)
    {
        struct pollfd pollfd = { watched_pidfd, POLLIN, 0 };
        if (watched_pidfd == -1) return STATUS_INVALID_HANDLE;
        if (poll( &pollfd, 1, 0 ) != 1 || !(pollfd.revents & POLLIN)) return STATUS_PENDING;
        close( watched_pidfd ); watched_pidfd = -1;
        return STATUS_SUCCESS;
    }
    if (address != (void *)0x23000000 || size != 0x10000) return STATUS_INVALID_PARAMETER;
    if (args->action == 0)
    {
        if (collision) return STATUS_INVALID_PARAMETER;
        if (!(maps = fopen( "/proc/self/maps", "r" ))) return STATUS_UNSUCCESSFUL;
        while (fgets( line, sizeof(line), maps ))
        {
            int count = sscanf( line, "%lx-%lx %4s %lx %x:%x %lu %1s", &start, &end,
                                permissions, &offset, &device_major, &device_minor, &inode, extra );
            if (count >= 7 && start <= args->address && end >= args->address + size &&
                !strcmp( permissions, "---p" ) && inode && strstr( line, "memfd:" ))
            {
                DIR *fds = opendir( "/proc/self/fd" );
                struct dirent *entry;
                struct stat stat;
                if (!fds) break;
                while ((entry = readdir( fds )))
                {
                    char *tail;
                    int candidate = strtol( entry->d_name, &tail, 10 );
                    if (*tail || candidate < 0 || fstat( candidate, &stat )) continue;
                    if ((unsigned long)stat.st_ino != inode || major(stat.st_dev) != device_major ||
                        minor(stat.st_dev) != device_minor) continue;
                    if ((reservation_fd = dup( candidate )) < 0) break;
                    reservation_offset = offset + args->address - start;
                    reserved = TRUE; break;
                }
                closedir( fds );
                break;
            }
        }
        fclose( maps );
        if (!reserved) return STATUS_CONFLICTING_ADDRESSES;
        if (munmap( address, size )) return STATUS_UNSUCCESSFUL;
        mapped = mmap( address, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0 );
        if (mapped != address)
        {
            if (mapped != MAP_FAILED) munmap( mapped, size );
            /* No MAP_FIXED fallback: preserve a raced-in mapping. */
            mmap( address, size, PROT_NONE, MAP_PRIVATE | MAP_FIXED_NOREPLACE, reservation_fd, reservation_offset );
            close( reservation_fd ); reservation_fd = -1;
            return STATUS_CONFLICTING_ADDRESSES;
        }
        collision = mapped; collision_size = size;
        *(volatile BYTE *)mapped = 0xcc;
        *((volatile BYTE *)mapped + size - 1) = 0xcc;
        return STATUS_SUCCESS;
    }
    if (args->action != 1 || collision != address || collision_size != size)
        return STATUS_INVALID_PARAMETER;
    if (munmap( collision, collision_size )) return STATUS_UNSUCCESSFUL;
    collision = NULL; collision_size = 0;
    mapped = mmap( address, size, PROT_NONE, MAP_PRIVATE | MAP_FIXED_NOREPLACE, reservation_fd, reservation_offset );
    close( reservation_fd ); reservation_fd = -1;
    if (mapped != address)
    {
        if (mapped != MAP_FAILED) munmap( mapped, size );
        return STATUS_CONFLICTING_ADDRESSES;
    }
    return STATUS_SUCCESS;
}
const unixlib_entry_t __wine_unix_call_funcs[] = { collision_call };
