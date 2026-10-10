/*
 * Standalone native ELF fixture for the experimental managed executor layout.
 * Build as a PIE and run through the Wine preloader before ntdll/PE bootstrap.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "wine/managed_layout.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error "managed executor fixture requires Linux AMD64"
#endif

struct wine_preload_info { void *addr; size_t size; };

/* The preloader resolves these exported storage slots in the main ELF and
 * writes the descriptor and reservation list into them before main(). */
const struct wine_preload_info *wine_main_preload_info;
const struct wine_managed_layout *wine_main_managed_layout;
void *wine_r_debug;

static unsigned int failures;

static void check( int condition, const char *description )
{
    if (!condition)
    {
        fprintf( stderr, "managed-executor: FAIL: %s\n", description );
        failures++;
    }
}

static int outside_managed_ranges( const void *ptr )
{
    uintptr_t value = (uintptr_t)ptr;

    return value < WINE_MANAGED_GUEST_START || value >= WINE_MANAGED_HOST_END;
}

static void check_native_address( const void *ptr, const char *description )
{
    if (!outside_managed_ranges( ptr ))
    {
        fprintf( stderr, "managed-executor: FAIL: %s at %p is inside guest/host PE ranges\n",
                 description, ptr );
        failures++;
    }
}

/* Read /proc/self/maps only.  The reservation may be represented by one
 * merged VMA or several adjacent VMAs after endpoint protection checks. */
static int check_reserved_span( unsigned long long start, unsigned long long end,
                                const char *description )
{
    FILE *maps = fopen( "/proc/self/maps", "r" );
    char *line = NULL;
    size_t capacity = 0;
    unsigned long long cursor = start, map_start, map_end;
    char protection[5];
    int valid = 1;

    check( !!maps, "open own /proc/self/maps read-only" );
    if (!maps) return 0;
    check_native_address( maps, "native maps FILE state" );

    while (getline( &line, &capacity, maps ) != -1)
    {
        check_native_address( line, "native maps parser buffer" );
        if (sscanf( line, "%llx-%llx %4s", &map_start, &map_end, protection ) != 3) continue;
        if (map_end <= cursor || map_start >= end) continue;
        if (map_start > cursor)
        {
            check( 0, description );
            valid = 0;
        }
        if (protection[0] != '-' || protection[1] != '-' || protection[2] != '-')
        {
            check( 0, "managed reserved span is PROT_NONE" );
            valid = 0;
        }
        cursor = map_end < end ? map_end : end;
        if (cursor == end) break;
    }

    if (cursor != end)
    {
        check( 0, description );
        valid = 0;
    }
    free( line );
    fclose( maps );
    return valid;
}

/* Change protections only on pages already verified as this process's
 * PROT_NONE reservation.  mprotect preserves the owned mapping and cannot
 * replace an unrelated VMA as MAP_FIXED would. */
static void check_owned_endpoint( unsigned long long address, const char *description )
{
    long page_size = sysconf( _SC_PAGESIZE );
    volatile unsigned char *page = (volatile unsigned char *)(uintptr_t)address;
    unsigned char expected = 0x5a;

    check( page_size > 0 && !(address % page_size), "reserved endpoint is page-aligned" );
    if (page_size <= 0 || address % page_size) return;
    if (mprotect( (void *)page, page_size, PROT_READ | PROT_WRITE ))
    {
        fprintf( stderr, "managed-executor: FAIL: %s mprotect writable: %m\n", description );
        failures++;
        return;
    }
    *page = expected;
    check( *page == expected, description );
    if (mprotect( (void *)page, page_size, PROT_NONE ))
    {
        fprintf( stderr, "managed-executor: FAIL: %s restore PROT_NONE: %m\n", description );
        failures++;
    }
}

static void *thread_main( void *arg )
{
    pthread_attr_t attr;
    void *stack = NULL;
    size_t size = 0;
    int status;

    (void)arg;
    status = pthread_getattr_np( pthread_self(), &attr );
    check( !status, "inspect native default pthread attributes" );
    if (status) return (void *)1;
    status = pthread_attr_getstack( &attr, &stack, &size );
    pthread_attr_destroy( &attr );
    check( !status && stack && size, "read native default pthread stack" );
    if (!status && stack) check_native_address( stack, "native default pthread stack" );
    printf( "native default pthread stack %p size %#zx\n", stack, size );
    return status ? (void *)1 : NULL;
}

int main( void )
{
    const struct wine_managed_executor_layout *layout;
    FILE *maps;
    char *line = NULL;
    size_t line_capacity = 0;
    void *mapping, *heap, *library, *symbol, *thread_result = NULL;
    pthread_t thread;
    int thread_status;
    int guest_reserved, host_reserved;
    int descriptor_valid, preload_valid;

    layout = (const struct wine_managed_executor_layout *)wine_main_managed_layout;
    descriptor_valid = layout && layout->common.version == WINE_MANAGED_EXECUTOR_VERSION &&
           layout->common.role == WINE_MANAGED_LAYOUT_EXECUTOR &&
           layout->common.guest_start == WINE_MANAGED_GUEST_START &&
           layout->common.guest_end == WINE_MANAGED_GUEST_END &&
           layout->size == 96 && sizeof(*layout) == 96 &&
           layout->layout_id == 2 &&
           layout->host_start == WINE_MANAGED_HOST_START &&
           layout->host_end == WINE_MANAGED_HOST_END &&
           layout->ntdll_start == WINE_MANAGED_HOST_NTDLL_START &&
           layout->ntdll_end == WINE_MANAGED_HOST_NTDLL_END &&
           layout->shared_data_start == WINE_MANAGED_KUSER_START &&
           layout->shared_data_end == WINE_MANAGED_KUSER_END &&
           layout->dispatcher_start == WINE_MANAGED_DISPATCH_START &&
           layout->dispatcher_end == WINE_MANAGED_DISPATCH_END &&
           layout->dispatcher_end - layout->dispatcher_start == 0x1000;
    check( descriptor_valid, "real v2 executor handoff has ABI size 96 and layout id 2" );
    check( descriptor_valid, "handoff carries exact private RW/NX dispatcher page range" );
    preload_valid = wine_main_preload_info &&
           wine_main_preload_info[0].addr == (void *)WINE_MANAGED_GUEST_START &&
           wine_main_preload_info[0].size == WINE_MANAGED_GUEST_END - WINE_MANAGED_GUEST_START &&
           wine_main_preload_info[1].addr == (void *)WINE_MANAGED_HOST_START &&
           wine_main_preload_info[1].size == WINE_MANAGED_HOST_END - WINE_MANAGED_HOST_START &&
           !wine_main_preload_info[2].size;
    check( preload_valid, "preloader publishes exactly the guest and host reservations" );

    guest_reserved = check_reserved_span( WINE_MANAGED_GUEST_START, WINE_MANAGED_GUEST_END,
                                         "complete guest reservation in own address map" );
    host_reserved = check_reserved_span( WINE_MANAGED_HOST_START, WINE_MANAGED_HOST_END,
                                         "complete host PE reservation in own address map" );

    /* Prove both the guest edge and canonical ntdll slot are pages owned by
     * the reservations, then restore their original inaccessible state. */
    if (guest_reserved && descriptor_valid && preload_valid)
        check_owned_endpoint( WINE_MANAGED_GUEST_END - 0x1000,
                              "guest endpoint writable then restored" );
    if (host_reserved && descriptor_valid && preload_valid)
    {
        check_owned_endpoint( WINE_MANAGED_HOST_NTDLL_END - 0x1000,
                              "canonical ntdll endpoint writable then restored" );
        check_owned_endpoint( WINE_MANAGED_HOST_END - 0x1000,
                              "host endpoint writable then restored" );
    }
    check_reserved_span( WINE_MANAGED_GUEST_START, WINE_MANAGED_GUEST_END,
                         "guest reservation restored after endpoint writes" );
    check_reserved_span( WINE_MANAGED_HOST_START, WINE_MANAGED_HOST_END,
                         "host PE reservation restored after endpoint writes" );

    check_native_address( (const void *)&main, "native PIE image" );
    check_native_address( (const void *)&maps, "native initial process stack" );

    /* An ordinary low mmap hint must be rejected by the reservation and
     * placed in the native host domain by the kernel. */
    mapping = mmap( (void *)0x20000, 0x10000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    check( mapping != MAP_FAILED && outside_managed_ranges( mapping ),
           "ordinary native mmap stays outside guest and host PE reservations" );
    if (mapping != MAP_FAILED) munmap( mapping, 0x10000 );

    heap = calloc( 1, 0x10000 );
    check( heap && outside_managed_ranges( heap ), "native libc heap stays outside managed ranges" );
    printf( "native PIE %p, stack %p, heap %p\n", (const void *)&main, (void *)&maps, heap );
    printf( "dispatcher handoff range [%#llx,%#llx) (standalone native fixture; no Wine page installed)\n",
            layout ? layout->dispatcher_start : 0, layout ? layout->dispatcher_end : 0 );
    free( heap );

    library = dlopen( "libm.so.6", RTLD_NOW );
    check( !!library, "native dynamic library loads" );
    if (library)
    {
        symbol = dlsym( library, "cos" );
        check( symbol && outside_managed_ranges( symbol ),
               "native dlopen image stays outside managed ranges" );
        dlclose( library );
    }

    thread_status = pthread_create( &thread, NULL, thread_main, NULL );
    check( !thread_status, "native default pthread starts" );
    if (!thread_status)
    {
        thread_status = pthread_join( thread, &thread_result );
        check( !thread_status, "native default pthread joins" );
        check( !thread_result, "native default pthread stack stays outside managed ranges" );
    }

    /* Re-open after runtime allocations to verify that libc and dynamic
     * loader activity did not consume either reserved domain. */
    maps = fopen( "/proc/self/maps", "r" );
    check( !!maps, "reopen own /proc/self/maps read-only" );
    if (maps)
    {
        check_native_address( maps, "native maps FILE state after libc/dlopen/pthread" );
        if (getline( &line, &line_capacity, maps ) != -1)
            check_native_address( line, "native VM map metadata buffer" );
        free( line );
        fclose( maps );
    }
    check_reserved_span( WINE_MANAGED_GUEST_START, WINE_MANAGED_GUEST_END,
                         "guest remains reserved after native allocations" );
    check_reserved_span( WINE_MANAGED_HOST_START, WINE_MANAGED_HOST_END,
                         "host PE remains reserved after native allocations" );

    printf( "managed-executor: %u failures\n", failures );
    return !!failures;
}
