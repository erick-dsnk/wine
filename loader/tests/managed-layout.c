/*
 * Standalone native fixture for the experimental managed target preloader.
 * Build as PIE with -Wl,--export-dynamic and run through wine-preloader.
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
#include <sys/mman.h>
#include <stdint.h>
#include "wine/managed_layout.h"

struct wine_preload_info { void *addr; size_t size; };
const struct wine_preload_info *wine_main_preload_info;
const struct wine_managed_layout *wine_main_managed_layout;
void *wine_r_debug;

static unsigned int failures;

static void check( int condition, const char *description )
{
    if (!condition)
    {
        fprintf( stderr, "managed-layout: FAIL: %s\n", description );
        failures++;
    }
}

static void *thread_main( void *arg )
{
    pthread_attr_t attr;
    void *stack;
    size_t size;

    if (pthread_getattr_np( pthread_self(), &attr )) return (void *)1;
    pthread_attr_getstack( &attr, &stack, &size );
    pthread_attr_destroy( &attr );
    printf( "native default pthread stack %p size %#zx\n", stack, size );
    return (uintptr_t)stack < WINE_MANAGED_GUEST_END ? (void *)1 : NULL;
}

int main(void)
{
    FILE *maps;
    char line[512], prot[5];
    unsigned long long start, end, cursor = WINE_MANAGED_GUEST_START;
    void *mapping, *heap, *library, *symbol, *result;
    pthread_t thread;
    int thread_status;

    check( wine_main_managed_layout &&
           wine_main_managed_layout->version == WINE_MANAGED_LAYOUT_VERSION &&
           wine_main_managed_layout->role == WINE_MANAGED_LAYOUT_TARGET &&
           wine_main_managed_layout->guest_start == WINE_MANAGED_GUEST_START &&
           wine_main_managed_layout->guest_end == WINE_MANAGED_GUEST_END,
           "loader-established descriptor" );
    check( wine_main_preload_info && wine_main_preload_info[0].addr == (void *)WINE_MANAGED_GUEST_START &&
           wine_main_preload_info[0].size == WINE_MANAGED_GUEST_END - WINE_MANAGED_GUEST_START &&
           !wine_main_preload_info[1].size, "one admitted guest reservation" );
    check( (uintptr_t)&main >= WINE_MANAGED_GUEST_END, "native PIE image outside guest" );
    check( (uintptr_t)&maps >= WINE_MANAGED_GUEST_END, "initial native stack outside guest" );

    /* This standalone fixture owns the reservation before Windows images load. */
    mapping = mmap( (void *)(WINE_MANAGED_GUEST_END - 0x1000), 0x1000, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    check( mapping == (void *)(WINE_MANAGED_GUEST_END - 0x1000), "native last guest page maps" );
    if (mapping == (void *)(WINE_MANAGED_GUEST_END - 0x1000))
    {
        ((volatile unsigned char *)mapping)[0xfff] = 0xa5;
        check( ((volatile unsigned char *)mapping)[0xfff] == 0xa5, "native last guest byte retains write" );
        mapping = mmap( mapping, 0x1000, PROT_NONE,
                        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0 );
        check( mapping == (void *)(WINE_MANAGED_GUEST_END - 0x1000), "native last guest page reservation restored" );
    }

    maps = fopen( "/proc/self/maps", "r" );
    check( !!maps, "read native mappings" );
    if (maps)
    {
        while (fgets( line, sizeof(line), maps ))
        {
            if (sscanf( line, "%llx-%llx %4s", &start, &end, prot ) != 3) continue;
            if (end <= WINE_MANAGED_GUEST_START || start >= WINE_MANAGED_GUEST_END) continue;
            check( start == cursor && end <= WINE_MANAGED_GUEST_END, "continuous guest reservation" );
            check( prot[0] == '-' && prot[1] == '-' && prot[2] == '-', "guest reservation inaccessible" );
            printf( "guest mapping %s", line );
            cursor = end;
        }
        fclose( maps );
    }
    check( cursor == WINE_MANAGED_GUEST_END, "complete declared guest span" );

    mapping = mmap( (void *)0x20000, 0x10000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    check( mapping != MAP_FAILED && (uintptr_t)mapping >= WINE_MANAGED_GUEST_END,
           "native mmap hint cannot consume guest reservation" );
    if (mapping != MAP_FAILED) munmap( mapping, 0x10000 );
    heap = calloc( 1, 0x10000 );
    check( heap && (uintptr_t)heap >= WINE_MANAGED_GUEST_END, "native heap outside guest" );
    printf( "native PIE %p, stack %p, heap %p\n", &main, &maps, heap );
    free( heap );
    library = dlopen( "libm.so.6", RTLD_NOW );
    check( !!library, "native dynamic library loads" );
    if (library)
    {
        symbol = dlsym( library, "cos" );
        check( symbol && (uintptr_t)symbol >= WINE_MANAGED_GUEST_END, "native dlopen outside guest" );
        dlclose( library );
    }
    thread_status = pthread_create( &thread, NULL, thread_main, NULL );
    check( !thread_status, "native default pthread starts" );
    if (!thread_status)
    {
        pthread_join( thread, &result );
        check( !result, "native default pthread stack outside guest" );
    }
    printf( "managed-layout: %u failures\n", failures );
    return !!failures;
}
