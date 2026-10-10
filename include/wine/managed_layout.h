/*
 * Experimental managed target layout handoff between the preloader and ntdll.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_MANAGED_LAYOUT_H
#define __WINE_MANAGED_LAYOUT_H

#define WINE_MANAGED_LAYOUT_SETTING "v1:target:400000000000"
#define WINE_MANAGED_LAYOUT_VERSION 1
#define WINE_MANAGED_LAYOUT_TARGET  1
#define WINE_MANAGED_GUEST_START    0x10000ULL
#define WINE_MANAGED_GUEST_END      0x400000000000ULL
#define WINE_MANAGED_EXECUTOR_SETTING "v2:executor:400000000000:410000000000"
#define WINE_MANAGED_EXECUTOR_VERSION 2
#define WINE_MANAGED_LAYOUT_EXECUTOR  2
#define WINE_MANAGED_EXECUTOR_LAYOUT_ID 3
#define WINE_MANAGED_EXECUTOR_RESERVATION_FILE_BACKED_SEALED 1u
#define WINE_MANAGED_HOST_START     0x400000000000ULL
#define WINE_MANAGED_HOST_END       0x410000000000ULL
#define WINE_MANAGED_HOST_NTDLL_START WINE_MANAGED_HOST_START
#define WINE_MANAGED_HOST_NTDLL_END  0x400001000000ULL
#define WINE_MANAGED_HOST_ALLOC_START WINE_MANAGED_HOST_NTDLL_END
#define WINE_MANAGED_KUSER_START    0x7ffe0000ULL
#define WINE_MANAGED_KUSER_END      0x7ffe1000ULL
#define WINE_MANAGED_DISPATCH_START 0x7ffe1000ULL
#define WINE_MANAGED_DISPATCH_END   0x7ffe2000ULL

/* Internal startup ABI, not a Windows interface or executor admission. */
struct wine_managed_layout
{
    unsigned int version;
    unsigned int role;
    unsigned long long guest_start;
    unsigned long long guest_end;
};

/* Version 1 remains exactly the common prefix above. Read this extension only
 * after validating version 2 and the executor role. Layout 3 carries the
 * sealed file-backed guest reservation used to restore revocable views. */
struct wine_managed_executor_layout
{
    struct wine_managed_layout common;
    unsigned int size;
    unsigned int layout_id;
    unsigned long long host_start;
    unsigned long long host_end;
    unsigned long long ntdll_start;
    unsigned long long ntdll_end;
    unsigned long long shared_data_start;
    unsigned long long shared_data_end;
    unsigned long long dispatcher_start;
    unsigned long long dispatcher_end;
    int guest_reservation_fd;
    unsigned int guest_reservation_flags;
};

#endif
