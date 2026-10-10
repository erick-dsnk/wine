/*
 * Unit test suite for the virtual memory APIs.
 *
 * Copyright 2019 Remi Bernon for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/test.h"
#include "wine/managed_layout.h"
#include "ddk/wdm.h"

static unsigned int page_size;

static DWORD64 (WINAPI *pGetEnabledXStateFeatures)(void);
static NTSTATUS (WINAPI *pRtlCreateUserStack)(SIZE_T, SIZE_T, ULONG, SIZE_T, SIZE_T, INITIAL_TEB *);
static NTSTATUS (WINAPI *pRtlCreateUserThread)(HANDLE, SECURITY_DESCRIPTOR*, BOOLEAN, ULONG, SIZE_T,
                                               SIZE_T, PRTL_THREAD_START_ROUTINE, void*, HANDLE*, CLIENT_ID* );
static ULONG64 (WINAPI *pRtlGetEnabledExtendedFeatures)(ULONG64);
static NTSTATUS (WINAPI *pRtlFreeUserStack)(void *);
static void * (WINAPI *pRtlFindExportedRoutineByName)(HMODULE,const char*);
static BOOL (WINAPI *pIsWow64Process)(HANDLE, PBOOL);
static NTSTATUS (WINAPI *pRtlGetNativeSystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
static BOOLEAN (WINAPI *pRtlIsEcCode)(const void *);
static NTSTATUS (WINAPI *pNtAllocateVirtualMemoryEx)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG,
                                                     MEM_EXTENDED_PARAMETER *, ULONG);
static NTSTATUS (WINAPI *pNtMapViewOfSectionEx)(HANDLE, HANDLE, PVOID *, const LARGE_INTEGER *, SIZE_T *,
        ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
static NTSTATUS (WINAPI *pNtSetInformationVirtualMemory)(HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS,
                                                         ULONG_PTR, PMEMORY_RANGE_ENTRY,
                                                         PVOID, ULONG);

static const BOOL is_win64 = sizeof(void*) != sizeof(int);
static BOOL is_wow64;

static SYSTEM_BASIC_INFORMATION sbi;

static DWORD WINAPI managed_target_thread( void *arg )
{
    TEB *teb = NtCurrentTeb();
    ULONG_PTR local = (ULONG_PTR)&teb;

    ok( (ULONG_PTR)teb < WINE_MANAGED_GUEST_END, "target TEB outside guest: %p\n", teb );
    ok( local < WINE_MANAGED_GUEST_END, "target Windows stack outside guest: %p\n", &teb );
    return 0;
}

static void test_managed_target_layout( BOOL child )
{
    SYSTEM_BASIC_INFORMATION info;
    SYSTEM_INFO system_info;
    MEMORY_BASIC_INFORMATION mbi;
    void *addr, *fixed, *saved;
    SIZE_T size, result_size;
    LARGE_INTEGER section_size;
    HANDLE section = NULL, thread;
    HMODULE module;
    NTSTATUS status;
    DWORD exit_code;
    char setting[64], command[2 * MAX_PATH], **argv;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    NTSTATUS (WINAPI *set_unix_env)(const char *, const char *);
    BOOL inject;

    if (!child && (!GetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", setting, sizeof(setting) ) ||
                  strcmp( setting, WINE_MANAGED_LAYOUT_SETTING )))
    {
        skip( "managed target layout is not enabled\n" );
        return;
    }
    if (!is_win64)
    {
        skip( "managed target layout requires AMD64\n" );
        return;
    }

    status = NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL );
    ok( !status, "basic information returned %08lx\n", status );
    ok( (ULONG_PTR)info.HighestUserAddress == WINE_MANAGED_GUEST_END - 1,
        "unexpected highest guest address %p\n", info.HighestUserAddress );
    GetSystemInfo( &system_info );
    ok( (ULONG_PTR)system_info.lpMaximumApplicationAddress == WINE_MANAGED_GUEST_END - 1,
        "unexpected maximum application address %p\n", system_info.lpMaximumApplicationAddress );
    trace( "managed target highest %p, TEB %p, PEB %p\n", info.HighestUserAddress,
           NtCurrentTeb(), NtCurrentTeb()->Peb );
    if (child) return;

    addr = (void *)1;
    size = 0x110000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    ok( status == STATUS_INVALID_PARAMETER, "DOS allocation escaped guest minimum: %08lx\n", status );

    addr = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
    ok( !status, "top-down allocation returned %08lx\n", status );
    if (!status)
    {
        ok( (ULONG_PTR)addr + size <= WINE_MANAGED_GUEST_END, "top-down allocation escaped: %p\n", addr );
        ok( (ULONG_PTR)addr >= WINE_MANAGED_GUEST_END - 0x10000000,
            "top-down allocation did not reach the upper guest range: %p\n", addr );
        trace( "legal upper guest Windows allocation %p, size %Ix\n", addr, size );
        *(volatile BYTE *)addr = 0x5a;
        saved = addr;
        size = 0;
        status = NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
        ok( !status, "release returned %08lx\n", status );
        status = NtQueryVirtualMemory( NtCurrentProcess(), saved, MemoryBasicInformation,
                                       &mbi, sizeof(mbi), &result_size );
        ok( !status && mbi.State == MEM_FREE, "released guest state %08lx/%lx\n", status, mbi.State );
        addr = saved;
        size = 0x10000;
        status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
        ok( !status && addr == saved, "reuse returned %08lx at %p\n", status, addr );
        if (!status)
        {
            ok( *(volatile BYTE *)addr == 0, "reused guest memory is not zero\n" );
            size = 0;
            status = NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
            ok( !status, "reuse release returned %08lx\n", status );
        }
    }

    fixed = (void *)(ULONG_PTR)(WINE_MANAGED_GUEST_END - 0x10000);
    addr = fixed;
    size = 0x10000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if (status == STATUS_CONFLICTING_ADDRESSES)
    {
        status = NtQueryVirtualMemory( NtCurrentProcess(), fixed, MemoryBasicInformation,
                                       &mbi, sizeof(mbi), &result_size );
        ok( !status && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE,
            "last Windows allocation granule conflict has no image: %08lx/%lx/%lx\n",
            status, mbi.State, mbi.Type );
        trace( "terminal granule image allocation %p, region %p + %Ix, state %lx, type %lx\n",
               mbi.AllocationBase, mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Type );
        status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)(ULONG_PTR)(WINE_MANAGED_GUEST_END - 0x1000),
                                       MemoryBasicInformation, &mbi, sizeof(mbi), &result_size );
        ok( !status && (ULONG_PTR)mbi.BaseAddress < WINE_MANAGED_GUEST_END,
            "last guest page query %08lx/%p\n", status, mbi.BaseAddress );
        trace( "last Windows allocation granule contains a loaded PE image; final guest page state %lx\n", mbi.State );
        status = STATUS_CONFLICTING_ADDRESSES;
    }
    else ok( !status && addr == fixed, "last legal allocation returned %08lx at %p\n", status, addr );
    if (!status)
    {
        *((volatile BYTE *)addr + 0xffff) = 0xa5;
        ok( *((volatile BYTE *)addr + 0xffff) == 0xa5, "last guest byte did not retain write\n" );
        size = 0;
        status = NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
        ok( !status, "last allocation release returned %08lx\n", status );
    }
    addr = fixed;
    size = 0x20000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_NOACCESS );
    ok( status == STATUS_INVALID_PARAMETER, "cross-boundary allocation returned %08lx\n", status );
    addr = (void *)(ULONG_PTR)WINE_MANAGED_GUEST_END;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_NOACCESS );
    ok( status == STATUS_INVALID_PARAMETER, "host-range allocation returned %08lx\n", status );

    section_size.QuadPart = 0x10000;
    status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &section_size,
                              PAGE_READWRITE, SEC_COMMIT, NULL );
    ok( !status, "section creation returned %08lx\n", status );
    if (!status)
    {
        addr = (void *)(ULONG_PTR)WINE_MANAGED_GUEST_END;
        size = 0x10000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &addr, 0, 0, NULL, &size,
                                     ViewUnmap, 0, PAGE_READWRITE );
        ok( !NT_SUCCESS(status), "host-range section mapping returned %08lx at %p\n", status, addr );
        if (NT_SUCCESS(status)) NtUnmapViewOfSection( NtCurrentProcess(), addr );
        NtClose( section );
    }

    /* Cannot fit around this process's loaded PE images and thread state.
     * Exercise the bounded retry after the first allocation search fails. */
    addr = NULL;
    size = (SIZE_T)(WINE_MANAGED_GUEST_END - WINE_MANAGED_GUEST_START);
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_NOACCESS );
    ok( status == STATUS_NO_MEMORY, "exhausted guest search returned %08lx at %p\n", status, addr );
    if (!status)
    {
        size = 0;
        NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
    }

    module = LoadLibraryA( "version.dll" );
    ok( !!module && (ULONG_PTR)module < WINE_MANAGED_GUEST_END,
        "ordinary PE load escaped guest: %p, error %lu\n", module, GetLastError() );
    if (module) FreeLibrary( module );
    if (GetEnvironmentVariableA( "WINE_MANAGED_LEGACY_TEST", setting, sizeof(setting) ))
    {
        module = LoadLibraryA( "managed_legacy.dll" );
        ok( !module, "unsupported legacy .so builtin loaded at %p\n", module );
        if (module) FreeLibrary( module );
    }
    thread = CreateThread( NULL, 0, managed_target_thread, NULL, 0, NULL );
    ok( !!thread, "target thread creation failed %lu\n", GetLastError() );
    if (thread)
    {
        ok( WaitForSingleObject( thread, 10000 ) == WAIT_OBJECT_0, "target thread did not return\n" );
        CloseHandle( thread );
    }

    /* Windows environment edits cannot disable the admitted process contract. */
    ok( SetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", NULL ), "environment removal failed\n" );
    GetSystemInfo( &system_info );
    ok( (ULONG_PTR)system_info.lpMaximumApplicationAddress == WINE_MANAGED_GUEST_END - 1,
        "environment removal changed admitted limit\n" );
    winetest_get_mainargs( &argv );
    snprintf( command, sizeof(command), "\"%s\" %s managed-layout-child", argv[0], argv[1] );
    memset( &pi, 0, sizeof(pi) );
    if (CreateProcessA( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ))
    {
        ok( WaitForSingleObject( pi.hProcess, 10000 ) == WAIT_OBJECT_0, "managed child did not exit\n" );
        GetExitCodeProcess( pi.hProcess, &exit_code );
        ok( !exit_code, "managed child returned %lu\n", exit_code );
        CloseHandle( pi.hThread );
        CloseHandle( pi.hProcess );
    }
    else ok( FALSE, "managed child launch failed %lu\n", GetLastError() );

    inject = GetEnvironmentVariableA( "WINE_MANAGED_INJECT_TEST", setting, sizeof(setting) );
    if (inject)
    {
        set_unix_env = (void *)GetProcAddress( GetModuleHandleA("ntdll.dll"), "__wine_set_unix_env" );
        ok( !!set_unix_env, "Wine Unix environment test hook is unavailable\n" );
        if (!set_unix_env) return;
        ok( !set_unix_env( "PROTON_MANAGED_FAIL_RESERVED", "1" ), "cannot enable reserved-map injection\n" );
        addr = NULL;
        size = 0x730000;
        status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
        ok( status == STATUS_NO_MEMORY && !addr && size == 0x730000,
            "reserved-map failure returned %08lx/%p/%Ix\n", status, addr, size );
        if (!status)
        {
            size = 0;
            NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
        }
        ok( !set_unix_env( "PROTON_MANAGED_FAIL_RESERVED", NULL ), "cannot disable reserved-map injection\n" );
        addr = NULL;
        size = 0x730000;
        status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
        ok( !status && (ULONG_PTR)addr + size <= WINE_MANAGED_GUEST_END,
            "reserved-map retry returned %08lx/%p\n", status, addr );
        if (!status)
        {
            *(volatile BYTE *)addr = 0x7b;
            size = 0;
            status = NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
            ok( !status, "reserved-map retry cleanup returned %08lx\n", status );
        }
        ok( !set_unix_env( "WINE_MANAGED_LAYOUT", NULL ), "cannot remove native layout setting for child test\n" );
        ok( !set_unix_env( "PROTON_MANAGED_FAIL_CHILD_ENV", "1" ), "cannot enable child-env injection\n" );
        memset( &pi, 0, sizeof(pi) );
        SetLastError(0xdeadbeef);
        if (CreateProcessA( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ))
        {
            ok( FALSE, "child launched despite layout setenv failure\n" );
            WaitForSingleObject( pi.hProcess, 10000 );
            CloseHandle( pi.hThread );
            CloseHandle( pi.hProcess );
        }
        /* spawn_process's grandchild exits 1 after exec_wineloader fails. */
        else ok( GetLastError() == ERROR_WAIT_1, "child-env failure returned error %lu\n", GetLastError() );
        ok( !set_unix_env( "PROTON_MANAGED_FAIL_CHILD_ENV", NULL ), "cannot disable child-env injection\n" );
        ok( !set_unix_env( "WINE_MANAGED_LAYOUT", WINE_MANAGED_LAYOUT_SETTING ), "cannot restore native layout setting\n" );
    }
}

static inline void *get_rva( HMODULE module, DWORD va )
{
    return (void *)((char *)module + va);
}

static HANDLE create_target_process(const char *arg)
{
    char **argv;
    char cmdline[MAX_PATH];
    PROCESS_INFORMATION pi = { 0 };
    BOOL ret;
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);

    winetest_get_mainargs(&argv);
    sprintf(cmdline, "%s %s %s", argv[0], argv[1], arg);
    ret = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ok(ret, "error: %lu\n", GetLastError());
    ret = CloseHandle(pi.hThread);
    ok(ret, "error %lu\n", GetLastError());
    return pi.hProcess;
}

static BOOL shared_private_backing_enabled(void)
{
    char value[8];
    return GetEnvironmentVariableA("WINE_SHARED_PRIVATE_BACKING", value, sizeof(value)) == 1 && value[0] == '1';
}

static DWORD shared_private_backing_probe_hold(void)
{
    char value[16];
    DWORD len = GetEnvironmentVariableA("WINE_SHARED_PRIVATE_BACKING_PROBE_HOLD_MS", value, sizeof(value));
    unsigned long hold;

    if (!len || len >= sizeof(value)) return 0;
    hold = strtoul(value, NULL, 10);
    return min(hold, 10000);
}

static UINT_PTR get_zero_bits(UINT_PTR p)
{
    UINT_PTR z = 0;

#ifdef _WIN64
    if (p >= 0xffffffff)
        return (~(UINT_PTR)0) >> get_zero_bits(p >> 32);
#endif

    if (p == 0) return 0;
    while ((p >> (31 - z)) != 1) z++;
    return z;
}

static UINT_PTR get_zero_bits_mask(ULONG_PTR z)
{
    if (z >= 32)
    {
        z = get_zero_bits(z);
#ifdef _WIN64
        if (z >= 32) return z;
#endif
    }
    return (~(UINT32)0) >> z;
}

static void test_NtAllocateVirtualMemory(void)
{
    void *addr1, *addr2;
    NTSTATUS status;
    SIZE_T size;
    ULONG_PTR zero_bits;

    /* simple allocation should success */
    size = 0x1000;
    addr1 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr1, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_SUCCESS, "NtAllocateVirtualMemory returned %08lx\n", status);

    /* allocation conflicts because of 64k align */
    size = 0x1000;
    addr2 = (char *)addr1 + 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "NtAllocateVirtualMemory returned %08lx\n", status);

    /* it should conflict, even when zero_bits is explicitly set */
    size = 0x1000;
    addr2 = (char *)addr1 + 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, 12, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "NtAllocateVirtualMemory returned %08lx\n", status);

    /* 1 zero bits should zero 63-31 upper bits */
    size = 0x1000;
    addr2 = NULL;
    zero_bits = 1;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, zero_bits, &size,
                                     MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY ||
       broken(status == STATUS_INVALID_PARAMETER_3) /* winxp */,
       "NtAllocateVirtualMemory returned %08lx\n", status);
    if (status == STATUS_SUCCESS)
    {
        ok(((UINT_PTR)addr2 >> (32 - zero_bits)) == 0,
           "NtAllocateVirtualMemory returned address: %p\n", addr2);

        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory return %08lx, addr2: %p\n", status, addr2);
    }

    for (zero_bits = 2; zero_bits <= 20; zero_bits++)
    {
        size = 0x1000;
        addr2 = NULL;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, zero_bits, &size,
                                         MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                                         PAGE_READWRITE);
        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY ||
           broken(zero_bits == 20 && status == STATUS_CONFLICTING_ADDRESSES) /* w1064v1809 */,
           "NtAllocateVirtualMemory with %d zero_bits returned %08lx\n", (int)zero_bits, status);
        if (status == STATUS_SUCCESS)
        {
            ok(((UINT_PTR)addr2 >> (32 - zero_bits)) == 0,
               "NtAllocateVirtualMemory with %d zero_bits returned address %p\n", (int)zero_bits, addr2);

            size = 0;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory return %08lx, addr2: %p\n", status, addr2);
        }
    }

    /* 21 zero bits never succeeds */
    size = 0x1000;
    addr2 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, 21, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_NO_MEMORY || status == STATUS_INVALID_PARAMETER,
       "NtAllocateVirtualMemory returned %08lx\n", status);
    if (status == STATUS_SUCCESS)
    {
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory return %08lx, addr2: %p\n", status, addr2);
    }

    /* 22 zero bits is invalid */
    size = 0x1000;
    addr2 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, 22, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_3 || status == STATUS_INVALID_PARAMETER,
       "NtAllocateVirtualMemory returned %08lx\n", status);

    /* zero bits > 31 should be considered as a leading zeroes bitmask on 64bit and WoW64 */
    size = 0x1000;
    addr2 = NULL;
    zero_bits = 0x1aaaaaaa;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, zero_bits, &size,
                                      MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                                      PAGE_READWRITE);

    if (!is_win64 && !is_wow64)
    {
        ok(status == STATUS_INVALID_PARAMETER_3, "NtAllocateVirtualMemory returned %08lx\n", status);
    }
    else
    {
        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY,
           "NtAllocateVirtualMemory returned %08lx\n", status);
        if (status == STATUS_SUCCESS)
        {
            ok(((UINT_PTR)addr2 & ~get_zero_bits_mask(zero_bits)) == 0 &&
               ((UINT_PTR)addr2 & ~zero_bits) != 0, /* only the leading zeroes matter */
               "NtAllocateVirtualMemory returned address %p\n", addr2);

            size = 0;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory return %08lx, addr2: %p\n", status, addr2);
        }
    }

    /* AT_ROUND_TO_PAGE flag is not supported for NtAllocateVirtualMemory */
    size = 0x1000;
    addr2 = (char *)addr1 + 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr2, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT | AT_ROUND_TO_PAGE, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_5 || status == STATUS_INVALID_PARAMETER,
       "NtAllocateVirtualMemory returned %08lx\n", status);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory failed\n");

    /* NtFreeVirtualMemory tests */

    size = 0x10000;
    addr1 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr1, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_SUCCESS, "NtAllocateVirtualMemory returned %08lx\n", status);

    size = 2;
    addr2 = (char *)addr1 + 0x1fff;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory failed %lx\n", status);
    ok( size == 0x2000, "wrong size %Ix\n", size );
    ok( addr2 == (char *)addr1 + 0x1000, "wrong addr %p\n", addr2 );

    size = 0;
    addr2 = (char *)addr1 + 0x1001;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_DECOMMIT);
    ok(status == STATUS_FREE_VM_NOT_AT_BASE, "NtFreeVirtualMemory failed %lx\n", status);
    ok( size == 0, "wrong size %Ix\n", size );
    ok( addr2 == (char *)addr1 + 0x1001, "wrong addr %p\n", addr2 );

    size = 0;
    addr2 = (char *)addr1 + 0xffe;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory failed %lx\n", status);
    ok( size == 0 || broken(size == 0x10000) /* <= win10 1709 */, "wrong size %Ix\n", size );
    ok( addr2 == addr1, "wrong addr %p\n", addr2 );

    size = 0;
    addr2 = (char *)addr1 + 0x1001;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
    ok(status == STATUS_FREE_VM_NOT_AT_BASE, "NtFreeVirtualMemory failed %lx\n", status);
    ok( size == 0, "wrong size %Ix\n", size );
    ok( addr2 == (char *)addr1 + 0x1001, "wrong addr %p\n", addr2 );

    size = 0;
    addr2 = (char *)addr1 + 0xfff;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr2, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "NtFreeVirtualMemory failed %lx\n", status);
    ok( size == 0x10000, "wrong size %Ix\n", size );
    ok( addr2 == addr1, "wrong addr %p\n", addr2 );

    /* Placeholder functionality */
    size = 0x10000;
    addr1 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr1, 0, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(!!status, "Unexpected status %08lx.\n", status);
}

#define check_region_size(p, s) check_region_size_(p, s, __LINE__)
static void check_region_size_(void *p, SIZE_T s, unsigned int line)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;
    SIZE_T size;

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory( NtCurrentProcess(), p, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok_(__FILE__,line)( !status, "Unexpected return value %08lx\n", status );
    ok_(__FILE__,line)( size == sizeof(mbi), "Unexpected return value.\n");
    ok_(__FILE__,line)( mbi.RegionSize == s, "Unexpected size %Iu, expected %Iu.\n", mbi.RegionSize, s);
}

static void test_NtAllocateVirtualMemoryEx(void)
{
    MEMORY_REGION_INFORMATION mri;
    MEMORY_BASIC_INFORMATION mbi;
    MEM_EXTENDED_PARAMETER ext[2];
    char *p, *p1, *p2, *p3;
    void *addresses[16];
    SIZE_T size, size2;
    ULONG granularity;
    NTSTATUS status;
    ULONG_PTR count;
    void *addr1;

    if (!pNtAllocateVirtualMemoryEx)
    {
        win_skip("NtAllocateVirtualMemoryEx() is missing\n");
        return;
    }

    size = 0x1000;
    addr1 = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    /* specifying a count of >0 with NULL parameters should fail */
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, NULL, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    /* NULL process handle */
    size = 0x1000;
    addr1 = NULL;
    status = pNtAllocateVirtualMemoryEx(NULL, &addr1, &size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_HANDLE, "Unexpected status %08lx.\n", status);

    /* Placeholder functionality */
    size = 0x10000;
    addr1 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr1, 0, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE, NULL, 0);
    ok(!status, "Unexpected status %08lx.\n", status);

    memset(addr1, 0xcc, size);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&addr1, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(!status, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
            PAGE_READONLY, NULL, 0);
    ok(!status, "Unexpected status %08lx.\n", status);

    ok(!*(unsigned int *)addr1, "Got %#x.\n", *(unsigned int *)addr1);

    status = NtQueryVirtualMemory( NtCurrentProcess(), addr1, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(mbi.AllocationProtect == PAGE_READONLY, "Unexpected protection %#lx.\n", mbi.AllocationProtect);
    ok(mbi.State == MEM_COMMIT, "Unexpected state %#lx.\n", mbi.State);
    ok(mbi.Type == MEM_PRIVATE, "Unexpected type %#lx.\n", mbi.Type);
    ok(mbi.RegionSize == 0x10000, "Unexpected size.\n");

    size = 0x10000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&addr1, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(!status, "Unexpected status %08lx.\n", status);

    status = NtQueryVirtualMemory( NtCurrentProcess(), addr1, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(mbi.AllocationProtect == PAGE_NOACCESS, "Unexpected protection %#lx.\n", mbi.AllocationProtect);
    ok(mbi.State == MEM_RESERVE, "Unexpected state %#lx.\n", mbi.State);
    ok(mbi.Type == MEM_PRIVATE, "Unexpected type %#lx.\n", mbi.Type);
    ok(mbi.RegionSize == 0x10000, "Unexpected size.\n");

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size = 0x1000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_COMMIT, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size,
            MEM_WRITE_WATCH | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
            PAGE_READONLY, NULL, 0);
    ok(!status || broken(status == STATUS_INVALID_PARAMETER) /* Win10 1809, the version where
            NtAllocateVirtualMemoryEx is introduced */, "Unexpected status %08lx.\n", status);

    if (!status)
    {
        size = 0x10000;
        status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_COMMIT, PAGE_READWRITE, NULL, 0);
        ok(!status, "Unexpected status %08lx.\n", status);

        status = NtQueryVirtualMemory( NtCurrentProcess(), addr1, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
        ok(!status, "Unexpected status %08lx.\n", status);
        ok(mbi.AllocationProtect == PAGE_READONLY, "Unexpected protection %#lx.\n", mbi.AllocationProtect);
        ok(mbi.State == MEM_COMMIT, "Unexpected state %#lx.\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "Unexpected type %#lx.\n", mbi.Type);
        ok(mbi.RegionSize == 0x10000, "Unexpected size.\n");

        size = 0x10000;
        count = ARRAY_SIZE(addresses);
        status = NtGetWriteWatch( NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, addr1, size,
                                  addresses, &count, &granularity );
        ok(!status, "Unexpected status %08lx.\n", status);
        ok(!count, "Unexpected count %u.\n", (unsigned int)count);
        *((char *)addr1 + 0x1000) = 1;
        count = ARRAY_SIZE(addresses);
        status = NtGetWriteWatch( NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, addr1, size,
                                  addresses, &count, &granularity );
        ok(!status, "Unexpected status %08lx.\n", status);
        ok(count == 1, "Unexpected count %u.\n", (unsigned int)count);
        ok(addresses[0] == (char *)addr1 + 0x1000, "Unexpected address %p.\n", addresses[0]);

        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    }

    /* Placeholder region splitting. */
    addr1 = NULL;
    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    p = addr1;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);
    ok(size == 0x10000, "Unexpected size %#Ix.\n", size);
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size == 0x10000, "Unexpected size %#Ix.\n", size);
    ok(p == addr1, "Unexpected addr %p, expected %p.\n", p, addr1);


    /* Split in three regions. */
    addr1 = NULL;
    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&addr1, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    p = addr1;
    p1 = p + size / 2;
    p2 = p1 + size / 4;
    size2 = size / 4;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == p + size / 2, "Unexpected addr %p, expected %p.\n", p, p + size / 2);

    check_region_size(p, size / 2);
    check_region_size(p1, size / 4);
    check_region_size(p2, size - size / 2 - size / 4);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p == addr1, "Unexpected addr %p, expected %p.\n", p, addr1);
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == p + size / 2, "Unexpected addr %p, expected %p.\n", p1, p + size / 2);
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p2, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p2 == p1 + size / 4, "Unexpected addr %p, expected %p.\n", p2, p1 + size / 4);

    /* Split in two regions, specifying lower part. */
    addr1 = NULL;
    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    size2 = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&addr1, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_INVALID_PARAMETER_3, "Unexpected status %08lx.\n", status);
    ok(!size2, "Unexpected size %#Ix.\n", size2);

    p1 = addr1;
    p2 = p1 + size / 4;
    p3 = p2 + size / 4;
    size2 = size / 4;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(p1 == addr1, "Unexpected address.\n");
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == addr1, "Unexpected addr %p, expected %p.\n", p1, addr1);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p2, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    check_region_size(p1, p2 - p1);
    check_region_size(p2, p3 - p2);
    check_region_size(p3, size - (p3 - p1));

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size, MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_INVALID_PARAMETER_4, "Unexpected status %08lx.\n", status);

    size2 = size + 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size2 = size - 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    p1 = (char *)addr1 + 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);
    p1 = addr1;

    size2 = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_INVALID_PARAMETER_3, "Unexpected status %08lx.\n", status);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size, MEM_RELEASE);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "Unexpected status %08lx.\n", status);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size == 0x10000, "Unexpected size %#Ix.\n", size);
    ok(p1 == addr1, "Unexpected addr %p, expected %p.\n", p1, addr1);
    check_region_size(p1, size);

    size2 = size / 4;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == addr1, "Unexpected addr %p, expected %p.\n", p1, addr1);
    check_region_size(p1, size / 4);
    check_region_size(p2, size - size / 4);

    size2 = size - size / 4;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), (void **)&p2, &size2, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size2 = size - size / 4;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p2, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0xc000, "Unexpected size %#Ix.\n", size2);
    ok(p2 == p1 + size / 4, "Unexpected addr %p, expected %p.\n", p2, p1 + size / 4);

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);

    size2 = size / 4;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x4000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == addr1, "Unexpected addr %p, expected %p.\n", p1, addr1);

    size2 = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p3, &size2, MEM_RELEASE);
    ok(status == STATUS_MEMORY_NOT_ALLOCATED, "Unexpected status %08lx.\n", status);

    /* Split in two regions, specifying second half. */
    addr1 = NULL;
    size = 0x10000;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr1, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size == 0x10000, "Unexpected size %#Ix.\n", size);

    p1 = addr1;
    p2 = p1 + size / 2;

    size2 = size / 2;
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p2, &size2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x8000, "Unexpected size %#Ix.\n", size2);
    ok(p2 == p1 + size / 2, "Unexpected addr %p, expected %p.\n", p2, p1 + size / 2);
    check_region_size(p1, size / 2);
    check_region_size(p2, size / 2);

    status = NtQueryVirtualMemory( NtCurrentProcess(), p1, MemoryBasicInformation, &mbi, sizeof(mbi), NULL );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status );
    ok( mbi.AllocationBase == p1, "got %p.\n", mbi.AllocationBase );
    ok( mbi.Type == MEM_PRIVATE, "got %#lx.\n", mbi.Type );
    ok( mbi.State == MEM_RESERVE, "got %#lx.\n", mbi.State );
    ok( mbi.RegionSize == size / 2, "Unexpected size %Iu, expected %Iu.\n", mbi.RegionSize, size / 2 );
    ok( mbi.AllocationProtect == PAGE_NOACCESS, "got %#lx.\n", mbi.AllocationProtect );
    status = NtQueryVirtualMemory( NtCurrentProcess(), p1, MemoryRegionInformation, &mri, sizeof(mri), NULL );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status );
    ok( mri.AllocationBase == p1, "got %p.\n", mri.AllocationBase );
    ok( mri.RegionSize == size / 2, "Unexpected size %Iu, expected %Iu.\n", mri.RegionSize, size / 2 );
    ok( !mri.CommitSize, "Unexpected size %Iu.\n", mri.CommitSize );
    ok( mri.AllocationProtect == PAGE_NOACCESS, "got %#lx.\n", mri.AllocationProtect );

    status = NtQueryVirtualMemory( NtCurrentProcess(), p2, MemoryBasicInformation, &mbi, sizeof(mbi), NULL );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status );
    ok( mbi.AllocationBase == p2, "got %p.\n", mbi.AllocationBase );
    ok( mbi.Type == MEM_PRIVATE, "got %#lx.\n", mbi.Type );
    ok( mbi.State == MEM_RESERVE, "got %#lx.\n", mbi.State );
    ok( mbi.RegionSize == size / 2, "Unexpected size %Iu, expected %Iu.\n", mbi.RegionSize, size / 2 );
    ok( mbi.AllocationProtect == PAGE_NOACCESS, "got %#lx.\n", mbi.AllocationProtect );
    status = NtQueryVirtualMemory( NtCurrentProcess(), p2, MemoryRegionInformation, &mri, sizeof(mri), NULL );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status );
    ok( mri.AllocationBase == p2, "got %p.\n", mri.AllocationBase );
    ok( mri.RegionSize == size / 2, "Unexpected size %Iu, expected %Iu.\n", mri.RegionSize, size / 2 );
    ok( !mri.CommitSize, "Unexpected size %Iu.\n", mri.CommitSize );
    ok( mri.AllocationProtect == PAGE_NOACCESS, "got %#lx.\n", mri.AllocationProtect );

    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p1, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x8000, "Unexpected size %#Ix.\n", size2);
    ok(p1 == addr1, "Unexpected addr %p, expected %p.\n", p1, addr1);
    status = NtFreeVirtualMemory(NtCurrentProcess(), (void **)&p2, &size2, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(size2 == 0x8000, "Unexpected size %#Ix.\n", size2);
    ok(p2 == p1 + size / 2, "Unexpected addr %p, expected %p.\n", p2, p1 + size / 2);

    memset( ext, 0, sizeof(ext) );
    ext[0].Type = MemExtendedParameterAttributeFlags;
    ext[0].ULong = 0;
    ext[1].Type = MemExtendedParameterAttributeFlags;
    ext[1].ULong = 0;
    size = 0x10000;
    addr1 = NULL;
    status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE, ext, 1 );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    NtFreeVirtualMemory( NtCurrentProcess(), &addr1, &size, MEM_DECOMMIT );
    status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE, ext, 2 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    memset( ext, 0, sizeof(ext) );
    ext[0].Type = MemExtendedParameterAttributeFlags;
    ext[0].ULong = MEM_EXTENDED_PARAMETER_EC_CODE;
    size = 0x10000;
    addr1 = NULL;
    status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE, ext, 1 );
#ifdef __x86_64__
    if (pRtlGetNativeSystemInformation)
    {
        SYSTEM_CPU_INFORMATION cpu_info;

        pRtlGetNativeSystemInformation( SystemCpuInformation, &cpu_info, sizeof(cpu_info), NULL );
        if (cpu_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        {
            ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
            if (pRtlIsEcCode) ok( pRtlIsEcCode( addr1 ), "not EC code %p\n", addr1 );
            size = 0;
            NtFreeVirtualMemory( NtCurrentProcess(), &addr1, &size, MEM_RELEASE );

            size = 0x10000;
            addr1 = NULL;
            status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_RESERVE,
                                                 PAGE_EXECUTE_READWRITE, NULL, 0 );
            ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
            if (pRtlIsEcCode) ok( !pRtlIsEcCode( addr1 ), "EC code %p\n", addr1 );
            size = 0x1000;
            status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_COMMIT,
                                                 PAGE_EXECUTE_READWRITE, ext, 1 );
            ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
            if (pRtlIsEcCode)
            {
                ok( pRtlIsEcCode( addr1 ), "not EC code %p\n", addr1 );
                ok( !pRtlIsEcCode( (char *)addr1 + 0x1000 ), "EC code %p\n", (char *)addr1 + 0x1000 );
            }
            size = 0x2000;
            status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_COMMIT,
                                                 PAGE_EXECUTE_READWRITE, NULL, 0 );
            ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
            if (pRtlIsEcCode)
            {
                ok( pRtlIsEcCode( addr1 ), "not EC code %p\n", addr1 );
                ok( !pRtlIsEcCode( (char *)addr1 + 0x1000 ), "EC code %p\n", (char *)addr1 + 0x1000 );
            }

            NtFreeVirtualMemory( NtCurrentProcess(), &addr1, &size, MEM_DECOMMIT );
            if (pRtlIsEcCode) ok( pRtlIsEcCode( addr1 ), "not EC code %p\n", addr1 );

            size = 0x2000;
            ext[0].ULong = 0;
            status = pNtAllocateVirtualMemoryEx( NtCurrentProcess(), &addr1, &size, MEM_COMMIT,
                                                 PAGE_EXECUTE_READWRITE, ext, 1 );
            ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
            if (pRtlIsEcCode)
            {
                ok( pRtlIsEcCode( addr1 ), "not EC code %p\n", addr1 );
                ok( !pRtlIsEcCode( (char *)addr1 + 0x1000 ), "EC code %p\n", (char *)addr1 + 0x1000 );
            }

            size = 0;
            NtFreeVirtualMemory( NtCurrentProcess(), &addr1, &size, MEM_RELEASE );
            return;
        }
    }
#endif
    ok(status == STATUS_INVALID_PARAMETER || status == STATUS_NOT_SUPPORTED,
       "Unexpected status %08lx.\n", status);
}

static void test_NtAllocateVirtualMemoryEx_address_requirements(void)
{
    MEM_EXTENDED_PARAMETER ext[2];
    MEM_ADDRESS_REQUIREMENTS a;
    NTSTATUS status;
    SYSTEM_INFO si;
    SIZE_T size;
    void *addr;

    if (!pNtAllocateVirtualMemoryEx)
    {
        win_skip("NtAllocateVirtualMemoryEx() is missing\n");
        return;
    }

    GetSystemInfo(&si);

    memset(&ext, 0, sizeof(ext));
    ext[0].Type = 0;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    memset(&ext, 0, sizeof(ext));
    ext[0].Type = MemExtendedParameterMax;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    memset(&a, 0, sizeof(a));
    ext[0].Type = MemExtendedParameterAddressRequirements;
    ext[0].Pointer = &a;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    ext[1] = ext[0];
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 2);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = NULL;
    a.Alignment = 0;

    a.HighestEndingAddress = (void *)(0x20001000 + 1);
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20001000 - 2);
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20000800 - 1);
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (char *)si.lpMaximumApplicationAddress + 0x1000;
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (char *)si.lpMaximumApplicationAddress;
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    size = 0x40000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(!((ULONG_PTR)addr & 0xffff), "Unexpected addr %p.\n", addr);
    ok((ULONG_PTR)addr + size <= 0x20001000, "Unexpected addr %p.\n", addr);

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);


    size = 0x40000;
    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 24, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_3 || status == STATUS_INVALID_PARAMETER,
            "Unexpected status %08lx.\n", status);

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0xffffffff, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (is_win64 || is_wow64)
        ok(!status || status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);
    else
        ok(status == STATUS_INVALID_PARAMETER_3 || status == STATUS_INVALID_PARAMETER,
                "Unexpected status %08lx.\n", status);

    if (!status)
    {
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(!status, "Unexpected status %08lx.\n", status);
    }

    a.HighestEndingAddress = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status || status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx.\n", status);
    if (!status)
    {
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(!status, "Unexpected status %08lx.\n", status);
    }


    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    a.Alignment = 0x10000;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(!((ULONG_PTR)addr & 0xffff), "Unexpected addr %p.\n", addr);
    ok((ULONG_PTR)addr + size < 0x20001000, "Unexpected addr %p.\n", addr);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    a.Alignment = 0x20000000;
    size = 0x2000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_NO_MEMORY, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = NULL;
    a.Alignment = 0x8000;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.Alignment = 0x30000;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.Alignment = 0x40000;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(!((ULONG_PTR)addr & 0x3ffff), "Unexpected addr %p.\n", addr);
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)0x20001000;
    a.Alignment = 0;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)(0x20001000 - 1);
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)(0x20001000 + 1);
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)0x30000000;
    a.HighestEndingAddress = (void *)0x20000000;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)0x20000000;
    a.HighestEndingAddress = 0;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(addr >= (void *)0x20000000, "Unexpected addr %p.\n", addr);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (void *)0x20000000;
    a.HighestEndingAddress = (void *)0x2fffffff;
    size = 0x1000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(addr >= (void *)0x20000000 && addr < (void *)0x30000000, "Unexpected addr %p.\n", addr);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(!status, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = (char *)si.lpMaximumApplicationAddress + 1;
    a.HighestEndingAddress = 0;
    size = 0x10000;
    addr = NULL;
    status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size, MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE, ext, 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);
}

struct test_stack_size_thread_args
{
    DWORD expect_committed;
    DWORD expect_reserved;
};

static void DECLSPEC_NOINLINE force_stack_grow(void)
{
    volatile int buffer[0x2000];
    int i;

    for (i = 0; i < ARRAY_SIZE(buffer); i++) buffer[i] = 0xdeadbeef;
    (void)buffer[0];
}

static void DECLSPEC_NOINLINE force_stack_grow_small(void)
{
    volatile int buffer[0x400];
    int i;

    for (i = 0; i < ARRAY_SIZE(buffer); i++) buffer[i] = 0xdeadbeef;
    (void)buffer[0];
}

static DWORD WINAPI test_stack_size_thread(void *ptr)
{
    struct test_stack_size_thread_args *args = ptr;
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;
    SIZE_T size, guard_size;
    DWORD committed, reserved;
    void *addr;

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    reserved = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->DeallocationStack;
    todo_wine ok( committed == args->expect_committed || broken(committed == 0x1000), "unexpected stack committed size %lx, expected %lx\n", committed, args->expect_committed );
    ok( reserved == args->expect_reserved, "unexpected stack reserved size %lx, expected %lx\n", reserved, args->expect_reserved );

    addr = (char *)NtCurrentTeb()->DeallocationStack;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.AllocationBase == NtCurrentTeb()->DeallocationStack, "unexpected AllocationBase %p, expected %p\n", mbi.AllocationBase, NtCurrentTeb()->DeallocationStack );
    ok( mbi.AllocationProtect == PAGE_READWRITE, "unexpected AllocationProtect %#lx, expected %#x\n", mbi.AllocationProtect, PAGE_READWRITE );
    ok( mbi.BaseAddress == addr, "unexpected BaseAddress %p, expected %p\n", mbi.BaseAddress, addr );
    ok( mbi.State == MEM_RESERVE, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_RESERVE );
    ok( mbi.Protect == 0, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, 0 );
    ok( mbi.Type == MEM_PRIVATE, "unexpected Type %#lx, expected %#x\n", mbi.Type, MEM_PRIVATE );


    force_stack_grow();

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    reserved = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->DeallocationStack;
    todo_wine ok( committed == 0x9000, "unexpected stack committed size %lx, expected 9000\n", committed );
    ok( reserved == args->expect_reserved, "unexpected stack reserved size %lx, expected %lx\n", reserved, args->expect_reserved );


    /* reserved area shrinks whenever stack grows */

    addr = (char *)NtCurrentTeb()->DeallocationStack;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.AllocationBase == NtCurrentTeb()->DeallocationStack, "unexpected AllocationBase %p, expected %p\n", mbi.AllocationBase, NtCurrentTeb()->DeallocationStack );
    ok( mbi.AllocationProtect == PAGE_READWRITE, "unexpected AllocationProtect %#lx, expected %#x\n", mbi.AllocationProtect, PAGE_READWRITE );
    ok( mbi.BaseAddress == addr, "unexpected BaseAddress %p, expected %p\n", mbi.BaseAddress, addr );
    ok( mbi.State == MEM_RESERVE, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_RESERVE );
    ok( mbi.Protect == 0, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, 0 );
    ok( mbi.Type == MEM_PRIVATE, "unexpected Type %#lx, expected %#x\n", mbi.Type, MEM_PRIVATE );

    guard_size = reserved - committed - mbi.RegionSize;
    ok( guard_size == 0x1000 || guard_size == 0x2000 || guard_size == 0x3000, "unexpected guard_size %I64x, expected 1000, 2000 or 3000\n", (UINT64)guard_size );

    /* the commit area is initially preceded by guard pages */

    addr = (char *)NtCurrentTeb()->DeallocationStack + mbi.RegionSize;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.AllocationBase == NtCurrentTeb()->DeallocationStack, "unexpected AllocationBase %p, expected %p\n", mbi.AllocationBase, NtCurrentTeb()->DeallocationStack );
    ok( mbi.AllocationProtect == PAGE_READWRITE, "unexpected AllocationProtect %#lx, expected %#x\n", mbi.AllocationProtect, PAGE_READWRITE );
    ok( mbi.BaseAddress == addr, "unexpected BaseAddress %p, expected %p\n", mbi.BaseAddress, addr );
    ok( mbi.RegionSize == guard_size, "unexpected RegionSize %I64x, expected 3000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == (PAGE_READWRITE|PAGE_GUARD), "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE|PAGE_GUARD );
    ok( mbi.Type == MEM_PRIVATE, "unexpected Type %#lx, expected %#x\n", mbi.Type, MEM_PRIVATE );

    addr = (char *)NtCurrentTeb()->Tib.StackLimit;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.AllocationBase == NtCurrentTeb()->DeallocationStack, "unexpected AllocationBase %p, expected %p\n", mbi.AllocationBase, NtCurrentTeb()->DeallocationStack );
    ok( mbi.AllocationProtect == PAGE_READWRITE, "unexpected AllocationProtect %#lx, expected %#x\n", mbi.AllocationProtect, PAGE_READWRITE );
    ok( mbi.BaseAddress == addr, "unexpected BaseAddress %p, expected %p\n", mbi.BaseAddress, addr );
    ok( mbi.RegionSize == committed, "unexpected RegionSize %I64x, expected %I64x\n", (UINT64)mbi.RegionSize, (UINT64)committed );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );
    ok( mbi.Type == MEM_PRIVATE, "unexpected Type %#lx, expected %#x\n", mbi.Type, MEM_PRIVATE );

    return 0;
}

static DWORD WINAPI test_stack_growth_thread(void *ptr)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;
    SIZE_T size, guard_size;
    DWORD committed;
    void *addr;
    DWORD prot;
    void *tmp;

    test_stack_size_thread( ptr );
    if (!is_win64) return 0;

    addr = (char *)NtCurrentTeb()->DeallocationStack;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );

    guard_size = (char *)NtCurrentTeb()->Tib.StackLimit - (char *)NtCurrentTeb()->DeallocationStack - mbi.RegionSize;
    ok( guard_size == 0x1000 || guard_size == 0x2000 || guard_size == 0x3000, "unexpected guard_size %I64x, expected 1000, 2000 or 3000\n", (UINT64)guard_size );

    /* setting a guard page shrinks stack automatically */

    addr = (char *)NtCurrentTeb()->Tib.StackLimit + 0x2000;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD );
    ok( !status, "NtAllocateVirtualMemory returned %08lx\n", status );

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x6000, "unexpected stack committed size %lx, expected 6000\n", committed );

    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)addr - 0x2000, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.RegionSize == 0x2000, "unexpected RegionSize %I64x, expected 2000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );

    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.RegionSize == 0x1000, "unexpected RegionSize %I64x, expected 1000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == (PAGE_READWRITE|PAGE_GUARD), "unexpected Protect %#lx, expected %#x\n", mbi.Protect, (PAGE_READWRITE|PAGE_GUARD) );

    addr = (char *)NtCurrentTeb()->Tib.StackLimit;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    todo_wine ok( mbi.RegionSize == 0x6000, "unexpected RegionSize %I64x, expected 6000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );


    /* guard pages are restored as the stack grows back */

    addr = (char *)NtCurrentTeb()->Tib.StackLimit + 0x4000;
    tmp = (char *)addr - guard_size - 0x1000;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD );
    ok( !status, "NtAllocateVirtualMemory returned %08lx\n", status );

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x1000, "unexpected stack committed size %lx, expected 1000\n", committed );

    status = NtQueryVirtualMemory( NtCurrentProcess(), tmp, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    todo_wine ok( mbi.RegionSize == guard_size + 0x1000, "unexpected RegionSize %I64x, expected %I64x\n", (UINT64)mbi.RegionSize, (UINT64)(guard_size + 0x1000) );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );

    force_stack_grow_small();

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x2000, "unexpected stack committed size %lx, expected 2000\n", committed );

    status = NtQueryVirtualMemory( NtCurrentProcess(), tmp, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.RegionSize == 0x1000, "unexpected RegionSize %I64x, expected 1000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );

    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)tmp + 0x1000, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.RegionSize == guard_size, "unexpected RegionSize %I64x, expected %I64x\n", (UINT64)mbi.RegionSize, (UINT64)guard_size );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == (PAGE_READWRITE|PAGE_GUARD), "unexpected Protect %#lx, expected %#x\n", mbi.Protect, (PAGE_READWRITE|PAGE_GUARD) );


    /* forcing stack limit over guard pages still shrinks the stack on page fault */

    addr = (char *)tmp + guard_size + 0x1000;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD );
    ok( !status, "NtAllocateVirtualMemory returned %08lx\n", status );

    NtCurrentTeb()->Tib.StackLimit = (char *)tmp;

    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)tmp + 0x1000, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    todo_wine ok( mbi.RegionSize == guard_size + 0x1000, "unexpected RegionSize %I64x, expected %I64x\n", (UINT64)mbi.RegionSize, (UINT64)(guard_size + 0x1000) );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == (PAGE_READWRITE|PAGE_GUARD), "unexpected Protect %#lx, expected %#x\n", mbi.Protect, (PAGE_READWRITE|PAGE_GUARD) );

    force_stack_grow_small();

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x2000, "unexpected stack committed size %lx, expected 2000\n", committed );


    /* it works with NtProtectVirtualMemory as well */

    force_stack_grow();

    addr = (char *)NtCurrentTeb()->Tib.StackLimit + 0x2000;
    size = 0x1000;
    status = NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE | PAGE_GUARD, &prot );
    ok( !status, "NtProtectVirtualMemory returned %08lx\n", status );
    todo_wine ok( prot == PAGE_READWRITE, "unexpected prot %#lx, expected %#x\n", prot, PAGE_READWRITE );

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x6000, "unexpected stack committed size %lx, expected 6000\n", committed );

    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)addr - 0x2000, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    todo_wine ok( mbi.RegionSize == 0x2000, "unexpected RegionSize %I64x, expected 2000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );

    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    ok( mbi.RegionSize == 0x1000, "unexpected RegionSize %I64x, expected 1000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    ok( mbi.Protect == (PAGE_READWRITE|PAGE_GUARD), "unexpected Protect %#lx, expected %#x\n", mbi.Protect, (PAGE_READWRITE|PAGE_GUARD) );

    addr = (char *)NtCurrentTeb()->Tib.StackLimit;
    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &size );
    ok( !status, "NtQueryVirtualMemory returned %08lx\n", status );
    todo_wine ok( mbi.RegionSize == 0x6000, "unexpected RegionSize %I64x, expected 6000\n", (UINT64)mbi.RegionSize );
    ok( mbi.State == MEM_COMMIT, "unexpected State %#lx, expected %#x\n", mbi.State, MEM_COMMIT );
    todo_wine ok( mbi.Protect == PAGE_READWRITE, "unexpected Protect %#lx, expected %#x\n", mbi.Protect, PAGE_READWRITE );


    /* clearing the guard pages doesn't change StackLimit back */

    force_stack_grow();

    addr = (char *)NtCurrentTeb()->Tib.StackLimit + 0x2000;
    size = 0x1000;
    status = NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE | PAGE_GUARD, &prot );
    ok( !status, "NtProtectVirtualMemory returned %08lx\n", status );
    todo_wine ok( prot == PAGE_READWRITE, "unexpected prot %#lx, expected %#x\n", prot, PAGE_READWRITE );

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x6000, "unexpected stack committed size %lx, expected 6000\n", committed );

    status = NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &prot );
    ok( !status, "NtProtectVirtualMemory returned %08lx\n", status );
    ok( prot == (PAGE_READWRITE | PAGE_GUARD), "unexpected prot %#lx, expected %#x\n", prot, (PAGE_READWRITE | PAGE_GUARD) );

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x6000, "unexpected stack committed size %lx, expected 6000\n", committed );

    /* and as we messed with it and it now doesn't fault, it doesn't grow back either */

    force_stack_grow();

    committed = (char *)NtCurrentTeb()->Tib.StackBase - (char *)NtCurrentTeb()->Tib.StackLimit;
    todo_wine ok( committed == 0x6000, "unexpected stack committed size %lx, expected 6000\n", committed );

    ExitThread(0);
}

static DWORD WINAPI test_stack_size_dummy_thread(void *ptr)
{
    return 0;
}

static void test_RtlCreateUserStack(void)
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress );
    struct test_stack_size_thread_args args;
    SIZE_T default_commit = nt->OptionalHeader.SizeOfStackCommit;
    SIZE_T default_reserve = nt->OptionalHeader.SizeOfStackReserve;
    MEMORY_BASIC_INFORMATION mbi;
    INITIAL_TEB stack = {0};
    unsigned int i;
    NTSTATUS ret;
    HANDLE thread;
    CLIENT_ID id;
    SIZE_T szret;

    struct
    {
        SIZE_T commit, reserve, commit_align, reserve_align, expect_commit, expect_reserve;
    }
    tests[] =
    {
        {       0,        0,      1,        1, default_commit, default_reserve},
        {  0x2000,        0,      1,        1,         0x2000, default_reserve},
        {  0x4000,        0,      1,        1,         0x4000, default_reserve},
        {       0, 0x200000,      1,        1, default_commit, 0x200000},
        {  0x4000, 0x200000,      1,        1,         0x4000, 0x200000},
        {0x100000, 0x100000,      1,        1,       0x100000, 0x100000},
        { 0xff000, 0x100000,      1,        1,        0xff000, 0x100000},
        { 0x20000,  0x20000,      1,        1,        0x20000, 0x100000},

        {       0, 0x110000,      1,        1, default_commit, 0x110000},
        {       0, 0x110000,      1,  0x40000, default_commit, 0x140000},
        {       0, 0x140000,      1,  0x40000, default_commit, 0x140000},
        { 0x11000, 0x140000,      1,  0x40000,        0x11000, 0x140000},
        { 0x11000, 0x140000, 0x4000,  0x40000,        0x14000, 0x140000},
        {       0,        0, 0x4000, 0x400000,
                (default_commit + 0x3fff) & ~0x3fff,
                (default_reserve + 0x3fffff) & ~0x3fffff},
    };

    if (!pRtlCreateUserStack)
    {
        win_skip("RtlCreateUserStack() is missing\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        memset(&stack, 0xcc, sizeof(stack));
        ret = pRtlCreateUserStack(tests[i].commit, tests[i].reserve, 0,
                tests[i].commit_align, tests[i].reserve_align, &stack);
        ok(!ret, "%u: got status %#lx\n", i, ret);
        ok(!stack.OldStackBase, "%u: got OldStackBase %p\n", i, stack.OldStackBase);
        ok(!stack.OldStackLimit, "%u: got OldStackLimit %p\n", i, stack.OldStackLimit);
        ok(!((ULONG_PTR)stack.DeallocationStack & (page_size - 1)),
                "%u: got unaligned memory %p\n", i, stack.DeallocationStack);
        ok((ULONG_PTR)stack.StackBase - (ULONG_PTR)stack.DeallocationStack == tests[i].expect_reserve,
                "%u: got reserve %#Ix\n", i, (ULONG_PTR)stack.StackBase - (ULONG_PTR)stack.DeallocationStack);
        todo_wine ok((ULONG_PTR)stack.StackBase - (ULONG_PTR)stack.StackLimit == tests[i].expect_commit,
                "%u: got commit %#Ix\n", i, (ULONG_PTR)stack.StackBase - (ULONG_PTR)stack.StackLimit);
        szret = VirtualQuery(stack.DeallocationStack, &mbi, sizeof(mbi));
        ok(szret == sizeof(mbi), "got %Iu.\n", szret);
        ok(mbi.AllocationBase == stack.DeallocationStack, "got %p, %p.\n", mbi.AllocationBase, stack.DeallocationStack);
        if (tests[i].commit + 2 * page_size <= max( tests[i].reserve, 0x100000))
        {
            ok(mbi.State == MEM_RESERVE, "%u: got %#lx.\n", i, mbi.State);
            ok(!mbi.Protect, "%u: got %#lx.\n", i, mbi.Protect);
        }
        else if (tests[i].commit + page_size <= max( tests[i].reserve, 0x100000))
        {
            todo_wine ok(mbi.State == MEM_COMMIT, "%u: got %#lx.\n", i, mbi.State);
            todo_wine ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "%u: got %#lx.\n", i, mbi.Protect);
        }
        else
        {
            todo_wine ok(mbi.State == MEM_COMMIT, "%u: got %#lx.\n", i, mbi.State);
            todo_wine ok(mbi.Protect == PAGE_READWRITE, "%u: got %#lx.\n", i, mbi.Protect);
        }
        pRtlFreeUserStack(stack.DeallocationStack);
    }

    ret = pRtlCreateUserStack(0x11000, 0x110000, 0, 1, 0, &stack);
    ok(ret == STATUS_INVALID_PARAMETER, "got %#lx\n", ret);

    ret = pRtlCreateUserStack(0x11000, 0x110000, 0, 0, 1, &stack);
    ok(ret == STATUS_INVALID_PARAMETER, "got %#lx\n", ret);

    args.expect_committed = 0x4000;
    args.expect_reserved = default_reserve;
    thread = CreateThread(NULL, 0x3f00, test_stack_growth_thread, &args, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    args.expect_committed = default_commit < 0x2000 ? 0x2000 : default_commit;
    args.expect_reserved = 0x400000;
    thread = CreateThread(NULL, 0x3ff000, test_stack_growth_thread, &args, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    if (is_win64)
    {
        thread = CreateThread(NULL, 0x80000000, test_stack_size_dummy_thread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
        ok(thread != NULL, "CreateThread with huge stack failed\n");
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }

    args.expect_committed = default_commit < 0x2000 ? 0x2000 : default_commit;
    args.expect_reserved = 0x100000;
    for (i = 0; i < 32; i++)
    {
        ULONG mask = ~0u >> i;
        NTSTATUS expect_ret = STATUS_SUCCESS;

        if (i == 12) expect_ret = STATUS_CONFLICTING_ADDRESSES;
        else if (i >= 13) expect_ret = STATUS_INVALID_PARAMETER;
        ret = pRtlCreateUserStack( args.expect_committed, args.expect_reserved, i, 0x1000, 0x1000, &stack );
        ok( ret == expect_ret || ret == STATUS_NO_MEMORY ||
            (ret == STATUS_INVALID_PARAMETER_3 && expect_ret == STATUS_INVALID_PARAMETER) ||
            broken( i == 1 && ret == STATUS_INVALID_PARAMETER_3 ), /* win7 */
            "%u: got %lx / %lx\n", i, ret, expect_ret );
        if (!ret) pRtlFreeUserStack( stack.DeallocationStack );
        ret = pRtlCreateUserThread( GetCurrentProcess(), NULL, FALSE, i,
                                    args.expect_reserved, args.expect_committed,
                                    (void *)test_stack_size_thread, &args, &thread, &id );
        ok( ret == expect_ret || ret == STATUS_NO_MEMORY ||
            (ret == STATUS_INVALID_PARAMETER_3 && expect_ret == STATUS_INVALID_PARAMETER) ||
            broken( i == 1 && ret == STATUS_INVALID_PARAMETER_3 ), /* win7 */
            "%u: got %lx / %lx\n", i, ret, expect_ret );
        if (!ret)
        {
            WaitForSingleObject( thread, INFINITE );
            CloseHandle( thread );
        }

        if (mask <= 31) continue;
        if (!is_win64 && !is_wow64) expect_ret = STATUS_INVALID_PARAMETER_3;
        ret = pRtlCreateUserStack( args.expect_committed, args.expect_reserved, mask, 0x1000, 0x1000, &stack );
        ok( ret == expect_ret || ret == STATUS_NO_MEMORY ||
            (ret == STATUS_INVALID_PARAMETER_3 && expect_ret == STATUS_INVALID_PARAMETER),
            "%08lx: got %lx / %lx\n", mask, ret, expect_ret );
        if (!ret) pRtlFreeUserStack( stack.DeallocationStack );
        ret = pRtlCreateUserThread( GetCurrentProcess(), NULL, FALSE, mask,
                                    args.expect_reserved, args.expect_committed,
                                    (void *)test_stack_size_thread, &args, &thread, &id );
        ok( ret == expect_ret || ret == STATUS_NO_MEMORY ||
            (ret == STATUS_INVALID_PARAMETER_3 && expect_ret == STATUS_INVALID_PARAMETER),
            "%08lx: got %lx / %lx\n", mask, ret, expect_ret );
        if (!ret)
        {
            WaitForSingleObject( thread, INFINITE );
            CloseHandle( thread );
        }
    }
}

static void test_NtMapViewOfSection(void)
{
    static const char testfile[] = "testfile.xxx";
    static const char data[] = "test data for NtMapViewOfSection";
    char buffer[sizeof(data)];
    HANDLE file, mapping, process;
    void *ptr, *ptr2, *mem, *mem2;
    BOOL ret;
    DWORD status, written;
    SIZE_T size, size2, result;
    LARGE_INTEGER offset;
    ULONG_PTR zero_bits;
    SYSTEM_INFO si;

    if (!pIsWow64Process || !pIsWow64Process(NtCurrentProcess(), &is_wow64)) is_wow64 = FALSE;

    file = CreateFileA(testfile, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "Failed to create test file\n");
    WriteFile(file, data, sizeof(data), &written, NULL);
    SetFilePointer(file, 4096, NULL, FILE_BEGIN);
    SetEndOfFile(file);

    /* read/write mapping */

    mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, 4096, NULL);
    ok(mapping != 0, "CreateFileMapping failed\n");

    process = create_target_process("sleep");
    ok(process != NULL, "Can't start process\n");

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, NULL, &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_HANDLE, "NtMapViewOfSection returned %08lx\n", status);

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "NtMapViewOfSection returned %08lx\n", status);
    ok(!((ULONG_PTR)ptr & 0xffff), "returned memory %p is not aligned to 64k\n", ptr);

    ret = ReadProcessMemory(process, ptr, buffer, sizeof(buffer), &result);
    ok(ret, "ReadProcessMemory failed\n");
    ok(result == sizeof(buffer), "ReadProcessMemory didn't read all data (%Ix)\n", result);
    ok(!memcmp(buffer, data, sizeof(buffer)), "Wrong data read\n");

    /* 1 zero bits should zero 63-31 upper bits */
    ptr2 = NULL;
    size = 0;
    zero_bits = 1;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, zero_bits, 0, &offset, &size, 1, MEM_TOP_DOWN, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY,
       "NtMapViewOfSection returned %08lx\n", status);
    if (status == STATUS_SUCCESS)
    {
        ok(((UINT_PTR)ptr2 >> (32 - zero_bits)) == 0,
           "NtMapViewOfSection returned address: %p\n", ptr2);

        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);
    }

    for (zero_bits = 2; zero_bits <= 20; zero_bits++)
    {
        ptr2 = NULL;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, zero_bits, 0, &offset, &size, 1, MEM_TOP_DOWN, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY,
           "NtMapViewOfSection with %d zero_bits returned %08lx\n", (int)zero_bits, status);
        if (status == STATUS_SUCCESS)
        {
            ok(((UINT_PTR)ptr2 >> (32 - zero_bits)) == 0,
               "NtMapViewOfSection with %d zero_bits returned address %p\n", (int)zero_bits, ptr2);

            status = NtUnmapViewOfSection(process, ptr2);
            ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);
        }
    }

    /* 21 zero bits never succeeds */
    ptr2 = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, 21, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_NO_MEMORY || status == STATUS_INVALID_PARAMETER,
       "NtMapViewOfSection returned %08lx\n", status);

    /* 22 zero bits is invalid */
    ptr2 = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, 22, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_4 || status == STATUS_INVALID_PARAMETER,
       "NtMapViewOfSection returned %08lx\n", status);

    /* zero bits > 31 should be considered as a leading zeroes bitmask on 64bit and WoW64 */
    ptr2 = NULL;
    size = 0;
    zero_bits = 0x1aaaaaaa;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, zero_bits, 0, &offset, &size, 1, MEM_TOP_DOWN, PAGE_READWRITE);

    if (!is_win64 && !is_wow64)
    {
        ok(status == STATUS_INVALID_PARAMETER_4, "NtMapViewOfSection returned %08lx\n", status);
    }
    else
    {
        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY,
           "NtMapViewOfSection returned %08lx\n", status);
        if (status == STATUS_SUCCESS)
        {
            ok(((UINT_PTR)ptr2 & ~get_zero_bits_mask(zero_bits)) == 0 &&
               ((UINT_PTR)ptr2 & ~zero_bits) != 0, /* only the leading zeroes matter */
               "NtMapViewOfSection returned address %p\n", ptr2);

            status = NtUnmapViewOfSection(process, ptr2);
            ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);
        }
    }

    /* mapping at the same page conflicts */
    ptr2 = ptr;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "NtMapViewOfSection returned %08lx\n", status);

    /* offset has to be aligned */
    ptr2 = ptr;
    size = 0;
    offset.QuadPart = 1;
    status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "NtMapViewOfSection returned %08lx\n", status);

    /* ptr has to be aligned */
    ptr2 = (char *)ptr + 42;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "NtMapViewOfSection returned %08lx\n", status);

    /* still not 64k aligned */
    ptr2 = (char *)ptr + 0x1000;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "NtMapViewOfSection returned %08lx\n", status);

    /* when an address is passed, it has to satisfy the provided number of zero bits */
    ptr2 = (char *)ptr + 0x1000;
    size = 0;
    offset.QuadPart = 0;
    zero_bits = get_zero_bits(((UINT_PTR)ptr2) >> 1);
    status = NtMapViewOfSection(mapping, process, &ptr2, zero_bits, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_4 || status == STATUS_INVALID_PARAMETER,
       "NtMapViewOfSection returned %08lx\n", status);

    ptr2 = (char *)ptr + 0x1000;
    size = 0;
    offset.QuadPart = 0;
    zero_bits = get_zero_bits((UINT_PTR)ptr2);
    status = NtMapViewOfSection(mapping, process, &ptr2, zero_bits, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "NtMapViewOfSection returned %08lx\n", status);

    if (!is_win64 && !is_wow64)
    {
        /* new memory region conflicts with previous mapping */
        ptr2 = ptr;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_CONFLICTING_ADDRESSES, "NtMapViewOfSection returned %08lx\n", status);

        ptr2 = (char *)ptr + 42;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_CONFLICTING_ADDRESSES, "NtMapViewOfSection returned %08lx\n", status);

        /* in contrary to regular NtMapViewOfSection, only 4kb align is enforced */
        ptr2 = (char *)ptr + 0x1000;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "NtMapViewOfSection returned %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x1000,
           "expected address %p, got %p\n", (char *)ptr + 0x1000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

        /* the address is rounded down if not on a page boundary */
        ptr2 = (char *)ptr + 0x1001;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "NtMapViewOfSection returned %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x1000,
           "expected address %p, got %p\n", (char *)ptr + 0x1000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

        ptr2 = (char *)ptr + 0x2000;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "NtMapViewOfSection returned %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x2000,
           "expected address %p, got %p\n", (char *)ptr + 0x2000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);
    }
    else
    {
        ptr2 = (char *)ptr + 0x1000;
        size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset,
                                    &size, 1, AT_ROUND_TO_PAGE, PAGE_READWRITE);
        ok(status == STATUS_INVALID_PARAMETER_9 || status == STATUS_INVALID_PARAMETER,
           "NtMapViewOfSection returned %08lx\n", status);
    }

    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    NtClose(mapping);

    CloseHandle(file);
    DeleteFileA(testfile);

    /* test zero_bits > 31 with a 64-bit DLL file image mapping */
    if (is_win64)
    {
        file = CreateFileA("c:\\windows\\system32\\version.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
        ok(file != INVALID_HANDLE_VALUE, "Failed to open version.dll\n");

        mapping = CreateFileMappingA(file, NULL, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);
        ok(mapping != 0, "CreateFileMapping failed\n");

        ptr = NULL;
        size = 0;
        offset.QuadPart = 0;
        zero_bits = 0x7fffffff;
        status = NtMapViewOfSection(mapping, process, &ptr, zero_bits, 0, &offset, &size, 1, 0, PAGE_READONLY);

        ok(status == STATUS_SUCCESS || status == STATUS_IMAGE_NOT_AT_BASE, "NtMapViewOfSection returned %08lx\n", status);
        ok(!((ULONG_PTR)ptr & 0xffff), "returned memory %p is not aligned to 64k\n", ptr);
        ok(((UINT_PTR)ptr & ~get_zero_bits_mask(zero_bits)) == 0, "NtMapViewOfSection returned address %p\n", ptr);

        status = NtUnmapViewOfSection(process, ptr);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

        NtClose(mapping);
        CloseHandle(file);
    }

    /* image offset */

    GetSystemInfo(&si);

    file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "Failed to open ntdll.dll\n");

    mapping = CreateFileMappingA(file, NULL, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);
    ok(mapping != 0, "CreateFileMapping failed\n");

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, process, &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE, "NtMapViewOfSection returned %08lx\n", status);

    ptr2 = NULL;
    size2 = 0;
    offset.QuadPart = si.dwAllocationGranularity;
    status = NtMapViewOfSection(mapping, process, &ptr2, 0, 0, &offset, &size2, 1, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE, "NtMapViewOfSection returned %08lx\n", status);

    ok(size2 == size - si.dwAllocationGranularity, "got unexpected sizes %Ix, %Ix\n", size, size2);
    size2 = size - si.dwAllocationGranularity;

    mem = malloc(size2);
    ret = ReadProcessMemory(process, (char*)ptr + si.dwAllocationGranularity, mem, size2, &result);
    ok(ret, "ReadProcessMemory failed\n");
    ok(size2 == result, "ReadProcessMemory didn't read all data (%Ix)\n", result);

    mem2 = malloc(size2);
    ret = ReadProcessMemory(process, ptr2, mem2, size2, &result);
    ok(ret, "ReadProcessMemory failed\n");
    ok(size2 == result, "ReadProcessMemory didn't read all data (%Ix)\n", result);

    ok(memcmp(mem, mem2, size2) == 0, "memory does not match\n");

    free(mem);
    free(mem2);

    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    status = NtUnmapViewOfSection(process, ptr2);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    NtClose(mapping);
    CloseHandle(file);

    TerminateProcess(process, 0);
    CloseHandle(process);
}

static void test_NtMapViewOfSectionEx(void)
{
    static const char testfile[] = "testfile.xxx";
    static const char data[] = "test data for NtMapViewOfSectionEx";
    char buffer[sizeof(data)];
    MEM_EXTENDED_PARAMETER ext[2];
    MEM_ADDRESS_REQUIREMENTS a;
    SYSTEM_INFO si;
    HANDLE file, mapping, process;
    DWORD status, written;
    SIZE_T size, result;
    LARGE_INTEGER offset;
    void *ptr, *ptr2;
    BOOL ret;

    if (!pNtMapViewOfSectionEx)
    {
        win_skip("NtMapViewOfSectionEx() is not supported.\n");
        return;
    }

    if (!pIsWow64Process || !pIsWow64Process(NtCurrentProcess(), &is_wow64)) is_wow64 = FALSE;
    GetSystemInfo(&si);

    file = CreateFileA(testfile, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "Failed to create test file\n");
    WriteFile(file, data, sizeof(data), &written, NULL);
    SetFilePointer(file, 0x40000, NULL, FILE_BEGIN);
    SetEndOfFile(file);

    /* read/write mapping */

    mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, 0x40000, NULL);
    ok(mapping != 0, "CreateFileMapping failed\n");

    process = create_target_process("sleep");
    ok(process != NULL, "Can't start process\n");

    ptr = NULL;
    size = 0x1000;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx(mapping, NULL, &ptr, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_HANDLE, "Unexpected status %08lx\n", status);

    ptr = NULL;
    size = 0x1000;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx(mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx\n", status);
    ok(!((ULONG_PTR)ptr & 0xffff), "returned memory %p is not aligned to 64k\n", ptr);

    ret = ReadProcessMemory(process, ptr, buffer, sizeof(buffer), &result);
    ok(ret, "ReadProcessMemory failed\n");
    ok(result == sizeof(buffer), "ReadProcessMemory didn't read all data (%Ix)\n", result);
    ok(!memcmp(buffer, data, sizeof(buffer)), "Wrong data read\n");

    /* mapping at the same page conflicts */
    ptr2 = ptr;
    size = 0;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx\n", status);

    /* offset has to be aligned */
    ptr2 = ptr;
    size = 0;
    offset.QuadPart = 1;
    status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_MAPPED_ALIGNMENT, "Unexpected status %08lx\n", status);

    /* ptr has to be aligned */
    ptr2 = (char *)ptr + 42;
    size = 0;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_MAPPED_ALIGNMENT, "Unexpected status %08lx\n", status);

    /* still not 64k aligned */
    ptr2 = (char *)ptr + 0x1000;
    size = 0;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, 0, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_MAPPED_ALIGNMENT, "Unexpected status %08lx\n", status);

    if (!is_win64 && !is_wow64)
    {
        /* new memory region conflicts with previous mapping */
        ptr2 = ptr;
        size = 0x1000;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx\n", status);

        ptr2 = (char *)ptr + 42;
        size = 0x1000;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_CONFLICTING_ADDRESSES, "Unexpected status %08lx\n", status);

        /* in contrary to regular NtMapViewOfSection, only 4kb align is enforced */
        ptr2 = (char *)ptr + 0x1000;
        size = 0x1000;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_SUCCESS, "Unexpected status %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x1000,
           "expected address %p, got %p\n", (char *)ptr + 0x1000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

        /* the address is rounded down if not on a page boundary */
        ptr2 = (char *)ptr + 0x1001;
        size = 0x1000;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_SUCCESS, "Unexpected status %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x1000,
           "expected address %p, got %p\n", (char *)ptr + 0x1000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

        ptr2 = (char *)ptr + 0x2000;
        size = 0x1000;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_SUCCESS, "Unexpected status %08lx\n", status);
        ok((char *)ptr2 == (char *)ptr + 0x2000,
           "expected address %p, got %p\n", (char *)ptr + 0x2000, ptr2);
        status = NtUnmapViewOfSection(process, ptr2);
        ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);
    }
    else
    {
        ptr2 = (char *)ptr + 0x1000;
        size = 0;
        offset.QuadPart = 0;
        status = pNtMapViewOfSectionEx(mapping, process, &ptr2, &offset, &size, AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_INVALID_PARAMETER, "NtMapViewOfSectionEx returned %08lx\n", status);
    }

    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    /* extended parameters */

    memset(&ext, 0, sizeof(ext));
    ext[0].Type = 0;
    size = 0x1000;
    ptr = NULL;
    offset.QuadPart = 0;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    memset(&ext, 0, sizeof(ext));
    ext[0].Type = MemExtendedParameterMax;
    size = 0x1000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    memset(&a, 0, sizeof(a));
    ext[0].Type = MemExtendedParameterAddressRequirements;
    ext[0].Pointer = &a;
    size = 0x1000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(!status, "Unexpected status %08lx.\n", status);
    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    ext[1] = ext[0];
    size = 0x1000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 2 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.LowestStartingAddress = NULL;
    a.Alignment = 0;
    a.HighestEndingAddress = (void *)(0x20001000 + 1);
    size = 0x10000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20001000 - 2);
    size = 0x10000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (void *)(0x20000800 - 1);
    size = 0x10000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (char *)si.lpMaximumApplicationAddress + 0x1000;
    size = 0x10000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = (char *)si.lpMaximumApplicationAddress;
    size = 0x10000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(!status, "Unexpected status %08lx.\n", status);
    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    size = 0x40000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(!status, "Unexpected status %08lx.\n", status);
    ok(!((ULONG_PTR)ptr & 0xffff), "Unexpected addr %p.\n", ptr);
    ok((ULONG_PTR)ptr + size <= 0x20001000, "Unexpected addr %p.\n", ptr);
    status = NtUnmapViewOfSection(process, ptr);
    ok(status == STATUS_SUCCESS, "NtUnmapViewOfSection returned %08lx\n", status);

    size = 0x40000;
    a.HighestEndingAddress = (void *)(0x20001000 - 1);
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    a.HighestEndingAddress = NULL;
    a.Alignment = 0x30000;
    size = 0x1000;
    ptr = NULL;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %08lx.\n", status);

    for (a.Alignment = 1; a.Alignment; a.Alignment *= 2)
    {
        size = 0x1000;
        ptr = NULL;
        status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READWRITE, ext, 1 );
        ok(status == STATUS_INVALID_PARAMETER, "Align %Ix unexpected status %08lx.\n", a.Alignment, status);
    }

    NtClose(mapping);

    CloseHandle(file);
    DeleteFileA(testfile);

    file = CreateFileA( "c:\\windows\\system32\\version.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0 );
    ok( file != INVALID_HANDLE_VALUE, "Failed to open version.dll\n" );
    mapping = CreateFileMappingA( file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    memset(&ext, 0, sizeof(ext));
    ext[0].Type = MemExtendedParameterImageMachine;
    ext[0].ULong = 0;
    ptr = NULL;
    size = 0;
    status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READONLY, ext, 1 );
    if (status != STATUS_INVALID_PARAMETER)
    {
        ok(status == STATUS_SUCCESS || status == STATUS_IMAGE_NOT_AT_BASE, "NtMapViewOfSection returned %08lx\n", status);
        NtUnmapViewOfSection(process, ptr);

        ext[1].Type = MemExtendedParameterImageMachine;
        ext[1].ULong = 0;
        ptr = NULL;
        size = 0;
        status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READONLY, ext, 2 );
        ok(status == STATUS_INVALID_PARAMETER, "NtMapViewOfSection returned %08lx\n", status);

        ext[0].ULong = IMAGE_FILE_MACHINE_R3000;
        ext[1].ULong = IMAGE_FILE_MACHINE_R4000;
        ptr = NULL;
        size = 0;
        status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READONLY, ext, 2 );
        ok(status == STATUS_INVALID_PARAMETER, "NtMapViewOfSection returned %08lx\n", status);

        ptr = NULL;
        size = 0;
        status = pNtMapViewOfSectionEx( mapping, process, &ptr, &offset, &size, 0, PAGE_READONLY, ext, 1 );
        ok(status == STATUS_NOT_SUPPORTED, "NtMapViewOfSection returned %08lx\n", status);
    }
    else win_skip( "MemExtendedParameterImageMachine not supported\n" );

    NtClose(mapping);
    CloseHandle(file);

    TerminateProcess(process, 0);
    CloseHandle(process);
}

static void test_user_shared_data(void)
{
    struct old_xstate_configuration
    {
        ULONG64 EnabledFeatures;
        ULONG Size;
        ULONG OptimizedSave:1;
        ULONG CompactionEnabled:1;
        XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];
    };

    ULONG feature_offsets[] =
    {
            0,
            160, /*offsetof(XMM_SAVE_AREA32, XmmRegisters)*/
            512  /* sizeof(XMM_SAVE_AREA32) */ + offsetof(XSTATE, YmmContext),
    };
    ULONG feature_sizes[] =
    {
            160,
            256, /*sizeof(M128A) * 16 */
            sizeof(YMMCONTEXT),
    };
    const KUSER_SHARED_DATA *user_shared_data = (void *)0x7ffe0000;
    XSTATE_CONFIGURATION xstate = user_shared_data->XState;
    ULONG64 feature_mask;
    ULONG64 supported_xstate_features = (1 << XSTATE_LEGACY_FLOATING_POINT) | (1 << XSTATE_LEGACY_SSE) | (1 << XSTATE_AVX);
    ULONG xstate_part_size = sizeof(XSTATE);
    unsigned int i;

    ok(user_shared_data->NumberOfPhysicalPages == sbi.MmNumberOfPhysicalPages,
            "Got number of physical pages %#lx, expected %#lx.\n",
            user_shared_data->NumberOfPhysicalPages, sbi.MmNumberOfPhysicalPages);

#if defined(__i386__) || defined(__x86_64__)
    ok(user_shared_data->ProcessorFeatures[PF_RDTSC_INSTRUCTION_AVAILABLE] /* Supported since Pentium CPUs. */,
            "_RDTSC not available.\n");
#endif
    ok(user_shared_data->ActiveProcessorCount == NtCurrentTeb()->Peb->NumberOfProcessors
            || broken(!user_shared_data->ActiveProcessorCount) /* before Win7 */,
            "Got unexpected ActiveProcessorCount %lu.\n", user_shared_data->ActiveProcessorCount);
    ok(user_shared_data->ActiveGroupCount == 1
            || broken(!user_shared_data->ActiveGroupCount) /* before Win7 */,
            "Got unexpected ActiveGroupCount %u.\n", user_shared_data->ActiveGroupCount);

    if (!pRtlGetEnabledExtendedFeatures)
    {
        win_skip("RtlGetEnabledExtendedFeatures is not available.\n");
        return;
    }

    feature_mask = pRtlGetEnabledExtendedFeatures(~(ULONG64)0);
    if (!feature_mask)
    {
        skip("XState features are not available.\n");
        return;
    }

    if (!xstate.EnabledFeatures)
    {
        struct old_xstate_configuration *xs_old
                = (struct old_xstate_configuration *)((char *)user_shared_data + 0x3e0);

        ok(feature_mask == xs_old->EnabledFeatures, "Got unexpected xs_old->EnabledFeatures %s.\n",
                wine_dbgstr_longlong(xs_old->EnabledFeatures));
        win_skip("Old structure layout.\n");
        return;
    }

    if (!(xstate.EnabledFeatures & (1 << XSTATE_AVX)))
    {
        trace("AVX not present\n");
        feature_offsets[2] = 0;
        feature_sizes[2] = 0;
        xstate_part_size = offsetof( XSTATE, YmmContext );
        supported_xstate_features = (1 << XSTATE_LEGACY_FLOATING_POINT) | (1 << XSTATE_LEGACY_SSE);
    }

    trace("XState EnabledFeatures %#I64x, EnabledSupervisorFeatures %#I64x, EnabledVolatileFeatures %I64x.\n",
            xstate.EnabledFeatures, xstate.EnabledSupervisorFeatures, xstate.EnabledVolatileFeatures);
    feature_mask = pRtlGetEnabledExtendedFeatures(0);
    ok(!feature_mask, "Got unexpected feature_mask %s.\n", wine_dbgstr_longlong(feature_mask));
    feature_mask = pRtlGetEnabledExtendedFeatures(~(ULONG64)0);
    ok(feature_mask == (xstate.EnabledFeatures | xstate.EnabledSupervisorFeatures), "Got unexpected feature_mask %s.\n",
            wine_dbgstr_longlong(feature_mask));
    feature_mask = pGetEnabledXStateFeatures();
    ok(feature_mask == (xstate.EnabledFeatures | xstate.EnabledSupervisorFeatures), "Got unexpected feature_mask %s.\n",
            wine_dbgstr_longlong(feature_mask));
    ok((xstate.EnabledFeatures & supported_xstate_features) == supported_xstate_features,
            "Got unexpected EnabledFeatures %s.\n", wine_dbgstr_longlong(xstate.EnabledFeatures));
    ok((xstate.EnabledVolatileFeatures & supported_xstate_features) == (xstate.EnabledFeatures & supported_xstate_features),
            "Got unexpected EnabledVolatileFeatures %s.\n", wine_dbgstr_longlong(xstate.EnabledVolatileFeatures));
    ok(xstate.Size >= 512 + xstate_part_size,
            "Got unexpected Size %lu, expected %lu.\n", xstate.Size, (ULONG)(512 + xstate_part_size));
    if (xstate.CompactionEnabled)
        ok(xstate.OptimizedSave, "Got zero OptimizedSave with compaction enabled.\n");
    ok(!xstate.AlignedFeatures, "Got unexpected AlignedFeatures %s.\n",
            wine_dbgstr_longlong(xstate.AlignedFeatures));
    ok(xstate.AllFeatureSize >= 512 + xstate_part_size
            || !xstate.AllFeatureSize /* win8 on CPUs without XSAVEC */,
            "Got unexpected AllFeatureSize %lu.\n", xstate.AllFeatureSize);

    for (i = 0; i < ARRAY_SIZE(feature_sizes); ++i)
    {
        ok(xstate.AllFeatures[i] == feature_sizes[i]
                || !xstate.AllFeatures[i] /* win8+ on CPUs without XSAVEC */,
                "Got unexpected AllFeatures[%u] %lu, expected %lu.\n", i,
                xstate.AllFeatures[i], feature_sizes[i]);
        ok(xstate.Features[i].Size == feature_sizes[i], "Got unexpected Features[%u].Size %lu, expected %lu.\n", i,
                xstate.Features[i].Size, feature_sizes[i]);
        ok(xstate.Features[i].Offset == feature_offsets[i], "Got unexpected Features[%u].Offset %lu, expected %lu.\n",
                i, xstate.Features[i].Offset, feature_offsets[i]);
    }
}

static void perform_relocations( void *module, INT_PTR delta )
{
    IMAGE_NT_HEADERS *nt;
    IMAGE_BASE_RELOCATION *rel, *end;
    const IMAGE_DATA_DIRECTORY *relocs;
    const IMAGE_SECTION_HEADER *sec;
    ULONG protect_old[96], i;

    nt = RtlImageNtHeader( module );
    relocs = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocs->VirtualAddress || !relocs->Size) return;
    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr,
                                &size, PAGE_READWRITE, &protect_old[i] );
    }
    rel = (IMAGE_BASE_RELOCATION *)((char *)module + relocs->VirtualAddress);
    end = (IMAGE_BASE_RELOCATION *)((char *)rel + relocs->Size);
    while (rel && rel < end - 1 && rel->SizeOfBlock)
        rel = LdrProcessRelocationBlock( (char *)module + rel->VirtualAddress,
                                         (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT),
                                         (USHORT *)(rel + 1), delta );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr,
                                &size, protect_old[i], &protect_old[i] );
    }
}


static void test_syscalls(void)
{
    HMODULE module = GetModuleHandleW( L"ntdll.dll" );
    HANDLE handle;
    NTSTATUS status;
    NTSTATUS (WINAPI *pNtClose)(HANDLE);
    WCHAR path[MAX_PATH];
    HANDLE file, mapping;
    INT_PTR delta;
    void *ptr;

    /* initial image */
    pNtClose = (void *)GetProcAddress( module, "NtClose" );
    handle = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( handle != 0, "CreateEventWfailed %lu\n", GetLastError() );
    status = pNtClose( handle );
    ok( !status, "NtClose failed %lx\n", status );
    status = pNtClose( handle );
    ok( status == STATUS_INVALID_HANDLE, "NtClose failed %lx\n", status );

    /* syscall thunk copy */
    ptr = VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    ok( ptr != NULL, "VirtualAlloc failed\n" );
    memcpy( ptr, pNtClose, 32 );
    pNtClose = ptr;
    handle = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( handle != 0, "CreateEventWfailed %lu\n", GetLastError() );
    status = pNtClose( handle );
    ok( !status, "NtClose failed %lx\n", status );
    status = pNtClose( handle );
    ok( status == STATUS_INVALID_HANDLE, "NtClose failed %lx\n", status );
    VirtualFree( ptr, 0, MEM_FREE );

    /* new mapping */
    GetModuleFileNameW( module, path, MAX_PATH );
    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0 );
    ok( file != INVALID_HANDLE_VALUE, "can't open %s: %lu\n", wine_dbgstr_w(path), GetLastError() );
    mapping = CreateFileMappingW( file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL );
    ok( mapping != NULL, "CreateFileMappingW failed err %lu\n", GetLastError() );
    ptr = MapViewOfFile( mapping, FILE_MAP_READ, 0, 0, 0 );
    ok( ptr != NULL, "MapViewOfFile failed err %lu\n", GetLastError() );
    CloseHandle( mapping );
    delta = (char *)ptr - (char *)module;

    if (memcmp( ptr, module, 0x1000 ))
    {
        skip( "modules are not identical (non-PE build?)\n" );
        UnmapViewOfFile( ptr );
        CloseHandle( file );
        return;
    }
    perform_relocations( ptr, delta );
    pNtClose = (void *)GetProcAddress( module, "NtClose" );

    if (pRtlFindExportedRoutineByName)
    {
        void *func = pRtlFindExportedRoutineByName( module, "NtClose" );
        ok( func == (void *)pNtClose, "wrong ptr %p / %p\n", func, pNtClose );
        func = pRtlFindExportedRoutineByName( ptr, "NtClose" );
        ok( (char *)func - (char *)pNtClose == delta, "wrong ptr %p / %p\n", func, pNtClose );
    }
    else win_skip( "RtlFindExportedRoutineByName not supported\n" );

    if (!memcmp( pNtClose, (char *)pNtClose + delta, 32 ))
    {
        pNtClose = (void *)((char *)pNtClose + delta);
        handle = CreateEventW( NULL, FALSE, FALSE, NULL );
        ok( handle != 0, "CreateEventWfailed %lu\n", GetLastError() );
        status = pNtClose( handle );
        ok( !status, "NtClose failed %lx\n", status );
        status = pNtClose( handle );
        ok( status == STATUS_INVALID_HANDLE, "NtClose failed %lx\n", status );
    }
    else
    {
#ifdef __i386__
        NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, void *, ULONG, ULONG *);
        PROCESS_BASIC_INFORMATION pbi;
        void *exec_mem, *va_ptr;
        ULONG size;
        BOOL ret;

        exec_mem = VirtualAlloc( NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ok( !!exec_mem, "got NULL.\n" );

        /* NtQueryInformationProcess is special. */
        pNtQueryInformationProcess = (void *)GetProcAddress( module, "NtQueryInformationProcess" );
        va_ptr = RtlImageRvaToVa( RtlImageNtHeader(module), module,
                                  (char *)pNtQueryInformationProcess - (char *)module, NULL );
        ok( !!va_ptr, "offset not found %p / %p\n", pNtQueryInformationProcess, module );
        ret = SetFilePointer( file, (char *)va_ptr - (char *)module, NULL, FILE_BEGIN );
        ok( ret, "got %d, err %lu.\n", ret, GetLastError() );
        ret = ReadFile( file, exec_mem, 32, NULL, NULL );
        ok( ret, "got %d, err %lu.\n", ret, GetLastError() );
        if (!memcmp( exec_mem, pNtQueryInformationProcess, 5 ))
        {
            pNtQueryInformationProcess = exec_mem;
            /* The thunk still works without relocation. */
            status = pNtQueryInformationProcess( GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &size );
            ok( !status, "got %#lx.\n", status );
            ok( size == sizeof(pbi), "got %lu.\n", size );
            ok( pbi.PebBaseAddress == NtCurrentTeb()->Peb, "got %p, %p.\n", pbi.PebBaseAddress, NtCurrentTeb()->Peb );
        }
        else
            ok( 0, "file on disk doesn't match syscall %x / %x\n",
                *(UINT *)pNtQueryInformationProcess, *(UINT *)exec_mem );

        VirtualFree( exec_mem, 0, MEM_RELEASE );
#elif defined __x86_64__
        ok( 0, "syscall thunk relocated\n" );
#else
        skip( "syscall thunk relocated\n" );
#endif
    }
    CloseHandle( file );
    UnmapViewOfFile( ptr );
}

static void test_invalid_syscalls(void)
{
    HMODULE module = GetModuleHandleW( L"ntdll.dll" );
    NTSTATUS (WINAPI *pNtImpersonateAnonymousToken)( HANDLE thread );
    NTSTATUS status;
    DWORD prot, i;
    LONG old_id, new_id, *id;

    /* grab a syscall that's unlikely to be used while we are testing */
    pNtImpersonateAnonymousToken = (void *)GetProcAddress( module, "NtImpersonateAnonymousToken" );
    if (!pNtImpersonateAnonymousToken)
    {
        win_skip( "NtImpersonateAnonymousToken not supported\n" );
        return;
    }
    status = pNtImpersonateAnonymousToken( 0 );
    ok( status == STATUS_INVALID_HANDLE || status == STATUS_NOT_IMPLEMENTED, "wrong status %lx\n", status );
    VirtualProtect( pNtImpersonateAnonymousToken, 32, PAGE_EXECUTE_READWRITE, &prot );
    for (i = 0; i < 4; i++)
    {
        new_id = 0x666 | (i << 12);
        winetest_push_context( "%04lx", new_id );
#ifdef __i386__
        id = (LONG *)((BYTE *)pNtImpersonateAnonymousToken + 1);
        new_id = (*id & ~0xffff) | new_id;
#elif defined __x86_64__
        id = (LONG *)pNtImpersonateAnonymousToken + 1;
        new_id = (*id & ~0xffff) | new_id;
#elif defined __aarch64__
        id = (LONG *)pNtImpersonateAnonymousToken;
        new_id = (*id & ~(0xffff << 5)) | (new_id << 5);
#elif defined __arm__
        id = (LONG *)(((ULONG_PTR)pNtImpersonateAnonymousToken & ~1) + 2);
        new_id = 0x0c00f240 | ((new_id & 0xff) << 16) | ((new_id & 0xf00) << 20) | (new_id >> 12); /* movw ip, #0xnnn */
#endif
        old_id = *id;
        *id = new_id;
        NtFlushInstructionCache( GetCurrentProcess(), pNtImpersonateAnonymousToken, 32 );
        status = pNtImpersonateAnonymousToken( 0 );
        ok( status == STATUS_INVALID_SYSTEM_SERVICE, "wrong status %lx\n", status );
        *id = old_id;
        NtFlushInstructionCache( GetCurrentProcess(), pNtImpersonateAnonymousToken, 32 );
        winetest_pop_context();
    }
    VirtualProtect( pNtImpersonateAnonymousToken, 32, prot, &prot );
}

struct syscall_export
{
    UINT        rva;
    int         id;
    const char *name;
};

static int CDECL sort_syscalls( const void *a, const void *b )
{
    const struct syscall_export *exp_a = a;
    const struct syscall_export *exp_b = b;
    int ret = exp_a->rva - exp_b->rva;
    if (!ret) ret = strcmp( exp_a->name, exp_b->name );
    return ret;
}

static int get_syscall_id( void *code )
{
#ifdef __i386__
    static const BYTE patterns[][18] =
    {
        { 0xb8, 0, 0, 0, 0, 0xba, 0, 0, 0, 0, 0xff, 0xd2 }, /* >= win10 */
        { 0xb8, 0, 0, 0, 0, 0xba, 0, 0, 0, 0, 0xff, 0x12 }, /* winxp */
        { 0xb8, 0, 0, 0, 0, 0x64, 0xff, 0x15, 0xc0, 0, 0, 0 },  /* nt */
        { 0xb8, 0, 0, 0, 0, 0x8d, 0x54, 0x24, 0x04, 0xcd, 0x2e }, /* nt */
        { 0xb8, 0, 0, 0, 0, 0xb9, 0, 0, 0, 0, 0x8d, 0x54, 0x24, 0x04, 0x64, 0xff, 0x15, 0xc0 }, /* vista */
        { 0xb8, 0, 0, 0, 0, 0x33, 0xc9, 0x8d, 0x54, 0x24, 0x04, 0x64, 0xff, 0x15, 0xc0 }, /* vista */
        { 0xb8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x8d, 0x54, 0x24, 0x04, 0x64, 0xff, 0x15, 0xc0 }, /* win8 */
        { 0xb8, 0, 0, 0, 0, 0xe8, 0x01, 0, 0, 0, 0xc3, 0x8b, 0xd4, 0x0f, 0x34, 0xc3 },  /* win8 */
        { 0xb8, 0, 0, 0, 0, 0xe8, 0x03, 0, 0, 0, 0xc2, 0, 0, 0x8b, 0xd4, 0x0f, 0x34, 0xc3 }, /* win8 */
    };
    const BYTE *instr = code;
    UINT i, j;

    for (i = 0; i < ARRAY_SIZE(patterns); i++)
    {
        for (j = 0; j < ARRAY_SIZE(patterns[0]); j++)
            if (patterns[i][j] && patterns[i][j] != instr[j]) break;
        if (j == ARRAY_SIZE(patterns[0]))
            return *(UINT *)(instr + 1);
    }
#elif defined __x86_64__
    static const BYTE patterns[][20] =
    {
        { 0x4c, 0x8b, 0xd1, 0xb8, 0, 0, 0, 0, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe,
          0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05 },  /* >= win10 */
        { 0x4c, 0x8b, 0xd1, 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xc3 }, /* < win10 */
    };
    const BYTE *instr = code;
    UINT i, j;

    for (i = 0; i < ARRAY_SIZE(patterns); i++)
    {
        for (j = 0; j < ARRAY_SIZE(patterns[0]); j++)
            if (patterns[i][j] && patterns[i][j] != instr[j]) break;
        if (j == ARRAY_SIZE(patterns[0]))
            return ((UINT *)instr)[1];
    }
#elif defined __aarch64__
    const UINT *instr = code;

    if ((instr[0] & 0xffe0001f) == 0xd4000001 && instr[1] == 0xd65f03c0)  /* windows */
        return (instr[0] >> 5) & 0xffff;
    if ((instr[0] & 0xffe0001f) == 0xd2800008 && instr[1] == 0xaa1e03e9 &&
        instr[3] == 0xf9400210 && instr[4] == 0xd63f0200 && instr[5] == 0xd65f03c0) /* wine */
        return (instr[0] >> 5) & 0xffff;
#elif defined __arm__
    const USHORT *instr = code;

    if (instr[0] == 0xb40f && (instr[2] & 0x0f00) == 0x0c00 &&
        ((instr[3] == 0xdef8 && instr[4] == 0xb004 && instr[5] == 0x4770) ||  /* windows */
         (instr[3] == 0x4673 && instr[6] == 0xb004 && instr[7] == 0x4770)))  /* wine */
    {
        USHORT imm = ((instr[1] & 0x400) << 1) | (instr[2] & 0xff) | ((instr[2] >> 4) & 0x0700);
        if ((instr[1] & 0xfbf0) == 0xf240)  /* T3 */
        {
            return imm | (instr[1] & 0x0f) << 12;
        }
        else if ((instr[1] & 0xfbf0) == 0xf040)  /* T2 */
        {
            switch (imm >> 8)
            {
            case 0: return imm;
            case 1: return (imm & 0xff);
            case 2: return (imm & 0xff) << 8;
            case 3: return (imm & 0xff) | ((imm & 0xff) << 8);
            default: return (0x80 | (imm & 0x7f)) << (32 - (imm >> 7));
            }
        }
    }
#endif
    return -1;
}

static void test_syscall_numbers(void)
{
    struct syscall_export syscalls[4096];
    HMODULE module = GetModuleHandleA( "ntdll.dll" );
    IMAGE_EXPORT_DIRECTORY *exports;
    ULONG size;
    int pos;
    const WORD *ordinals;
    const DWORD *names, *functions;
    static const char *prefix[] = { "Nt", "Zw" };

    exports = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size );
    names = get_rva( module, exports->AddressOfNames );
    ordinals = get_rva( module, exports->AddressOfNameOrdinals );
    functions = get_rva( module, exports->AddressOfFunctions );

    for (unsigned int test = 0; test < ARRAY_SIZE(prefix); test++)
    {
        for (int i = pos = 0; i < exports->NumberOfNames; i++)
        {
            char *name = get_rva( module, names[i] );
            if (strncmp( name, prefix[test], strlen(prefix[test]) )) continue;
            if (!strcmp( name, "NtGetTickCount" ) ||
                !strcmp( name, "NtCurrentTeb" ) ||
                !strncmp( name, "NtdllDialogWndProc", 18 ) ||
                !strncmp( name, "NtdllDefWindowProc", 18 ))
                continue;  /* these are special */
            syscalls[pos].rva  = functions[ordinals[i]];
#ifdef __arm__
            syscalls[pos].rva &= ~1; /* thumb */
#endif
            syscalls[pos].id   = get_syscall_id( get_rva( module, syscalls[pos].rva ));
            syscalls[pos].name = name;
            pos++;
        }
        ok( pos, "no syscalls found\n" );
        qsort( syscalls, pos, sizeof(*syscalls), sort_syscalls );
        for (int i = 0, expect = 0; i < pos; i++, expect++)
        {
            if (syscalls[i].id == -1)
            {
                /* these may not be real syscalls */
                ok( !strcmp( syscalls[i].name + strlen(prefix[test]), "QuerySystemTime" ) ||
                    !strcmp( syscalls[i].name + strlen(prefix[test]), "QueryInformationProcess" ),
                    "not a syscall %04x %s\n", i, syscalls[i].name );
            }
            else if (LOWORD(syscalls[i].id) > expect)
            {
                ok( 0, "missing syscall %04x\n", expect );
                i--;
            }
            else
            {
                ok( LOWORD(syscalls[i].id) == expect, "wrong id %04x / %04x for %s\n",
                    syscalls[i].id, expect, syscalls[i].name );
            }
        }
    }
}

static void test_NtFreeVirtualMemory(void)
{
    void *addr1, *addr;
    NTSTATUS status;
    SIZE_T size;

    size = 0x10000;
    addr1 = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr1, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    size = 0;
    status = NtFreeVirtualMemory(NULL, &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_INVALID_HANDLE, "Unexpected status %08lx.\n", status);

    addr = (char *)addr1 + 0x1000;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_FREE_VM_NOT_AT_BASE, "Unexpected status %08lx.\n", status);

    size = 0x11000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "Unexpected status %08lx.\n", status);

    addr = (char *)addr1 + 0x1001;
    size = 0xffff;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "Unexpected status %08lx.\n", status);
    ok(size == 0xffff, "Unexpected size %p.\n", (void *)size);
    ok(addr == (char *)addr1 + 0x1001, "Got addr %p, addr1 %p.\n", addr, addr1);

    size = 0xfff;
    addr = (char *)addr1 + 0x1001;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    *(volatile char *)addr1 = 1;
    *((volatile char *)addr1 + 0x2000) = 1;
    ok(size == 0x1000, "Unexpected size %p.\n", (void *)size);
    ok(addr == (char *)addr1 + 0x1000, "Got addr %p, addr1 %p.\n", addr, addr1);

    size = 0xfff;
    addr = (char *)addr1 + 1;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    *((volatile char *)addr1 + 0x2000) = 1;
    ok(size == 0x1000, "Unexpected size %p.\n", (void *)size);
    ok(addr == addr1, "Got addr %p, addr1 %p.\n", addr, addr1);

    size = 0x1000;
    addr = addr1;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(addr == addr1, "Unexpected addr %p, addr1 %p.\n", addr, addr1);
    ok(size == 0x1000, "Unexpected size %p.\n", (void *)size);

    size = 0x10000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_DECOMMIT);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "Unexpected status %08lx.\n", status);

    size = 0x10000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "Unexpected status %08lx.\n", status);

    size = 0;
    addr = (char *)addr1 + 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_MEMORY_NOT_ALLOCATED, "Unexpected status %08lx.\n", status);

    size = 0x1000;
    addr = (char *)addr1 + 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_MEMORY_NOT_ALLOCATED, "Unexpected status %08lx.\n", status);

    size = 0;
    addr = (char *)addr1 + 0x2000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    size = 0x1000;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr1, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
}

static void test_shared_private_backing_lifecycle(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    void *base = NULL, *addr;
    SIZE_T size, query_size;
    NTSTATUS status;
    BOOL split = FALSE, left_live = FALSE, right_live = FALSE;
    BYTE *bytes;
    ULONG old_protect;

    if (!shared_private_backing_enabled()) return;

    size = page_size * 5;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve returned %08lx\n", status);
    if (status) return;
    ok(size == page_size * 5, "reserve size %Ix expected %Ix\n", size, page_size * 5);

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation, &mbi, sizeof(mbi), &query_size);
    ok(status == STATUS_SUCCESS, "query reserved page returned %08lx\n", status);
    if (!status)
    {
        ok(mbi.AllocationBase == base, "allocation base %p expected %p\n", mbi.AllocationBase, base);
        ok(mbi.State == MEM_RESERVE, "reserved page state %#lx\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "reserved page type %#lx\n", mbi.Type);
    }

    /* Commit only the middle two pages; this exercises commitment within an existing backed reservation. */
    addr = (char *)base + page_size;
    size = page_size * 2;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "partial commit returned %08lx\n", status);
    if (status) goto release_whole;
    ok(addr == (char *)base + page_size, "partial commit base %p\n", addr);
    ok(size == page_size * 2, "partial commit size %Ix\n", size);
    bytes = base;
    ok(bytes[page_size + 37] == 0, "first committed page was not zero-filled\n");
    ok(bytes[page_size * 2 + 37] == 0, "second committed page was not zero-filled\n");
    bytes[page_size + 37] = 0x51;
    bytes[page_size * 2 + 37] = 0x52;

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size, MemoryBasicInformation,
                                  &mbi, sizeof(mbi), &query_size);
    ok(status == STATUS_SUCCESS, "query first committed page returned %08lx\n", status);
    if (!status)
    {
        ok(mbi.State == MEM_COMMIT, "first committed page state %#lx\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "first committed page type %#lx\n", mbi.Type);
        ok(mbi.Protect == PAGE_READWRITE, "first committed page protection %#lx\n", mbi.Protect);
    }

    addr = (char *)base + page_size * 2;
    size = page_size;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
    ok(status == STATUS_SUCCESS, "protect second page returned %08lx\n", status);
    if (!status) ok(old_protect == PAGE_READWRITE, "old protection %#lx\n", old_protect);
    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size * 2,
                                  MemoryBasicInformation, &mbi, sizeof(mbi), &query_size);
    ok(status == STATUS_SUCCESS, "query read-only page returned %08lx\n", status);
    if (!status)
    {
        ok(mbi.State == MEM_COMMIT, "read-only page state %#lx\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "read-only page type %#lx\n", mbi.Type);
        ok(mbi.Protect == PAGE_READONLY, "read-only page protection %#lx\n", mbi.Protect);
    }

    /* Decommit/recommit one page while the neighboring committed page keeps its data and protection. */
    addr = (char *)base + page_size;
    size = page_size;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "partial decommit returned %08lx\n", status);
    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size,
                                  MemoryBasicInformation, &mbi, sizeof(mbi), &query_size);
    ok(status == STATUS_SUCCESS, "query decommitted page returned %08lx\n", status);
    if (!status)
    {
        ok(mbi.State == MEM_RESERVE, "decommitted page state %#lx\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "decommitted page type %#lx\n", mbi.Type);
    }
    ok(bytes[page_size * 2 + 37] == 0x52, "neighbor data changed during decommit\n");

    addr = (char *)base + page_size;
    size = page_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "recommit returned %08lx\n", status);
    if (status) goto release_whole;
    ok(bytes[page_size + 37] == 0, "recommitted page was not zero-filled\n");
    ok(bytes[page_size * 2 + 37] == 0x52, "neighbor data changed across recommit\n");
    bytes[page_size + 37] = 0x51;

    /* Release one committed page, splitting the reservation into two independently mutable siblings. */
    addr = (char *)base + page_size * 2;
    size = page_size;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "partial release returned %08lx\n", status);
    if (status) goto release_whole;
    split = TRUE;
    left_live = right_live = TRUE;
    ok(size == page_size, "partial release size %Ix\n", size);

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size * 2,
                                  MemoryBasicInformation, &mbi, sizeof(mbi), &query_size);
    ok(status == STATUS_SUCCESS, "query released middle page returned %08lx\n", status);
    if (!status) ok(mbi.State == MEM_FREE, "released middle page state %#lx\n", mbi.State);

    /* Commit, decommit and recommit pages on both sides of the released hole. */
    addr = base;
    size = page_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "left sibling commit returned %08lx\n", status);
    if (status) goto release_siblings;
    bytes[37] = 0x50;
    addr = (char *)base + page_size * 3;
    size = page_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "right sibling commit returned %08lx\n", status);
    if (status) goto release_siblings;
    bytes[page_size * 3 + 37] = 0x53;

    addr = base;
    size = page_size;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "left sibling decommit returned %08lx\n", status);
    addr = (char *)base + page_size * 3;
    size = page_size;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "right sibling decommit returned %08lx\n", status);

    addr = base;
    size = page_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "left sibling recommit returned %08lx\n", status);
    if (!status) ok(bytes[37] == 0, "left sibling recommit was not zero-filled\n");
    addr = (char *)base + page_size * 3;
    size = page_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "right sibling recommit returned %08lx\n", status);
    if (!status) ok(bytes[page_size * 3 + 37] == 0, "right sibling recommit was not zero-filled\n");
    ok(bytes[page_size + 37] == 0x51, "left sibling data changed across right-side operations\n");

release_siblings:
    if (left_live)
    {
        addr = base;
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "left sibling release returned %08lx\n", status);
        if (status)
        {
            addr = base;
            size = 0;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "retry left sibling release returned %08lx\n", status);
        }
        left_live = !!status;
    }
    if (right_live)
    {
        addr = (char *)base + page_size * 3;
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "right sibling release returned %08lx\n", status);
        if (status)
        {
            addr = (char *)base + page_size * 3;
            size = 0;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "retry right sibling release returned %08lx\n", status);
        }
        right_live = !!status;
    }
    if (!left_live && !right_live)
    {
        MEMORY_BASIC_INFORMATION left_mbi, right_mbi;
        status = NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation,
                                      &left_mbi, sizeof(left_mbi), &query_size);
        ok(status == STATUS_SUCCESS, "query released left sibling returned %08lx\n", status);
        if (!status) ok(left_mbi.State == MEM_FREE, "left sibling state after release %#lx\n", left_mbi.State);
        status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size * 4,
                                      MemoryBasicInformation, &right_mbi, sizeof(right_mbi), &query_size);
        ok(status == STATUS_SUCCESS, "query released right sibling returned %08lx\n", status);
        if (!status) ok(right_mbi.State == MEM_FREE, "right sibling state after release %#lx\n", right_mbi.State);
        status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + page_size * 2,
                                      MemoryBasicInformation, &right_mbi, sizeof(right_mbi), &query_size);
        ok(status == STATUS_SUCCESS, "query released hole returned %08lx\n", status);
        if (!status) ok(right_mbi.State == MEM_FREE, "released hole state after cleanup %#lx\n", right_mbi.State);
    }
    if (left_live || right_live) return;
    return;

release_whole:
    if (split) goto release_siblings;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "fallback reservation release returned %08lx\n", status);
}

/* These probes execute ordinary loads/stores.  The handler only recovers the
 * exact instruction and address under test; an unrelated fault is not hidden. */
#ifdef __x86_64__
static void *private_probe_pc, *private_probe_resume, *private_probe_address;
static ULONG_PTR private_probe_access;
static unsigned int private_probe_faults;

static LONG CALLBACK private_backing_probe_handler( EXCEPTION_POINTERS *exception )
{
    EXCEPTION_RECORD *record = exception->ExceptionRecord;

    if (record->ExceptionCode != STATUS_ACCESS_VIOLATION || record->NumberParameters != 2 ||
        record->ExceptionAddress != private_probe_pc ||
        record->ExceptionInformation[1] != (ULONG_PTR)private_probe_address)
        return EXCEPTION_CONTINUE_SEARCH;

    private_probe_access = record->ExceptionInformation[0];
    ++private_probe_faults;
    exception->ContextRecord->Rip = (ULONG_PTR)private_probe_resume;
    exception->ContextRecord->Rax = 0xdead;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void private_backing_expect_access( void *function, void *address, ULONG_PTR access,
                                          BOOL fault, unsigned int expected, void *resume )
{
    unsigned int (__cdecl *probe)( void *, unsigned int ) = function;
    unsigned int result;

    private_probe_pc = function;
    private_probe_resume = resume;
    private_probe_address = address;
    private_probe_access = ~0;
    private_probe_faults = 0;
    result = probe( address, 0x63 );
    private_probe_pc = NULL;
    ok( private_probe_faults == !!fault, "access %Iu faults %u expected %u at %p\n",
        access, private_probe_faults, !!fault, address );
    if (fault)
    {
        ok( private_probe_access == access, "fault access %Iu expected %Iu\n", private_probe_access, access );
        ok( result == 0xdead, "fault probe result %#x\n", result );
    }
    else ok( result == expected, "access %Iu result %#x expected %#x\n", access, result, expected );
}
#endif

static void test_private_mapping_protection_lifetime(void)
{
#ifdef __x86_64__
    static const BYTE read_code[] = { 0x0f, 0xb6, 0x01, 0xc3 }; /* movzbl (rcx),eax; ret */
    static const BYTE write_code[] = { 0x88, 0x11, 0x31, 0xc0, 0xc3 }; /* mov dl,(rcx); xor eax,eax; ret */
    static const BYTE exec_code[] = { 0xb8, 42, 0, 0, 0, 0xc3 }; /* mov eax,42; ret */
    BYTE *code, *base = NULL, *saved, *addr;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size, query_size, i;
    NTSTATUS status;
    HANDLE handler = NULL;
    ULONG old_protect;

    /* Run the same observable VM contract with backing on and off. */
    code = VirtualAlloc( NULL, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    ok( code != NULL, "probe allocation failed: %lu\n", GetLastError() );
    if (!code) return;
    memcpy( code, read_code, sizeof(read_code) );
    memcpy( code + 16, write_code, sizeof(write_code) );
    code[32] = 0xc3; /* Recovery returns through the probe's existing caller frame. */
    ok( FlushInstructionCache( GetCurrentProcess(), code, page_size ), "probe cache flush failed\n" );
    if (!VirtualProtect( code, page_size, PAGE_EXECUTE_READ, &old_protect ))
    {
        ok( 0, "probe protection failed: %lu\n", GetLastError() );
        goto done;
    }
    handler = RtlAddVectoredExceptionHandler( TRUE, private_backing_probe_handler );
    ok( handler != NULL, "probe handler installation failed\n" );
    if (!handler) goto done;
    size = page_size * 3;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&base, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    ok( status == STATUS_SUCCESS, "lifetime allocation returned %08lx\n", status );
    if (status) goto done;
    saved = base;
    for (i = 0; i < page_size * 3 && !base[i]; ++i) {}
    ok( i == page_size * 3, "first commit retained data at offset %Ix\n", i );
    memset( base, 0x5a, page_size * 3 );

    private_backing_expect_access( code, base, 0, FALSE, 0x5a, code + 32 );
    private_backing_expect_access( code + 16, base, 1, FALSE, 0, code + 32 );
    ok( base[0] == 0x63, "ordinary write was not visible\n" );
    memcpy( base, exec_code, sizeof(exec_code) );
    private_backing_expect_access( base, base, 8, TRUE, 0, code + 32 );
    addr = base;
    size = page_size;
    status = NtProtectVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, PAGE_EXECUTE_READ, &old_protect );
    ok( status == STATUS_SUCCESS, "execute protection returned %08lx\n", status );
    if (status) goto release;
    ok( old_protect == PAGE_READWRITE, "old executable page protection %#lx\n", old_protect );
    ok( FlushInstructionCache( GetCurrentProcess(), base, sizeof(exec_code) ), "target cache flush failed\n" );
    private_backing_expect_access( base, base, 8, FALSE, 42, code + 32 );
    private_backing_expect_access( code + 16, base, 1, TRUE, 0, code + 32 );
    addr = base;
    size = page_size;
    status = NtProtectVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, PAGE_READWRITE, &old_protect );
    ok( status == STATUS_SUCCESS, "remove execute protection returned %08lx\n", status );
    if (status) goto release;
    ok( old_protect == PAGE_EXECUTE_READ, "removed executable page old protection %#lx\n", old_protect );
    private_backing_expect_access( base, base, 8, TRUE, 0, code + 32 );
    private_backing_expect_access( code + 16, base, 1, FALSE, 0, code + 32 );
    private_backing_expect_access( code, base, 0, FALSE, 0x63, code + 32 );

    addr = base + page_size;
    size = page_size;
    status = NtProtectVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, PAGE_READONLY, &old_protect );
    ok( status == STATUS_SUCCESS, "read-only protection returned %08lx\n", status );
    if (status) goto release;
    private_backing_expect_access( code, addr, 0, FALSE, 0x5a, code + 32 );
    private_backing_expect_access( code + 16, addr, 1, TRUE, 0, code + 32 );
    ok( base[page_size] == 0x5a && base[page_size * 2] == 0x5a, "read-only fault changed bytes\n" );

    size = page_size;
    status = NtProtectVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, PAGE_NOACCESS, &old_protect );
    ok( status == STATUS_SUCCESS, "no-access protection returned %08lx\n", status );
    if (status) goto release;
    private_backing_expect_access( code, addr, 0, TRUE, 0, code + 32 );
    private_backing_expect_access( code + 16, addr, 1, TRUE, 0, code + 32 );
    size = page_size;
    status = NtFreeVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, MEM_DECOMMIT );
    ok( status == STATUS_SUCCESS, "lifetime decommit returned %08lx\n", status );
    if (status) goto release;
    private_backing_expect_access( code, addr, 0, TRUE, 0, code + 32 );
    private_backing_expect_access( code + 16, addr, 1, TRUE, 0, code + 32 );
    size = page_size;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&addr, 0, &size, MEM_COMMIT, PAGE_READWRITE );
    ok( status == STATUS_SUCCESS, "lifetime recommit returned %08lx\n", status );
    if (status) goto release;
    for (i = 0; i < page_size && !addr[i]; ++i) {}
    ok( i == page_size, "recommitted page retained data at offset %Ix\n", i );
    private_backing_expect_access( code + 16, addr, 1, FALSE, 0, code + 32 );
    private_backing_expect_access( code, addr, 0, FALSE, 0x63, code + 32 );
    ok( base[page_size * 2] == 0x5a, "neighbor changed across protection/decommit/recommit\n" );
    addr = base + page_size * 2;
    size = page_size;
    status = NtFreeVirtualMemory( NtCurrentProcess(), (void **)&addr, &size, MEM_DECOMMIT );
    ok( status == STATUS_SUCCESS, "read/write page decommit returned %08lx\n", status );
    if (status) goto release;
    private_backing_expect_access( code, addr, 0, TRUE, 0, code + 32 );
    private_backing_expect_access( code + 16, addr, 1, TRUE, 0, code + 32 );
    ok( base[0] == 0x63 && base[page_size] == 0x63, "read/write decommit changed neighbors\n" );

release:
    size = 0;
    status = NtFreeVirtualMemory( NtCurrentProcess(), (void **)&base, &size, MEM_RELEASE );
    ok( status == STATUS_SUCCESS, "lifetime release returned %08lx\n", status );
    if (status) goto done;
    base = NULL;
    private_backing_expect_access( code, saved, 0, TRUE, 0, code + 32 );
    private_backing_expect_access( code + 16, saved, 1, TRUE, 0, code + 32 );
    status = NtQueryVirtualMemory( NtCurrentProcess(), saved, MemoryBasicInformation,
                                  &mbi, sizeof(mbi), &query_size );
    ok( status == STATUS_SUCCESS, "released lifetime query returned %08lx\n", status );
    if (!status) ok( mbi.State == MEM_FREE, "released lifetime state %#lx\n", mbi.State );
    base = saved;
    size = page_size * 3;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&base, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    ok( status == STATUS_SUCCESS, "same-address reuse returned %08lx\n", status );
    if (status)
    {
        base = NULL;
        goto done;
    }
    ok( base == saved, "reuse base %p expected %p\n", base, saved );
    for (i = 0; i < page_size * 3 && !base[i]; ++i) {}
    ok( i == page_size * 3, "reused mapping retained old data at offset %Ix\n", i );
    private_backing_expect_access( code + 16, base, 1, FALSE, 0, code + 32 );
    private_backing_expect_access( code, base, 0, FALSE, 0x63, code + 32 );
    trace( "private_backing_matrix protection_lifetime completed backing=%u\n", shared_private_backing_enabled() );

done:
    if (base)
    {
        size = 0;
        status = NtFreeVirtualMemory( NtCurrentProcess(), (void **)&base, &size, MEM_RELEASE );
        ok( status == STATUS_SUCCESS, "reuse cleanup returned %08lx\n", status );
    }
    if (handler) RtlRemoveVectoredExceptionHandler( handler );
    VirtualFree( code, 0, MEM_RELEASE );
#endif
}

static void test_shared_private_backing_child(void)
{
    HANDLE process = NULL, ready_event = NULL, release_event = NULL;
    char ready_name[64], release_name[64], arg[160];
    void *base = NULL, *remote_base;
    void *candidates[16] = { 0 };
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size, remote_size, bytes_read;
    NTSTATUS status;
    DWORD exit_code, wait_status;
    BYTE local_byte, remote_byte;
    unsigned int attempt, candidate_count = 0, i;
    BOOL common_found = FALSE;
    HANDLE wait_handles[2];

    /* The explicit observer hold also exercises this fixture with backing off. */
    if (!shared_private_backing_enabled() && !shared_private_backing_probe_hold()) return;

    sprintf(ready_name, "wine_shared_private_backing_%08lx_ready", GetCurrentProcessId());
    sprintf(release_name, "wine_shared_private_backing_%08lx_release", GetCurrentProcessId());
    ready_event = CreateEventA(NULL, TRUE, FALSE, ready_name);
    release_event = CreateEventA(NULL, TRUE, FALSE, release_name);
    ok(ready_event != NULL, "failed to create ready event: %lu\n", GetLastError());
    ok(release_event != NULL, "failed to create release event: %lu\n", GetLastError());
    if (!ready_event || !release_event) goto done;

    sprintf(arg, "vm-backing-child %s %s", ready_name, release_name);
    process = create_target_process(arg);
    ok(process != NULL, "failed to start backing child\n");
    if (!process) goto done;

    wait_handles[0] = ready_event;
    wait_handles[1] = process;
    wait_status = WaitForMultipleObjects(ARRAY_SIZE(wait_handles), wait_handles, FALSE, 10000);
    ok(wait_status == WAIT_OBJECT_0, "child ready wait returned %#lx\n", wait_status);
    if (wait_status != WAIT_OBJECT_0) goto terminate_child;

    /* Keep each local candidate reserved until the child accepts one, so collisions cannot repeat. */
    for (attempt = 0; attempt < 16; attempt++)
    {
        base = NULL;
        size = page_size * 2;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "local candidate allocation returned %08lx\n", status);
        if (status) goto terminate_child;
        candidates[candidate_count++] = base;
        base = NULL;

        remote_base = candidates[candidate_count - 1];
        remote_size = page_size * 2;
        status = NtAllocateVirtualMemory(process, &remote_base, 0, &remote_size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (status == STATUS_SUCCESS)
        {
            ok(remote_base == candidates[candidate_count - 1], "child allocation base %p differs from requested %p\n",
               remote_base, candidates[candidate_count - 1]);
            if (remote_base != candidates[candidate_count - 1])
            {
                size = 0;
                NtFreeVirtualMemory(process, &remote_base, &size, MEM_RELEASE);
                goto terminate_child;
            }
            base = remote_base;
            candidates[candidate_count - 1] = NULL;
            common_found = TRUE;
            break;
        }
        if (status != STATUS_CONFLICTING_ADDRESSES && status != STATUS_NO_MEMORY)
        {
            ok(0, "child same-address allocation returned unexpected %08lx\n", status);
            goto terminate_child;
        }
    }
    ok(common_found, "could not find a common free address after %u distinct candidates\n", candidate_count);
    for (i = 0; i < candidate_count; i++)
    {
        if (!candidates[i]) continue;
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &candidates[i], &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "discard local candidate %u returned %08lx\n", i, status);
        candidates[i] = NULL;
    }
    if (!common_found) goto terminate_child;
    ok(base == remote_base, "local base %p differs from child base %p\n", base, remote_base);

    local_byte = 0x59;
    *(volatile BYTE *)base = local_byte;
    remote_byte = 0xa7;
    status = WriteProcessMemory(process, remote_base, &remote_byte, sizeof(remote_byte), &bytes_read);
    ok(status, "WriteProcessMemory to child failed: %lu\n", GetLastError());
    ok(bytes_read == sizeof(remote_byte), "wrote %Ix bytes to child\n", bytes_read);
    ok(*(volatile BYTE *)base == local_byte, "child write changed caller's same-VA allocation\n");

    bytes_read = 0;
    status = ReadProcessMemory(process, remote_base, &local_byte, sizeof(local_byte), &bytes_read);
    ok(status, "ReadProcessMemory from child failed: %lu\n", GetLastError());
    ok(bytes_read == sizeof(local_byte), "read %Ix bytes from child\n", bytes_read);
    ok(local_byte == remote_byte, "child byte %#x expected %#x\n", local_byte, remote_byte);

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(process, remote_base, MemoryBasicInformation, &mbi, sizeof(mbi), &bytes_read);
    ok(status == STATUS_SUCCESS, "query child private page returned %08lx\n", status);
    if (!status)
    {
        ok(mbi.AllocationBase == remote_base, "child allocation base %p expected %p\n", mbi.AllocationBase, remote_base);
        ok(mbi.State == MEM_COMMIT, "child page state %#lx\n", mbi.State);
        ok(mbi.Type == MEM_PRIVATE, "child page type %#lx\n", mbi.Type);
        ok(mbi.Protect == PAGE_READWRITE, "child page protection %#lx\n", mbi.Protect);
    }

    trace("shared_private_backing_probe state=resident parent_pid=%lu child_pid=%lu base=%p size=%Ix\n",
          GetCurrentProcessId(), GetProcessId(process), remote_base, remote_size);
    {
        DWORD hold = shared_private_backing_probe_hold();
        if (hold) Sleep(hold);
    }
    ok(SetEvent(release_event), "failed to signal child release event: %lu\n", GetLastError());
    wait_status = WaitForSingleObject(process, 10000);
    ok(wait_status == WAIT_OBJECT_0, "child exit wait returned %#lx\n", wait_status);
    if (wait_status == WAIT_OBJECT_0)
    {
        BOOL got_exit_code;
        exit_code = ~0u;
        got_exit_code = GetExitCodeProcess(process, &exit_code);
        ok(got_exit_code, "GetExitCodeProcess failed: %lu\n", GetLastError());
        ok(exit_code == 0, "child exited with %lu\n", exit_code);
        ok(*(volatile BYTE *)base == 0x59, "child exit changed caller's private bytes\n");
        *(volatile BYTE *)base = 0x5b;
        ok(*(volatile BYTE *)base == 0x5b, "caller mapping became unusable after child exit\n");
        trace("shared_private_backing_probe state=free owner=child parent_state=resident parent_pid=%lu child_pid=%lu base=%p size=%Ix exit=%lu\n",
              GetCurrentProcessId(), GetProcessId(process), remote_base, remote_size, exit_code);
        {
            DWORD hold = shared_private_backing_probe_hold();
            if (hold) Sleep(hold);
        }
    }
    else
    {
        TerminateProcess(process, 1);
        WaitForSingleObject(process, 10000);
    }

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "local shared-address release returned %08lx\n", status);
    if (!status)
    {
        memset(&mbi, 0, sizeof(mbi));
        status = NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation, &mbi, sizeof(mbi), &bytes_read);
        ok(status == STATUS_SUCCESS, "query released caller page returned %08lx\n", status);
        if (!status) ok(mbi.State == MEM_FREE, "caller page state after release %#lx\n", mbi.State);
    }
    goto done;

terminate_child:
    if (process)
    {
        SetEvent(release_event);
        if (WaitForSingleObject(process, 1000) != WAIT_OBJECT_0)
        {
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 10000);
        }
    }
    if (base)
    {
        size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    }
    for (i = 0; i < candidate_count; i++)
    {
        if (!candidates[i]) continue;
        size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &candidates[i], &size, MEM_RELEASE);
        candidates[i] = NULL;
    }
done:
    if (process) CloseHandle(process);
    if (ready_event) CloseHandle(ready_event);
    if (release_event) CloseHandle(release_event);
}

static void test_shared_private_backing_failure(void)
{
    char failure_case[32], base_string[32], *end;
    MEMORY_BASIC_INFORMATION mbi;
    void *base, *addr;
    SIZE_T size, returned_size;
    NTSTATUS status;
    ULONGLONG base_value;
    BYTE *bytes;
    ULONG old_protect;
    DWORD len;

    if (!shared_private_backing_enabled()) return;
    if (!is_win64) return;
    len = GetEnvironmentVariableA("PROTON_VM_FAIL_CASE", failure_case, sizeof(failure_case));
    if (!len) return;
    if (len >= sizeof(failure_case))
    {
        ok(0, "PROTON_VM_FAIL_CASE is too long\n");
        return;
    }
    if (!strcmp(failure_case, "fatal-protect") || !strcmp(failure_case, "fatal-decommit"))
    {
        char arg[96];
        HANDLE process;
        DWORD wait_status, exit_code = ~0u;

        len = GetEnvironmentVariableA("PROTON_VM_FAIL_BASE", base_string, sizeof(base_string));
        if (!len || len >= sizeof(base_string))
        {
            ok(0, "fatal rollback test requires PROTON_VM_FAIL_BASE\n");
            return;
        }
        base_value = strtoull(base_string, &end, 0);
        if (!base_value || *end || (base_value & 0xffff))
        {
            ok(0, "invalid PROTON_VM_FAIL_BASE %s\n", base_string);
            return;
        }
        sprintf(arg, "vm-backing-fatal %s %s", failure_case + 6, base_string);
        process = create_target_process(arg);
        ok(process != NULL, "failed to start fatal rollback child\n");
        if (!process) return;
        wait_status = WaitForSingleObject(process, 10000);
        ok(wait_status == WAIT_OBJECT_0, "fatal rollback child wait returned %#lx\n", wait_status);
        if (wait_status != WAIT_OBJECT_0)
        {
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 10000);
        }
        else
        {
            BOOL got_exit_code = GetExitCodeProcess(process, &exit_code);
            ok(got_exit_code, "GetExitCodeProcess failed: %lu\n", GetLastError());
            ok(exit_code == STATUS_UNSUCCESSFUL, "fatal rollback child exited %08lx\n", exit_code);
            trace("private_backing_failure case=%s stage=child_exit status=%08lx\n", failure_case, exit_code);
        }
        CloseHandle(process);
        return;
    }
    len = GetEnvironmentVariableA("PROTON_VM_FAIL_BASE", base_string, sizeof(base_string));
    if (!len || len >= sizeof(base_string))
    {
        ok(0, "PROTON_VM_FAIL_CASE requires PROTON_VM_FAIL_BASE\n");
        return;
    }

    base_value = strtoull(base_string, &end, 0);
    if (!base_value || *end || (base_value & 0xffff))
    {
        ok(0, "invalid PROTON_VM_FAIL_BASE %s\n", base_string);
        return;
    }
    base = (void *)(ULONG_PTR)base_value;
    trace("private_backing_failure case=%s stage=begin base=%p size=0x9000\n", failure_case, base);

    if (!strcmp(failure_case, "map"))
    {
        size = 0x9000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        trace("private_backing_failure case=map stage=first status=%08lx\n", status);
        ok(status == STATUS_NO_MEMORY, "injected allocation returned %08lx\n", status);
        ok(base == (void *)(ULONG_PTR)base_value, "failed allocation changed base to %p\n", base);
        ok(size == 0x9000, "failed allocation changed size to %Ix\n", size);
        if (status == STATUS_SUCCESS)
        {
            size = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
            return;
        }

        memset(&mbi, 0, sizeof(mbi));
        returned_size = VirtualQuery((void *)(ULONG_PTR)base_value, &mbi, sizeof(mbi));
        ok(returned_size == sizeof(mbi), "query failed allocation returned %Ix\n", returned_size);
        if (returned_size) ok(mbi.State == MEM_FREE, "failed allocation state %#lx\n", mbi.State);

        base = (void *)(ULONG_PTR)base_value;
        size = 0x9000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        trace("private_backing_failure case=map stage=retry status=%08lx\n", status);
        ok(status == STATUS_SUCCESS, "retry allocation returned %08lx\n", status);
        if (status) return;
        bytes = base;
        ok(bytes[0] == 0 && bytes[0x1000] == 0 && bytes[0x8000] == 0,
           "retried allocation was not zero-filled\n");
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "retry allocation release returned %08lx\n", status);
        memset(&mbi, 0, sizeof(mbi));
        returned_size = VirtualQuery((void *)(ULONG_PTR)base_value, &mbi, sizeof(mbi));
        ok(returned_size == sizeof(mbi), "query released retry allocation returned %Ix\n", returned_size);
        if (returned_size) ok(mbi.State == MEM_FREE, "released retry allocation state %#lx\n", mbi.State);
        return;
    }

    if (!strcmp(failure_case, "exec"))
    {
        static const BYTE code[] = { 0xb8, 42, 0, 0, 0, 0xc3 }; /* mov eax,42; ret */
        int (__cdecl *probe)(void);
        int result;

        size = 0x9000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        trace("private_backing_failure case=exec stage=first status=%08lx\n", status);
        ok(status == STATUS_ACCESS_DENIED, "injected executable allocation returned %08lx\n", status);
        ok(base == (void *)(ULONG_PTR)base_value, "failed executable allocation changed base to %p\n", base);
        ok(size == 0x9000, "failed executable allocation changed size to %Ix\n", size);
        if (status == STATUS_SUCCESS)
        {
            size = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
            return;
        }

        memset(&mbi, 0, sizeof(mbi));
        returned_size = VirtualQuery((void *)(ULONG_PTR)base_value, &mbi, sizeof(mbi));
        ok(returned_size == sizeof(mbi), "query failed executable allocation returned %Ix\n", returned_size);
        if (returned_size) ok(mbi.State == MEM_FREE, "failed executable allocation state %#lx\n", mbi.State);

        base = (void *)(ULONG_PTR)base_value;
        size = 0x9000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        trace("private_backing_failure case=exec stage=retry status=%08lx\n", status);
        ok(status == STATUS_SUCCESS, "executable allocation retry returned %08lx\n", status);
        if (status) return;
        memset(&mbi, 0, sizeof(mbi));
        status = NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation,
                                      &mbi, sizeof(mbi), &returned_size);
        ok(status == STATUS_SUCCESS, "query retried executable allocation returned %08lx\n", status);
        if (!status)
        {
            ok(mbi.State == MEM_COMMIT, "executable page state %#lx\n", mbi.State);
            ok(mbi.Type == MEM_PRIVATE, "executable page type %#lx\n", mbi.Type);
            ok(mbi.Protect == PAGE_EXECUTE_READWRITE, "executable page protection %#lx\n", mbi.Protect);
        }
        memcpy(base, code, sizeof(code));
        FlushInstructionCache(GetCurrentProcess(), base, sizeof(code));
        probe = (void *)base;
        result = probe();
        ok(result == 42, "executable backing probe returned %d\n", result);
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "executable allocation release returned %08lx\n", status);
        memset(&mbi, 0, sizeof(mbi));
        returned_size = VirtualQuery((void *)(ULONG_PTR)base_value, &mbi, sizeof(mbi));
        ok(returned_size == sizeof(mbi), "query released executable allocation returned %Ix\n", returned_size);
        if (returned_size) ok(mbi.State == MEM_FREE, "released executable allocation state %#lx\n", mbi.State);
        return;
    }

    if (strcmp(failure_case, "protect") && strcmp(failure_case, "decommit"))
    {
        ok(0, "unknown PROTON_VM_FAIL_CASE %s\n", failure_case);
        return;
    }

    size = 0x9000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "fixture allocation returned %08lx\n", status);
    if (status) return;
    bytes = base;

    if (!strcmp(failure_case, "protect"))
    {
        bytes[0x101] = 0x10;
        bytes[0x3101] = 0x30;
        bytes[0x6101] = 0x60;
        addr = (char *)base + 0x3000;
        size = 0x3000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        ok(status == STATUS_SUCCESS, "setup middle read-only segment returned %08lx\n", status);
        if (status) goto release_failure_fixture;
        ok(old_protect == PAGE_READWRITE, "setup old protection %#lx\n", old_protect);

        addr = base;
        size = 0x9000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        trace("private_backing_failure case=protect stage=first status=%08lx\n", status);
        ok(status == STATUS_ACCESS_DENIED, "injected protect returned %08lx\n", status);
        if (status == STATUS_ACCESS_DENIED)
        {
            static const ULONG offsets[] = { 0, 0x3000, 0x6000 };
            static const ULONG protections[] = { PAGE_READWRITE, PAGE_READONLY, PAGE_READWRITE };
            unsigned int i;
            for (i = 0; i < ARRAY_SIZE(offsets); i++)
            {
                memset(&mbi, 0, sizeof(mbi));
                status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + offsets[i],
                                              MemoryBasicInformation, &mbi, sizeof(mbi), &returned_size);
                ok(status == STATUS_SUCCESS, "query rollback segment %u returned %08lx\n", i, status);
                if (!status)
                {
                    ok(mbi.State == MEM_COMMIT, "rollback segment %u state %#lx\n", i, mbi.State);
                    ok(mbi.Type == MEM_PRIVATE, "rollback segment %u type %#lx\n", i, mbi.Type);
                    ok(mbi.Protect == protections[i], "rollback segment %u protection %#lx expected %#lx\n",
                       i, mbi.Protect, protections[i]);
                }
            }
            ok(bytes[0x101] == 0x10 && bytes[0x3101] == 0x30 && bytes[0x6101] == 0x60,
               "protect rollback changed fixture bytes\n");

            addr = base;
            size = 0x9000;
            status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
            trace("private_backing_failure case=protect stage=retry status=%08lx\n", status);
            ok(status == STATUS_SUCCESS, "protect retry returned %08lx\n", status);
            if (!status)
            {
                memset(&mbi, 0, sizeof(mbi));
                status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + 0x6000,
                                              MemoryBasicInformation, &mbi, sizeof(mbi), &returned_size);
                ok(status == STATUS_SUCCESS, "query retried protect returned %08lx\n", status);
                if (!status) ok(mbi.Protect == PAGE_READONLY, "retried protection %#lx\n", mbi.Protect);
                ok(bytes[0x101] == 0x10 && bytes[0x3101] == 0x30 && bytes[0x6101] == 0x60,
                   "protect retry changed fixture bytes\n");
            }
        }
    }
    else
    {
        bytes[0x101] = 0x10;
        bytes[0x1101] = 0x21;
        bytes[0x2101] = 0x32;
        addr = (char *)base + 0x1000;
        size = 0x1000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        ok(status == STATUS_SUCCESS, "setup decommit read-only page returned %08lx\n", status);
        if (status) goto release_failure_fixture;
        ok(old_protect == PAGE_READWRITE, "decommit setup old protection %#lx\n", old_protect);
        addr = (char *)base + 0x1000;
        size = 0x1000;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
        trace("private_backing_failure case=decommit stage=first status=%08lx\n", status);
        ok(status == STATUS_NOT_SUPPORTED, "injected decommit returned %08lx\n", status);
        if (status == STATUS_NOT_SUPPORTED)
        {
            memset(&mbi, 0, sizeof(mbi));
            status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + 0x1000,
                                          MemoryBasicInformation, &mbi, sizeof(mbi), &returned_size);
            ok(status == STATUS_SUCCESS, "query failed decommit returned %08lx\n", status);
            if (!status)
            {
                ok(mbi.State == MEM_COMMIT, "failed decommit page state %#lx\n", mbi.State);
                ok(mbi.Type == MEM_PRIVATE, "failed decommit page type %#lx\n", mbi.Type);
                ok(mbi.Protect == PAGE_READONLY, "failed decommit page protection %#lx\n", mbi.Protect);
            }
            ok(bytes[0x101] == 0x10 && bytes[0x1101] == 0x21 && bytes[0x2101] == 0x32,
               "failed decommit changed page contents\n");

            addr = (char *)base + 0x1000;
            size = 0x1000;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
            trace("private_backing_failure case=decommit stage=retry status=%08lx\n", status);
            ok(status == STATUS_SUCCESS, "decommit retry returned %08lx\n", status);
            if (!status)
            {
                status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + 0x1000,
                                              MemoryBasicInformation, &mbi, sizeof(mbi), &returned_size);
                ok(status == STATUS_SUCCESS, "query retried decommit returned %08lx\n", status);
                if (!status) ok(mbi.State == MEM_RESERVE, "retried decommit state %#lx\n", mbi.State);
                addr = (char *)base + 0x1000;
                size = 0x1000;
                status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
                ok(status == STATUS_SUCCESS, "decommit recommit returned %08lx\n", status);
                if (!status)
                {
                    ok(bytes[0x1101] == 0, "recommitted decommit page was not zero-filled\n");
                    ok(bytes[0x101] == 0x10 && bytes[0x2101] == 0x32,
                       "decommit retry changed neighboring data\n");
                }
            }
        }
    }

release_failure_fixture:
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "failure fixture release returned %08lx\n", status);
    memset(&mbi, 0, sizeof(mbi));
    returned_size = VirtualQuery((void *)(ULONG_PTR)base_value, &mbi, sizeof(mbi));
    ok(returned_size == sizeof(mbi), "query released failure fixture returned %Ix\n", returned_size);
    if (returned_size) ok(mbi.State == MEM_FREE, "released failure fixture state %#lx\n", mbi.State);
}

static void run_shared_private_backing_fatal(const char *failure_case, const char *base_string)
{
    void *base = (void *)(ULONG_PTR)strtoull(base_string, NULL, 0), *addr;
    SIZE_T size = 0x9000;
    NTSTATUS status;
    ULONG old_protect;

    trace("private_backing_failure case=fatal-%s stage=begin base=%p size=0x9000\n", failure_case, base);
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status)
    {
        trace("private_backing_failure case=fatal-%s stage=allocation_returned status=%08lx\n", failure_case, status);
        return;
    }
    if (!strcmp(failure_case, "protect"))
    {
        addr = (char *)base + 0x3000;
        size = 0x3000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        if (!status)
        {
            addr = base;
            size = 0x9000;
            status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        }
    }
    else
    {
        addr = (char *)base + 0x1000;
        size = 0x1000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        if (status) return;
        addr = (char *)base + 0x1000;
        size = 0x1000;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    }
    trace("private_backing_failure case=fatal-%s stage=operation_returned status=%08lx\n", failure_case, status);
}

static void test_NtProtectVirtualMemory(void)
{
    void *addr, *addr2;
    NTSTATUS status;
    SIZE_T size;
    DWORD old_prot;

    size = page_size * 16;
    addr = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    old_prot = 0;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_prot);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_READWRITE, "Unexpected old_prot %lx.\n", old_prot);

    status = NtProtectVirtualMemory(NULL, &addr, &size, PAGE_READONLY, &old_prot);
    ok(status == STATUS_INVALID_HANDLE, "Unexpected status %08lx.\n", status);

    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "Unexpected status %08lx.\n", status);

    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, 0, &old_prot);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "Unexpected status %08lx.\n", status);

    size = page_size * 8;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &old_prot);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_READONLY, "Unexpected old_prot %lx.\n", old_prot);
    addr = (char *)addr + page_size * 8;
    old_prot = 0;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_EXECUTE_READWRITE, &old_prot);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_READONLY, "Unexpected old_prot %lx.\n", old_prot);
    addr = (char *)addr - page_size * 8;
    size = page_size * 16;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_EXECUTE_READ, &old_prot);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_READWRITE, "Unexpected old_prot %lx.\n", old_prot);

    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    addr = NULL;
    size = page_size;
    old_prot = 0;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_prot);
    /* todo: STATUS_INVALID_PARAMETER in wine, STATUS_CONFLICTING_ADDRESSES in win64 */
    ok(status, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_NOACCESS || broken(old_prot) /* win7 */, "Unexpected old_prot %lx.\n", old_prot);

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    old_prot = 0;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_prot);
    ok(status == STATUS_NOT_COMMITTED, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_NOACCESS || broken(old_prot) /* win7 */, "Unexpected old_prot %lx.\n", old_prot);
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    addr2 = addr;
    addr = (char *)addr + 1;
    size = 1;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_prot);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(old_prot == PAGE_READWRITE, "Unexpected old_prot %lx.\n", old_prot);
    ok(size == page_size, "Unexpected size %p.\n",  (void *)size);
    ok(addr == addr2, "Got addr %p, addr2 %p.\n", addr, addr2);

    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
}

static void test_prefetch(void)
{
    NTSTATUS status;
    MEMORY_RANGE_ENTRY entries[2] = {{ 0 }};
    ULONG reservedarg = 0;
    char stackmem[] = "Test stack mem";
    static char testmem[] = "Test memory range data";

    if (!pNtSetInformationVirtualMemory)
    {
        skip("no NtSetInformationVirtualMemory in ntdll\n");
        return;
    }

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), -1, 1, entries, NULL, 32);
    ok( status == STATUS_INVALID_PARAMETER_2,
        "NtSetInformationVirtualMemory unexpected status on invalid info class (1): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), -1, 0, NULL, NULL, 0);
    ok( status == STATUS_INVALID_PARAMETER_2 || (is_wow64 && status == STATUS_INVALID_PARAMETER_3),
        "NtSetInformationVirtualMemory unexpected status on invalid info class (2): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), -1, 1, NULL, NULL, 32);
    ok( status == STATUS_INVALID_PARAMETER_2 || (is_wow64 && status == STATUS_ACCESS_VIOLATION),
        "NtSetInformationVirtualMemory unexpected status on invalid info class (3): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, NULL, 0 );
    ok( status == STATUS_INVALID_PARAMETER_5 ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on NULL info data (1): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, NULL, NULL, 0 );
    ok( status == STATUS_INVALID_PARAMETER_5 || (is_wow64 && status == STATUS_ACCESS_VIOLATION),
        "NtSetInformationVirtualMemory unexpected status on NULL info data (2): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             0, NULL, NULL, 0 );
    ok( status == STATUS_INVALID_PARAMETER_5 || (is_wow64 && status == STATUS_INVALID_PARAMETER_3),
        "NtSetInformationVirtualMemory unexpected status on NULL info data (3): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) * 2 );
    ok( status == STATUS_INVALID_PARAMETER_6,
        "NtSetInformationVirtualMemory unexpected status on extended info data (1): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             0, NULL, &reservedarg, sizeof(reservedarg) * 2 );
    ok( status == STATUS_INVALID_PARAMETER_6 || (is_wow64 && status == STATUS_INVALID_PARAMETER_3),
        "NtSetInformationVirtualMemory unexpected status on extended info data (2): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) / 2 );
    ok( status == STATUS_INVALID_PARAMETER_6,
        "NtSetInformationVirtualMemory unexpected status on shrunk info data (1): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             0, NULL, &reservedarg, sizeof(reservedarg) / 2 );
    ok( status == STATUS_INVALID_PARAMETER_6 || (is_wow64 && status == STATUS_INVALID_PARAMETER_3),
        "NtSetInformationVirtualMemory unexpected status on shrunk info data (2): %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             0, NULL, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_INVALID_PARAMETER_3,
        "NtSetInformationVirtualMemory unexpected status on 0 entries: %08lx\n", status);

    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, NULL, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_ACCESS_VIOLATION,
        "NtSetInformationVirtualMemory unexpected status on NULL entries: %08lx\n", status);

    entries[0].VirtualAddress = NULL;
    entries[0].NumberOfBytes = 0;
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_INVALID_PARAMETER_4 ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 1 empty entry: %08lx\n", status);

    entries[0].VirtualAddress = NULL;
    entries[0].NumberOfBytes = page_size;
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_SUCCESS ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 1 NULL address entry: %08lx\n", status);

    entries[0].VirtualAddress = (void *)((ULONG_PTR)testmem & -(ULONG_PTR)page_size);
    entries[0].NumberOfBytes = page_size;
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_SUCCESS ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 1 page-aligned entry: %08lx\n", status);

    entries[0].VirtualAddress = testmem;
    entries[0].NumberOfBytes = sizeof(testmem);
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_SUCCESS ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 1 entry: %08lx\n", status);

    entries[0].VirtualAddress = NULL;
    entries[0].NumberOfBytes = page_size;
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             1, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_SUCCESS ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 1 unmapped entry: %08lx\n", status);

    entries[0].VirtualAddress = (void *)((ULONG_PTR)testmem & -(ULONG_PTR)page_size);
    entries[0].NumberOfBytes = page_size;
    entries[1].VirtualAddress = (void *)((ULONG_PTR)stackmem & -(ULONG_PTR)page_size);
    entries[1].NumberOfBytes = page_size;
    status = pNtSetInformationVirtualMemory( NtCurrentProcess(), VmPrefetchInformation,
                                             2, entries, &reservedarg, sizeof(reservedarg) );
    ok( status == STATUS_SUCCESS ||
        broken( is_wow64 && status == STATUS_INVALID_PARAMETER_6 ) /* win10 1507 */,
        "NtSetInformationVirtualMemory unexpected status on 2 page-aligned entries: %08lx\n", status);
}

static void test_query_region_information(void)
{
    MEMORY_REGION_INFORMATION info;
    LARGE_INTEGER offset;
    SIZE_T len, size;
    NTSTATUS status;
    HANDLE mapping;
    void *ptr, *addr;
    ULONG old;

    size = 0x10000;
    ptr = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

#ifdef _WIN64
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info,
            FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info,
            FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info,
            FIELD_OFFSET(MEMORY_REGION_INFORMATION, RegionSize), &len);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "Unexpected status %08lx.\n", status);
#endif

    len = 0;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READWRITE, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == size, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(!info.CommitSize, "Unexpected commit size %#Ix.\n", info.CommitSize);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    /* Committed size */
    size = 0x10000;
    ptr = NULL;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    len = 0;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READWRITE, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == size, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(info.CommitSize == size, "Unexpected commit size %#Ix.\n", info.CommitSize);

    len = 0;
    addr = (char *)ptr + 0x1000;
    size = 0x1000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_NOACCESS, &old );
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READWRITE, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 0x10000, "Unexpected region size %#Ix.\n", info.RegionSize);
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(info.CommitSize == 0x10000, "Unexpected commit size %#Ix.\n", info.CommitSize);

    len = 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)ptr + 0x1000, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READWRITE, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 0x10000, "Unexpected region size %#Ix.\n", info.RegionSize);
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(info.CommitSize == 0x10000, "Unexpected commit size %#Ix.\n", info.CommitSize);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    memset(&info, 0xcc, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS, "Unexpected status %08lx.\n", status);
    ok(info.AllocationBase == (void *)(ULONG_PTR)0xcccccccccccccccc, "got %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == 0xcccccccc, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(info.RegionType == 0xcccccccc, "got %#lx.\n", info.RegionType);

    /* Pagefile mapping */
    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 4096, NULL);
    ok(mapping != 0, "CreateFileMapping failed\n");

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    len = 0;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READONLY, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 4096, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(!info.CommitSize, "Unexpected commit size %#Ix.\n", info.CommitSize);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_WRITECOPY);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    len = 0;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_WRITECOPY, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 4096, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(info.CommitSize == 4096, "Unexpected commit size %#Ix.\n", info.CommitSize);

    len = 0;
    *(volatile int *)ptr = 1;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_WRITECOPY, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 4096, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(info.CommitSize == 4096, "Unexpected commit size %#Ix.\n", info.CommitSize);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    *(volatile int *)ptr = 1;

    len = 0;
    memset(&info, 0x11, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryRegionInformation, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);
    ok(len == sizeof(info) ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId)) /* <= Win10-1909 */ ||
       broken(len >= offsetof(MEMORY_REGION_INFORMATION, CommitSize)) /* Win7 */,
       "Unexpected len %Ix\n", len);
    ok(info.AllocationBase == ptr, "Unexpected base %p.\n", info.AllocationBase);
    ok(info.AllocationProtect == PAGE_READWRITE, "Unexpected protection %lu.\n", info.AllocationProtect);
    ok(!info.Private, "Unexpected flag %d.\n", info.Private);
    ok(!info.MappedDataFile, "Unexpected flag %d.\n", info.MappedDataFile);
    ok(!info.MappedImage, "Unexpected flag %d.\n", info.MappedImage);
    ok(!info.MappedPageFile, "Unexpected flag %d.\n", info.MappedPageFile);
    ok(!info.MappedPhysical, "Unexpected flag %d.\n", info.MappedPhysical);
    ok(!info.DirectMapped, "Unexpected flag %d.\n", info.DirectMapped);
    ok(info.RegionSize == 4096, "Unexpected region size.\n");
    if (len >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
        ok(!info.CommitSize, "Unexpected commit size %#Ix.\n", info.CommitSize);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "Unexpected status %08lx.\n", status);

    NtClose(mapping);
}

static void test_query_image_information(void)
{
    MEMORY_IMAGE_INFORMATION info;
    IMAGE_NT_HEADERS *nt;
    LARGE_INTEGER offset;
    SIZE_T len, size;
    NTSTATUS status;
    HANDLE mapping, file;
    void *ptr;

    /* virtual allocation */

    size = 0x8000;
    ptr = NULL;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );

    len = 0xdead;
    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), ptr, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    if (status == STATUS_INVALID_INFO_CLASS)
    {
        win_skip( "MemoryImageInformation not supported\n" );
        NtUnmapViewOfSection( NtCurrentProcess(), ptr );
        return;
    }
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( len == sizeof(info), "wrong len %Ix\n", len );
    ok( !info.ImageBase, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( !info.SizeOfImage, "wrong size %Ix/%Ix\n", info.SizeOfImage, size );
    ok( !info.ImageFlags, "wrong flags %lx\n", info.ImageFlags );

    len = 0xdead;
    status = NtQueryVirtualMemory( NtCurrentProcess(), ptr, MemoryImageInformation,
                                   &info, sizeof(info) + 2, &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( len == sizeof(info), "wrong len %Ix\n", len );

    len = 0xdead;
    status = NtQueryVirtualMemory( NtCurrentProcess(), ptr, MemoryImageInformation,
                                   &info, sizeof(info) - 1, &len );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "Unexpected status %08lx\n", status );
    ok( len == 0xdead, "wrong len %Ix\n", len );

    len = 0xdead;
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + size, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_INVALID_ADDRESS, "Unexpected status %08lx\n", status );
    ok( len == 0xdead || broken(len == sizeof(info)), "wrong len %Ix\n", len );

    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( !info.ImageBase, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( !info.SizeOfImage, "wrong size %Ix/%Ix\n", info.SizeOfImage, size );
    ok( !info.ImageFlags, "wrong flags %lx\n", info.ImageFlags );

    size = 0;
    NtFreeVirtualMemory( NtCurrentProcess(), &ptr, &size, MEM_RELEASE );

    /* mapped dll */

    ptr = GetModuleHandleA( "ntdll.dll" );
    nt = RtlImageNtHeader( ptr );
    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( info.ImageBase == ptr, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( info.SizeOfImage == nt->OptionalHeader.SizeOfImage, "wrong size %Ix/%x\n",
        info.SizeOfImage, (UINT)nt->OptionalHeader.SizeOfImage );
    ok( !info.ImagePartialMap, "wrong partial map\n" );
    ok( !info.ImageNotExecutable, "wrong not executable\n" );
    ok( info.ImageSigningLevel == 0 || info.ImageSigningLevel == 12,
        "wrong signing level %u\n", info.ImageSigningLevel );

    /* image mapping */

    file = CreateFileA( "c:\\windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, 0 );
    mapping = CreateFileMappingA( file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection( mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY );
    ok( status == STATUS_IMAGE_NOT_AT_BASE, "Unexpected status %08lx\n", status );
    NtClose( mapping );

    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( info.ImageBase == ptr, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( info.SizeOfImage == size, "wrong size %Ix/%Ix\n", info.SizeOfImage, size );
    ok( !info.ImagePartialMap, "wrong partial map\n" );
    ok( !info.ImageNotExecutable, "wrong not executable\n" );
    ok( info.ImageSigningLevel == 0 || info.ImageSigningLevel == 12,
        "wrong signing level %u\n", info.ImageSigningLevel );

    NtUnmapViewOfSection( NtCurrentProcess(), ptr );

    /* partial image mapping */

    file = CreateFileA( "c:\\windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, 0 );
    mapping = CreateFileMappingA( file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0x4000, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection( mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY );
    ok( status == STATUS_IMAGE_NOT_AT_BASE, "Unexpected status %08lx\n", status );
    todo_wine
    ok( size == 0x4000, "wrong size %Ix\n", size );
    NtClose( mapping );

    nt = RtlImageNtHeader( ptr );
    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( info.ImageBase == ptr, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( info.SizeOfImage == nt->OptionalHeader.SizeOfImage, "wrong size %Ix/%x\n",
        info.SizeOfImage, (UINT)nt->OptionalHeader.SizeOfImage );
    todo_wine
    ok( info.ImagePartialMap, "wrong partial map\n" );
    ok( !info.ImageNotExecutable, "wrong not executable\n" );
    ok( info.ImageSigningLevel == 0 || info.ImageSigningLevel == 12,
        "wrong signing level %u\n", info.ImageSigningLevel );

    NtUnmapViewOfSection( NtCurrentProcess(), ptr );

    file = CreateFileA( "c:\\windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, 0 );
    mapping = CreateFileMappingA( file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    ptr = NULL;
    size = 0x5000;
    offset.QuadPart = 0;
    status = NtMapViewOfSection( mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY );
    ok( status == STATUS_IMAGE_NOT_AT_BASE, "Unexpected status %08lx\n", status );
    todo_wine
    ok( size == 0x5000, "wrong size %Ix\n", size );
    NtClose( mapping );

    nt = RtlImageNtHeader( ptr );
    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( info.ImageBase == ptr, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( info.SizeOfImage == nt->OptionalHeader.SizeOfImage, "wrong size %Ix/%x\n",
        info.SizeOfImage, (UINT)nt->OptionalHeader.SizeOfImage );
    todo_wine
    ok( info.ImagePartialMap, "wrong partial map\n" );
    ok( !info.ImageNotExecutable, "wrong not executable\n" );
    ok( info.ImageSigningLevel == 0 || info.ImageSigningLevel == 12,
        "wrong signing level %u\n", info.ImageSigningLevel );

    NtUnmapViewOfSection( NtCurrentProcess(), ptr );

    /* non-image mapping */

    mapping = CreateFileMappingA( file, NULL, PAGE_READONLY, 0, 0x10000, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection( mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    NtClose( mapping );

    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( !info.ImageBase, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( !info.SizeOfImage, "wrong size %Ix/%Ix\n", info.SizeOfImage, size );
    ok( !info.ImageFlags, "wrong flags %lx\n", info.ImageFlags );

    NtUnmapViewOfSection( NtCurrentProcess(), ptr );

    /* pagefile mapping */

    mapping = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL );
    ok( mapping != 0, "CreateFileMapping failed\n" );

    ptr = NULL;
    size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection( mapping, NtCurrentProcess(), &ptr, 0, 0, &offset, &size, 1, 0, PAGE_READONLY );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    NtClose( mapping );

    memset( &info, 0xcc, sizeof(info) );
    status = NtQueryVirtualMemory( NtCurrentProcess(), (char *)ptr + 0x1234, MemoryImageInformation,
                                   &info, sizeof(info), &len );
    ok( status == STATUS_SUCCESS, "Unexpected status %08lx\n", status );
    ok( !info.ImageBase, "wrong image base %p/%p\n", info.ImageBase, ptr );
    ok( !info.SizeOfImage, "wrong size %Ix/%Ix\n", info.SizeOfImage, size );
    ok( !info.ImageFlags, "wrong flags %lx\n", info.ImageFlags );

    NtUnmapViewOfSection( NtCurrentProcess(), ptr );
    NtClose( file );
}

static int *write_addr;
static int got_exception;

static LONG CALLBACK exec_write_handler( EXCEPTION_POINTERS *ptrs )
{
    MANAGE_WRITES_TO_EXECUTABLE_MEMORY mem = { .Version = 2, .ThreadAllowWrites = 1 };
    EXCEPTION_RECORD *rec = ptrs->ExceptionRecord;
    NTSTATUS status;

    got_exception++;
    ok( rec->ExceptionCode == STATUS_IN_PAGE_ERROR, "wrong exception %lx\n", rec->ExceptionCode );
    ok( rec->NumberParameters == 3, "wrong params %lx\n", rec->NumberParameters );
    ok( rec->ExceptionInformation[0] == 1, "not write access %Ix\n", rec->ExceptionInformation[0] );
    ok( (int *)rec->ExceptionInformation[1] == write_addr,
        "wrong address %p / %p\n", (void *)rec->ExceptionInformation[1], write_addr );
    ok( rec->ExceptionInformation[2] == STATUS_EXECUTABLE_MEMORY_WRITE, "wrong status %Ix\n",
        rec->ExceptionInformation[2] );

    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) );
    ok( !status, "NtSetInformationThread failed %lx\n", status );
    *write_addr = 0;  /* make the page dirty to prevent further exceptions */
    mem.ThreadAllowWrites = 0;
    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) );
    ok( !status, "NtSetInformationThread failed %lx\n", status );
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void test_exec_memory_writes(void)
{
    NTSTATUS status;
    void *ptr, *handler;
    MANAGE_WRITES_TO_EXECUTABLE_MEMORY mem = { .Version = 2 };
    MEMORY_RANGE_ENTRY range;
    ULONG flag, len, granularity;
    ULONG_PTR count;
    void *addresses[4];
    DWORD old_prot;
    WCHAR path[MAX_PATH];
    HANDLE file;
    IO_STATUS_BLOCK io;

    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) );
#ifdef __aarch64__
    ok( !status, "NtSetInformationProcess failed %lx\n", status );
#else
    if (!status)
    {
        SYSTEM_CPU_INFORMATION info;
        ULONG len;

        RtlGetNativeSystemInformation( SystemCpuInformation, &info, sizeof(info), &len );
        ok (info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64, "succeeded on non-ARM64\n" );
        mem.ProcessEnableWriteExceptions = 1;
        NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                 &mem, sizeof(mem) );
        skip( "skipping test on ARM64EC\n" );
        return;
    }
    ok( status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_SUPPORTED,
        "NtSetInformationProcess failed %lx\n", status );
#endif
    if (status) return;
    handler = RtlAddVectoredExceptionHandler( TRUE, exec_write_handler );

    /* test anon mapping */

    ptr = VirtualAlloc( NULL, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    write_addr = (int *)ptr + 3;

    mem.ProcessEnableWriteExceptions = 1;
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) );
    ok( !status, "NtSetInformationProcess failed %lx\n", status );

    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 0, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    VirtualProtect( ptr, page_size, PAGE_EXECUTE_READWRITE, &old_prot );
    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    /* no longer failing on dirty page */
    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 0, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    /* setting permissions resets protection */
    VirtualProtect( ptr, page_size, PAGE_EXECUTE_READWRITE, &old_prot );
    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    /* clearing dirty state also resets protection */
    range.VirtualAddress = ptr;
    range.NumberOfBytes = 1;
    flag = 0;
    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( !status, "NtSetInformationVirtualMemory failed %lx\n", status );

    /* making page dirty is not allowed */
    flag = 1;
    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( status == STATUS_INVALID_PARAMETER_5, "NtSetInformationVirtualMemory failed %lx\n", status );

    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    GetModuleFileNameW( 0, path, MAX_PATH );
    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0 );
    ok( file != INVALID_HANDLE_VALUE, "can't open %s: %lu\n", debugstr_w(path), GetLastError() );
    /* reading into protected page crashes on Windows */
    if (0) VirtualProtect( ptr, page_size, PAGE_EXECUTE_READWRITE, &old_prot );
    status = NtReadFile( file, 0, NULL, NULL, &io, write_addr, 8, NULL, NULL );
    ok( !status, "NtReadFile failed %lx\n", status );
    CloseHandle( file );

    VirtualFree( ptr, 0, MEM_RELEASE );

    /* test PE mapping */

    ptr = GetModuleHandleA( NULL );
    write_addr = (int *)ptr + 3;
    VirtualProtect( ptr, page_size, PAGE_EXECUTE_WRITECOPY, &old_prot );

    got_exception = 0;
    *write_addr = 0;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    got_exception = 0;
    *write_addr = 0;
    ok( got_exception == 0, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    VirtualProtect( ptr, page_size, PAGE_EXECUTE_WRITECOPY, &old_prot );
    got_exception = 0;
    *write_addr = 0;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    range.VirtualAddress = write_addr;
    range.NumberOfBytes = 1;
    flag = 0;
    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( !status, "NtSetInformationVirtualMemory failed %lx\n", status );
    got_exception = 0;
    *write_addr = 0;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    /* test interactions with write watches */

    ptr = VirtualAlloc( NULL, page_size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE );
    write_addr = (int *)ptr + 3;

    VirtualProtect( ptr, page_size, PAGE_EXECUTE_READWRITE, &old_prot );
    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    count = ARRAY_SIZE(addresses);
    status = NtGetWriteWatch( GetCurrentProcess(), 0, ptr, page_size, addresses, &count, &granularity );
    ok( !status, "NtGetWriteWatch failed %lx\n", status );
    ok( count == 1, "got count %Iu\n", count );
    ok( addresses[0] == ptr, "wrong ptr %p / %p\n", addresses[0], ptr );

    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 0, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    count = ARRAY_SIZE(addresses);
    status = NtGetWriteWatch( GetCurrentProcess(), WRITE_WATCH_FLAG_RESET,
                              ptr, page_size, addresses, &count, &granularity );
    ok( !status, "NtGetWriteWatch failed %lx\n", status );
    ok( count == 1, "got count %Iu\n", count );
    ok( addresses[0] == ptr, "wrong ptr %p / %p\n", addresses[0], ptr );

    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    count = ARRAY_SIZE(addresses);
    status = NtGetWriteWatch( GetCurrentProcess(), 0, ptr, page_size, addresses, &count, &granularity );
    ok( !status, "NtGetWriteWatch failed %lx\n", status );
    ok( count == 1, "got count %Iu\n", count );
    ok( addresses[0] == ptr, "wrong ptr %p / %p\n", addresses[0], ptr );

    range.VirtualAddress = ptr;
    range.NumberOfBytes = 1;
    flag = 0;
    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( !status, "NtSetInformationVirtualMemory failed %lx\n", status );

    count = ARRAY_SIZE(addresses);
    status = NtGetWriteWatch( GetCurrentProcess(), 0, ptr, page_size, addresses, &count, &granularity );
    ok( !status, "NtGetWriteWatch failed %lx\n", status );
    ok( count == 0, "got count %Iu\n", count );

    got_exception = 0;
    *write_addr = 0x123456;
    ok( got_exception == 1, "wrong number of exceptions %u\n", got_exception );
    write_addr++;

    /* test some invalid calls */

    VirtualFree( ptr, 0, MEM_RELEASE );
    flag = 0;
    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( status == STATUS_MEMORY_NOT_ALLOCATED, "NtSetInformationVirtualMemory failed %lx\n", status );

    mem.ProcessEnableWriteExceptions = 0;
    NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                             &mem, sizeof(mem) );

    status = pNtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                             1, &range, &flag, sizeof(flag) );
    ok( status == STATUS_NOT_SUPPORTED, "NtSetInformationVirtualMemory failed %lx\n", status );
    status = NtQueryInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                        &mem, sizeof(mem), &len );
    ok( status == STATUS_INVALID_INFO_CLASS, "NtQueryInformationProcess failed %lx\n", status );

    mem.ProcessEnableWriteExceptions = 1;
    mem.ThreadAllowWrites = 1;
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) );
    ok( status == STATUS_INVALID_PARAMETER, "NtSetInformationProcess failed %lx\n", status );
    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) );
    ok( status == STATUS_INVALID_PARAMETER, "NtSetInformationThread failed %lx\n", status );
    mem.ProcessEnableWriteExceptions = 0;
    mem.ThreadAllowWrites = 0;
    mem.Version = 3;
    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) );
    ok( status == STATUS_REVISION_MISMATCH, "NtSetInformationThread failed %lx\n", status );
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) );
    ok( status == STATUS_REVISION_MISMATCH, "NtSetInformationProcess failed %lx\n", status );
    mem.Version = 2;
    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) - 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "NtSetInformationThread failed %lx\n", status );
    status = NtSetInformationThread( GetCurrentThread(), ThreadManageWritesToExecutableMemory,
                                     &mem, sizeof(mem) + 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "NtSetInformationThread failed %lx\n", status );
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) - 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "NtSetInformationProcess failed %lx\n", status );
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessManageWritesToExecutableMemory,
                                      &mem, sizeof(mem) + 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "NtSetInformationProcess failed %lx\n", status );

    RtlRemoveVectoredExceptionHandler( handler );
}

START_TEST(virtual)
{
    HMODULE mod;

    int argc;
    char **argv;
    argc = winetest_get_mainargs(&argv);

    if (argc >= 3)
    {
        if (!strcmp(argv[2], "managed-layout") || !strcmp(argv[2], "managed-layout-child"))
        {
            test_managed_target_layout( !strcmp(argv[2], "managed-layout-child") );
            return;
        }
        if (!strcmp(argv[2], "sleep"))
        {
            Sleep(5000); /* spawned process runs for at most 5 seconds */
            return;
        }
        if (!strcmp(argv[2], "vm-backing-child") && argc >= 5)
        {
            HANDLE ready_event = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[3]);
            HANDLE release_event = OpenEventA(SYNCHRONIZE, FALSE, argv[4]);

            if (!ready_event || !release_event) ExitProcess(2);
            if (!SetEvent(ready_event)) ExitProcess(3);
            if (WaitForSingleObject(release_event, 30000) != WAIT_OBJECT_0) ExitProcess(4);
            CloseHandle(ready_event);
            CloseHandle(release_event);
            return;
        }
        if (!strcmp(argv[2], "vm-backing-fatal") && argc >= 5)
        {
            if (strcmp(argv[3], "protect") && strcmp(argv[3], "decommit")) ExitProcess(5);
            run_shared_private_backing_fatal(argv[3], argv[4]);
            return;
        }
        return;
    }

    mod = GetModuleHandleA("kernel32.dll");
    pIsWow64Process = (void *)GetProcAddress(mod, "IsWow64Process");
    pGetEnabledXStateFeatures = (void *)GetProcAddress(mod, "GetEnabledXStateFeatures");
    mod = GetModuleHandleA("ntdll.dll");
    pRtlCreateUserStack = (void *)GetProcAddress(mod, "RtlCreateUserStack");
    pRtlCreateUserThread = (void *)GetProcAddress(mod, "RtlCreateUserThread");
    pRtlFreeUserStack = (void *)GetProcAddress(mod, "RtlFreeUserStack");
    pRtlFindExportedRoutineByName = (void *)GetProcAddress(mod, "RtlFindExportedRoutineByName");
    pRtlGetEnabledExtendedFeatures = (void *)GetProcAddress(mod, "RtlGetEnabledExtendedFeatures");
    pRtlGetNativeSystemInformation = (void *)GetProcAddress(mod, "RtlGetNativeSystemInformation");
    pRtlIsEcCode = (void *)GetProcAddress(mod, "RtlIsEcCode");
    pNtAllocateVirtualMemoryEx = (void *)GetProcAddress(mod, "NtAllocateVirtualMemoryEx");
    pNtMapViewOfSectionEx = (void *)GetProcAddress(mod, "NtMapViewOfSectionEx");
    pNtSetInformationVirtualMemory = (void *)GetProcAddress(mod, "NtSetInformationVirtualMemory");

    NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL);
    trace("system page size %#lx\n", sbi.PageSize);
    page_size = sbi.PageSize;
    if (!pIsWow64Process || !pIsWow64Process(NtCurrentProcess(), &is_wow64)) is_wow64 = FALSE;

    test_NtAllocateVirtualMemory();
    test_NtAllocateVirtualMemoryEx();
    test_NtAllocateVirtualMemoryEx_address_requirements();
    test_NtFreeVirtualMemory();
    test_shared_private_backing_lifecycle();
    test_private_mapping_protection_lifetime();
    test_shared_private_backing_child();
    test_shared_private_backing_failure();
    test_NtProtectVirtualMemory();
    test_RtlCreateUserStack();
    test_NtMapViewOfSection();
    test_NtMapViewOfSectionEx();
    test_prefetch();
    test_user_shared_data();
    test_syscalls();
    test_invalid_syscalls();
    test_syscall_numbers();
    test_query_region_information();
    test_query_image_information();
    test_exec_memory_writes();
}
