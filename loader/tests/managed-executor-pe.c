/*
 * Benign standalone AMD64 PE fixture for managed executor host-RTL boot.
 * Build with the configured Wine winegcc, -m64 -mconsole -Wl,--large-address-aware,
 * -D__WINESRC__ -I/src/include, and -lntdll -lkernel32. This is not a driver.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "rtlsupportapi.h"
#include "ddk/wdm.h"

#if (!defined(__x86_64__) && !defined(_M_X64)) || !defined(_WIN32) || !defined(_WIN64) || \
    defined(__ELF__) || defined(__APPLE__) || defined(__arm64ec__) || \
    defined(_M_ARM64EC) || defined(__arm64ec_x64__)
#error This fixture requires an AMD64 PE build with real table unwind metadata.
#endif

/* Direct winegcc compilation does not supply the Wine Makefile's PE marker.
 * Select PE assembly directives only after checking the compiler target. */
#ifndef __WINE_PE_BUILD
#define __WINE_PE_BUILD
#endif
#include "wine/asm.h"
#include "wine/managed_layout.h"

C_ASSERT( sizeof(void *) == 8 );

static volatile LONG checks, failures;
static volatile LONG leaf_search, root_search, leaf_cleanup, root_cleanup, landed;
static volatile LONG leaf_cleanup_success, root_cleanup_success;
static void *fault_page;
static void * volatile leaf_resource;
static void * volatile root_resource;
static PEB *main_peb;
static HANDLE observation_ready, observation_release;
/* Keep the benign image larger than one allocation-granularity unit so the
 * SEC_IMAGE end-boundary case cannot pass merely because the image is tiny. */
static volatile BYTE image_boundary_padding[0x20000];
volatile LONG executor_instrumentation_calls, executor_instrumentation_replacement_calls;
void * volatile executor_instrumentation_return, * volatile executor_instrumentation_replacement_return;

static void check( int condition, const char *description )
{
    InterlockedIncrement( &checks );
    if (!condition)
    {
        fprintf( stderr, "managed-executor-pe: FAIL: %s\n", description );
        InterlockedIncrement( &failures );
    }
}

static int ordinary_host( const volatile void *address )
{
    return (ULONG_PTR)address >= WINE_MANAGED_HOST_ALLOC_START &&
           (ULONG_PTR)address < WINE_MANAGED_HOST_END;
}

static int native_address( const void *address )
{
    return (ULONG_PTR)address >= WINE_MANAGED_HOST_END;
}

static void pointer_trace( const char *name, const void *address )
{
    printf( "managed-executor-pe: pointer %s=%p\n", name, address );
}

static void require_join( HANDLE thread, DWORD timeout, const char *description )
{
    DWORD wait = WaitForSingleObject( thread, timeout );

    check( wait == WAIT_OBJECT_0, description );
    /* Closing a live worker's dependencies after a failed join is unsafe.
     * This fixture owns the process, so fail-stop leaves OS process teardown
     * responsible for every still-live thread and handle. */
    if (wait != WAIT_OBJECT_0)
    {
        fprintf( stderr, "managed-executor-pe: fail-stop after failed worker join\n" );
        ExitProcess( 1 );
    }
}

/* Both frames have their own genuine PE unwind entries. The faulting leaf
 * continues the initial search; the root starts an actual targeted unwind.
 * Each frame owns one resource prepared before entry: the leaf owns a real
 * heap allocation and the root owns a real event handle. Ownership transfers
 * to these frames when executor_fault_root is called; only their respective
 * unwind handlers consume it. No handler is invoked directly by the fixture.
 * Keep the call return PC before a meaningful
 * instruction, rather than at an epilogue which virtual unwind may skip. */
void WINAPI executor_fault_leaf( void *address );
ULONG_PTR WINAPI executor_fault_root( void *address );
extern char executor_fault_landing;

EXCEPTION_DISPOSITION WINAPI executor_leaf_handler( EXCEPTION_RECORD *record, void *frame,
                                                    CONTEXT *context, DISPATCHER_CONTEXT *dispatcher )
{
    if (record->ExceptionFlags & EXCEPTION_UNWINDING)
    {
        void *resource = InterlockedExchangePointer( &leaf_resource, NULL );
        if (resource && HeapFree( GetProcessHeap(), 0, resource ))
            InterlockedIncrement( &leaf_cleanup_success );
        InterlockedIncrement( &leaf_cleanup );
    }
    else if (record->ExceptionCode == STATUS_ACCESS_VIOLATION && record->NumberParameters >= 2 &&
             record->ExceptionInformation[0] == 0 &&
             record->ExceptionInformation[1] == (ULONG_PTR)fault_page)
        InterlockedIncrement( &leaf_search );
    return ExceptionContinueSearch;
}

EXCEPTION_DISPOSITION WINAPI executor_root_handler( EXCEPTION_RECORD *record, void *frame,
                                                    CONTEXT *context, DISPATCHER_CONTEXT *dispatcher )
{
    CONTEXT unwind_context;

    if (record->ExceptionFlags & EXCEPTION_UNWINDING)
    {
        if (record->ExceptionFlags & EXCEPTION_TARGET_UNWIND)
        {
            HANDLE resource = InterlockedExchangePointer( &root_resource, NULL );
            if (resource && !NtClose( resource ))
                InterlockedIncrement( &root_cleanup_success );
            InterlockedIncrement( &root_cleanup );
        }
        return ExceptionContinueSearch;
    }
    if (record->ExceptionCode != STATUS_ACCESS_VIOLATION || record->NumberParameters < 2 ||
        record->ExceptionInformation[0] != 0 ||
        record->ExceptionInformation[1] != (ULONG_PTR)fault_page)
        return ExceptionContinueSearch;
    InterlockedIncrement( &root_search );
    memset( &unwind_context, 0, sizeof(unwind_context) );
    RtlUnwindEx( frame, &executor_fault_landing, record, (void *)0x51a7,
                 &unwind_context, NULL );
    check( 0, "RtlUnwindEx unexpectedly returned to the search handler" );
    return ExceptionContinueSearch;
}

void WINAPI executor_mark_landing(void)
{
    InterlockedIncrement( &landed );
}

__ASM_GLOBAL_FUNC( executor_fault_leaf,
    "subq $40,%rsp\n\t"
    ".seh_stackalloc 40\n\t"
    ".seh_endprologue\n\t"
    "movzbl (%rcx),%eax\n\t"
    "xorl %eax,%eax\n\t"
    "addq $40,%rsp\n\t"
    "ret\n\t"
    ".seh_handler executor_leaf_handler,@except,@unwind\n\t" );

__ASM_GLOBAL_FUNC( executor_fault_root,
    "subq $40,%rsp\n\t"
    ".seh_stackalloc 40\n\t"
    ".seh_endprologue\n\t"
    "call executor_fault_leaf\n\t"
    "movl $0xbad,%eax\n\t"
    "addq $40,%rsp\n\t"
    "ret\n\t"
    ".globl executor_fault_landing\n"
    "executor_fault_landing:\n\t"
    "movq %rax,32(%rsp)\n\t"
    "call executor_mark_landing\n\t"
    "movq 32(%rsp),%rax\n\t"
    "addq $40,%rsp\n\t"
    "ret\n\t"
    ".seh_handler executor_root_handler,@except,@unwind\n\t" );

/* This is the existing AMD64 instrumentation-return ABI, not a WINAPI callback:
 * retain the syscall result and all GPRs, record the return target, jump to R10.
 * Neither callback calls an API or recursively enters the syscall dispatcher. */
void executor_instrumentation_callback(void);
void executor_instrumentation_replacement_callback(void);
__ASM_GLOBAL_FUNC( executor_instrumentation_callback,
    ".seh_endprologue\n\t"
    "lock incl executor_instrumentation_calls(%rip)\n\t"
    "movq %r10,executor_instrumentation_return(%rip)\n\t"
    "jmp *%r10\n\t" );
__ASM_GLOBAL_FUNC( executor_instrumentation_replacement_callback,
    ".seh_endprologue\n\t"
    "lock incl executor_instrumentation_replacement_calls(%rip)\n\t"
    "movq %r10,executor_instrumentation_replacement_return(%rip)\n\t"
    "jmp *%r10\n\t" );

static void inspect_thread( const char *prefix )
{
    TEB *teb = NtCurrentTeb();
    volatile BYTE stack_byte = 0x75;

    printf( "managed-executor-pe: thread %s tid=%lu teb=%p stack=%p limit=%p base=%p\n",
            prefix, GetCurrentThreadId(), teb, &stack_byte,
            teb->Tib.StackLimit, teb->Tib.StackBase );
    check( ordinary_host( teb ), "TEB lies in the ordinary host domain" );
    check( ordinary_host( &stack_byte ), "live PE stack lies in the ordinary host domain" );
    check( ordinary_host( teb->Tib.StackLimit ) &&
           (ULONG_PTR)teb->Tib.StackBase <= WINE_MANAGED_HOST_END &&
           (ULONG_PTR)&stack_byte >= (ULONG_PTR)teb->Tib.StackLimit &&
           (ULONG_PTR)&stack_byte < (ULONG_PTR)teb->Tib.StackBase,
           "TEB bounds contain the live PE stack" );
    check( teb->Peb == main_peb, "all physical threads retain the same real PEB" );
}

static DWORD WINAPI worker_thread( void *arg )
{
    LARGE_INTEGER counter;

    inspect_thread( "worker" );
    check( !NtQueryPerformanceCounter( &counter, NULL ), "worker syscall returns through host RTL" );
    if (observation_ready && observation_release)
    {
        check( SetEvent( observation_ready ), "observation worker signals readiness" );
        check( WaitForSingleObject( observation_release, 35000 ) == WAIT_OBJECT_0,
               "observation worker resumes through the physical host" );
    }
    return 0x75;
}

static void test_thread(void)
{
    DWORD exit_code = 0;
    HANDLE thread = CreateThread( NULL, 0, worker_thread, NULL, 0, NULL );

    check( !!thread, "real PE thread starts" );
    if (!thread) return;
    require_join( thread, 10000, "real PE thread terminates" );
    check( GetExitCodeThread( thread, &exit_code ) && exit_code == 0x75,
           "thread return survives native syscall and thread teardown" );
    check( CloseHandle( thread ), "thread handle closes" );
}

static void test_runtime(void)
{
    TEB *teb = NtCurrentTeb();
    PEB *peb = teb->Peb;
    SYSTEM_BASIC_INFORMATION basic;
    SYSTEM_INFO info;
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" ), extra;
    void **dispatcher = (void **)GetProcAddress( ntdll, "__wine_syscall_dispatcher" );
    void **unix_dispatcher = (void **)GetProcAddress( ntdll, "__wine_unix_call_dispatcher" );
    void *heap;
    LIST_ENTRY *entry;
    ULONG returned = 0;
    NTSTATUS status;

    check( (ULONG_PTR)ntdll == WINE_MANAGED_HOST_NTDLL_START, "real ntdll uses the canonical host base" );
    pointer_trace( "ntdll", ntdll );
    check( (ULONG_PTR)dispatcher >= WINE_MANAGED_HOST_NTDLL_START &&
           (ULONG_PTR)dispatcher + sizeof(*dispatcher) <= WINE_MANAGED_HOST_NTDLL_END &&
           (ULONG_PTR)unix_dispatcher >= WINE_MANAGED_HOST_NTDLL_START &&
           (ULONG_PTR)unix_dispatcher + sizeof(*unix_dispatcher) <= WINE_MANAGED_HOST_NTDLL_END,
           "private dispatcher storage lies inside the canonical real ntdll slot" );
    pointer_trace( "syscall_dispatcher_storage", dispatcher );
    pointer_trace( "unix_dispatcher_storage", unix_dispatcher );
    check( dispatcher && *dispatcher && native_address( *dispatcher ),
           "private syscall dispatcher points to a real native address outside both arenas" );
    check( unix_dispatcher && *unix_dispatcher && native_address( *unix_dispatcher ),
           "private Unix dispatcher points to a real native address outside both arenas" );
    if (dispatcher) pointer_trace( "syscall_dispatcher", *dispatcher );
    if (unix_dispatcher) pointer_trace( "unix_dispatcher", *unix_dispatcher );
    inspect_thread( "main" );
    check( ordinary_host( peb ), "PEB lies in the ordinary host domain" );
    check( ordinary_host( peb->ProcessParameters ), "process parameters lie in the ordinary host domain" );
    check( ordinary_host( peb->ProcessParameters->Environment ), "Windows environment lies in the ordinary host domain" );
    check( ordinary_host( peb->ProcessParameters->CommandLine.Buffer ), "Windows command line lies in the ordinary host domain" );
    check( ordinary_host( peb->ImageBaseAddress ) && ordinary_host( (void *)&test_runtime ),
           "relocated executable and its live code lie in the ordinary host domain" );
    check( ordinary_host( peb->ProcessHeap ) && ordinary_host( GetProcessHeap() ),
           "Windows process heap lies in the ordinary host domain" );
    heap = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 4096 );
    check( heap && ordinary_host( heap ), "real Windows heap allocation uses the host domain" );
    if (heap)
    {
        check( !*(BYTE *)heap, "heap zeroing remains functional" );
        *(BYTE *)heap = 0x39;
        check( HeapFree( GetProcessHeap(), 0, heap ), "Windows heap allocation frees" );
    }
    pointer_trace( "peb", peb );
    pointer_trace( "parameters", peb->ProcessParameters );
    pointer_trace( "environment", peb->ProcessParameters->Environment );
    pointer_trace( "process_heap", peb->ProcessHeap );
    pointer_trace( "exe", peb->ImageBaseAddress );
    check( ordinary_host( GetModuleHandleA( "kernel32.dll" ) ), "actual kernel32 import module uses the host domain" );
    extra = LoadLibraryA( "version.dll" );
    check( extra && ordinary_host( extra ), "a real additional import DLL loads in the host domain" );
    if (extra) check( FreeLibrary( extra ), "additional DLL unloads" );
    for (entry = peb->LdrData->InLoadOrderModuleList.Flink;
         entry != &peb->LdrData->InLoadOrderModuleList; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *module = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        printf( "managed-executor-pe: module base=%p size=%lx\n", module->DllBase, module->SizeOfImage );
        check( (module->DllBase == ntdll && (ULONG_PTR)module->DllBase + module->SizeOfImage <=
                WINE_MANAGED_HOST_NTDLL_END) ||
               (ordinary_host( module->DllBase ) && (ULONG_PTR)module->DllBase + module->SizeOfImage <=
                WINE_MANAGED_HOST_END), "loaded PE image lies wholly within its declared host slot" );
    }
    memset( &basic, 0, sizeof(basic) );
    status = NtQuerySystemInformation( SystemBasicInformation, &basic, sizeof(basic), &returned );
    check( !status, "actual SystemBasicInformation query succeeds" );
    if (!status)
        check( (ULONG_PTR)basic.LowestUserAddress == WINE_MANAGED_HOST_ALLOC_START &&
               (ULONG_PTR)basic.HighestUserAddress == WINE_MANAGED_HOST_END - 1,
               "physical process reports the truthful ordinary host allocation bounds" );
    GetSystemInfo( &info );
    check( (ULONG_PTR)info.lpMinimumApplicationAddress == WINE_MANAGED_HOST_ALLOC_START &&
           (ULONG_PTR)info.lpMaximumApplicationAddress == WINE_MANAGED_HOST_END - 1,
           "GetSystemInfo reports the same host allocation bounds" );
    printf( "managed-executor-pe: bounds min=%p max=%p\n", info.lpMinimumApplicationAddress,
            info.lpMaximumApplicationAddress );
    {
        MEMORY_BASIC_INFORMATION memory, sentinel;
        SIZE_T length = 0xdeadbeef;

        status = NtQueryVirtualMemory( NtCurrentProcess(), ntdll, MemoryBasicInformation,
                                       &memory, sizeof(memory), &length );
        check( !status && memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
               memory.AllocationBase == ntdll, "canonical real ntdll remains publicly queryable as an image" );
        memset( &memory, 0x5a, sizeof(memory) );
        sentinel = memory;
        length = 0xdeadbeef;
        status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)0x20000, MemoryBasicInformation,
                                       &memory, sizeof(memory), &length );
        check( status == STATUS_INVALID_PARAMETER && !memcmp( &memory, &sentinel, sizeof(memory) ) &&
               length == 0xdeadbeef, "guest query rejects without modifying caller outputs" );
    }
}

static BOOL free_allocation( void *address )
{
    SIZE_T size = 0;
    NTSTATUS status = NtFreeVirtualMemory( NtCurrentProcess(), &address, &size, MEM_RELEASE );

    check( !status,
           "private allocation releases through the real syscall path" );
    return !status;
}

static void reject_allocation( ULONG_PTR requested, SIZE_T requested_size, const char *description )
{
    void *address = (void *)requested;
    SIZE_T size = requested_size;
    NTSTATUS status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size,
                                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

    check( status == STATUS_INVALID_PARAMETER && address == (void *)requested && size == requested_size,
           description );
    printf( "managed-executor-pe: rejection va=%p size=%Ix status=%08lx result=%p/%Ix\n",
            (void *)requested, requested_size, status, address, size );
    if (!status) free_allocation( address );
}

static void check_shared_data( ULONG major_version )
{
    MEMORY_BASIC_INFORMATION memory;
    volatile KUSER_SHARED_DATA *shared = (void *)WINE_MANAGED_KUSER_START;

    check( VirtualQuery( (void *)WINE_MANAGED_KUSER_START, &memory, sizeof(memory) ) == sizeof(memory) &&
           memory.State == MEM_COMMIT && memory.Protect == PAGE_READONLY,
           "KUSER_SHARED_DATA stays committed and read-only after rejected mutation" );
    check( shared->NtMajorVersion == major_version,
           "ordinary volatile shared-data read remains intact after rejected mutation" );
}

static void test_shared_data(void)
{
    volatile KUSER_SHARED_DATA *shared = (void *)WINE_MANAGED_KUSER_START;
    ULONG major_version = shared->NtMajorVersion;
    DWORD old_protect = 0xdeadbeef;
    void *address = (void *)WINE_MANAGED_KUSER_START;
    SIZE_T size = 0x1000;
    NTSTATUS status;

    check_shared_data( major_version );
    status = NtProtectVirtualMemory( NtCurrentProcess(), &address, &size, PAGE_READWRITE, &old_protect );
    check( status < 0, "public protection change cannot make KUSER_SHARED_DATA writable" );
    check_shared_data( major_version );
    address = (void *)WINE_MANAGED_KUSER_START;
    size = 0;
    status = NtFreeVirtualMemory( NtCurrentProcess(), &address, &size, MEM_RELEASE );
    check( status < 0, "public release cannot remove KUSER_SHARED_DATA" );
    check_shared_data( major_version );
    address = (void *)WINE_MANAGED_KUSER_START;
    size = 0x1000;
    status = NtFreeVirtualMemory( NtCurrentProcess(), &address, &size, MEM_DECOMMIT );
    check( status < 0, "public decommit cannot remove KUSER_SHARED_DATA" );
    check_shared_data( major_version );
    address = (void *)WINE_MANAGED_KUSER_START;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size, MEM_RESET, PAGE_READWRITE );
    check( status < 0, "public reset cannot discard KUSER_SHARED_DATA" );
    check_shared_data( major_version );
    address = (void *)WINE_MANAGED_KUSER_START;
    size = 0x1000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size, MEM_COMMIT, PAGE_READWRITE );
    check( status < 0, "public recommit cannot change KUSER_SHARED_DATA" );
    check_shared_data( major_version );
    status = NtUnmapViewOfSection( NtCurrentProcess(), (void *)WINE_MANAGED_KUSER_START );
    check( status < 0, "public section unmap cannot remove KUSER_SHARED_DATA" );
    check_shared_data( major_version );
}

static void *dispatcher_pointer(void)
{
    return *(void * volatile *)WINE_MANAGED_DISPATCH_START;
}

static void check_private_dispatcher( void *expected )
{
    MEMORY_BASIC_INFORMATION memory;
    SIZE_T length = 0;
    LARGE_INTEGER counter;
    NTSTATUS status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)WINE_MANAGED_DISPATCH_START,
                                            MemoryBasicInformation, &memory, sizeof(memory), &length );

    check( !status && length == sizeof(memory) && memory.BaseAddress == (void *)WINE_MANAGED_DISPATCH_START &&
           memory.AllocationBase == (void *)WINE_MANAGED_DISPATCH_START && memory.RegionSize == 0x1000 &&
           memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE && memory.Protect == PAGE_READWRITE,
           "declared private dispatcher page remains committed read-write and non-executable" );
    check( dispatcher_pointer() == expected && native_address( expected ),
           "ordinary volatile dispatcher read preserves the real native pointer" );
    check( !NtQueryPerformanceCounter( &counter, NULL ), "real syscall succeeds after dispatcher mutation denial" );
}

static void test_private_dispatcher(void)
{
    static const ULONG protection[] = { PAGE_READWRITE, PAGE_READONLY, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE };
    static const ULONG free_type[] = { MEM_RELEASE, MEM_DECOMMIT, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER };
    static const ULONG allocation_type[] = { MEM_RESET, MEM_COMMIT, MEM_RESERVE | MEM_COMMIT };
    void *original = dispatcher_pointer(), *address;
    SIZE_T size;
    ULONG old_protect;
    NTSTATUS status;
    unsigned int i;

    /* This fixed low page is owned by Wine's physical AMD64 syscall ABI. It is
     * a deliberate private exception to the guest reservation, not an alias or
     * a security boundary: native runtime instrumentation writes remain valid. */
    pointer_trace( "fixed_private_dispatcher", original );
    check_private_dispatcher( original );
    for (i = 0; i < sizeof(protection) / sizeof(protection[0]); i++)
    {
        address = (void *)WINE_MANAGED_DISPATCH_START;
        size = 0x1000;
        old_protect = 0xdeadbeef;
        status = NtProtectVirtualMemory( NtCurrentProcess(), &address, &size, protection[i], &old_protect );
        check( status < 0 && address == (void *)WINE_MANAGED_DISPATCH_START && size == 0x1000 &&
               old_protect == PAGE_NOACCESS, "public dispatcher protection denial preserves range and reports existing Wine old-protection output" );
        check_private_dispatcher( original );
    }
    for (i = 0; i < sizeof(free_type) / sizeof(free_type[0]); i++)
    {
        address = (void *)WINE_MANAGED_DISPATCH_START;
        size = free_type[i] == MEM_RELEASE ? 0 : 0x1000;
        status = NtFreeVirtualMemory( NtCurrentProcess(), &address, &size, free_type[i] );
        check( status < 0 && address == (void *)WINE_MANAGED_DISPATCH_START &&
               size == (free_type[i] == MEM_RELEASE ? 0 : 0x1000),
               "public dispatcher release or decommit rejects with unchanged outputs" );
        check_private_dispatcher( original );
    }
    for (i = 0; i < sizeof(allocation_type) / sizeof(allocation_type[0]); i++)
    {
        address = (void *)WINE_MANAGED_DISPATCH_START;
        size = 0x1000;
        status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size, allocation_type[i], PAGE_READWRITE );
        check( status < 0 && address == (void *)WINE_MANAGED_DISPATCH_START && size == 0x1000,
               "public dispatcher reset or recommit rejects with unchanged outputs" );
        check_private_dispatcher( original );
    }
    address = (void *)WINE_MANAGED_DISPATCH_START;
    size = 0x1000;
    status = NtAllocateVirtualMemoryEx( NtCurrentProcess(), &address, &size,
                                        MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0 );
    check( status < 0 && address == (void *)WINE_MANAGED_DISPATCH_START && size == 0x1000,
           "public placeholder replacement cannot displace the owned dispatcher page" );
    check_private_dispatcher( original );
    status = NtUnmapViewOfSection( NtCurrentProcess(), (void *)WINE_MANAGED_DISPATCH_START );
    check( status < 0, "public section unmap cannot remove the private dispatcher page" );
    check_private_dispatcher( original );
    status = NtUnmapViewOfSectionEx( NtCurrentProcess(), (void *)WINE_MANAGED_DISPATCH_START, 0 );
    check( status < 0, "public extended section unmap cannot remove the private dispatcher page" );
    check_private_dispatcher( original );
}

static void set_instrumentation( void *callback )
{
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { 0 };
    NTSTATUS status;

    info.Callback = callback;
    status = NtSetInformationProcess( NtCurrentProcess(), ProcessInstrumentationCallback, &info, sizeof(info) );
    check( !status, "actual version-zero process instrumentation callback setting succeeds" );
    if (status) ExitProcess( 1 );
}

static void clear_instrumentation( void *original )
{
    set_instrumentation( NULL );
    check( dispatcher_pointer() == original, "clearing instrumentation restores the original private dispatcher" );
    if (dispatcher_pointer() != original) ExitProcess( 1 );
}

static void test_instrumentation(void)
{
    void *original = dispatcher_pointer(), *instrumented, *first_return, *replacement_return;
    LONG first_count, replacement_count;
    NTSTATUS first_status, replacement_status;
    LARGE_INTEGER counter;

    /* Follow the actual return ABI exercised by ntdll/tests/exception.c. The
     * callback is entered by a real syscall return, never called by this test. */
    set_instrumentation( executor_instrumentation_callback );
    instrumented = dispatcher_pointer();
    executor_instrumentation_calls = 0;
    executor_instrumentation_return = NULL;
    first_status = NtFlushProcessWriteBuffers();
    first_count = executor_instrumentation_calls;
    first_return = executor_instrumentation_return;
    set_instrumentation( executor_instrumentation_replacement_callback );
    executor_instrumentation_replacement_calls = 0;
    executor_instrumentation_replacement_return = NULL;
    replacement_status = NtFlushProcessWriteBuffers();
    replacement_count = executor_instrumentation_replacement_calls;
    replacement_return = executor_instrumentation_replacement_return;
    check( dispatcher_pointer() == instrumented, "replacing a non-null callback retains the native instrumentation dispatcher" );
    clear_instrumentation( original );
    check( instrumented != original && native_address( instrumented ),
           "instrumentation changes the owned low page to the genuine native instrumentation dispatcher" );
    check( !first_status && first_count == 1 && first_return >= (void *)NtFlushProcessWriteBuffers &&
           first_return < (void *)((BYTE *)NtFlushProcessWriteBuffers + 0x20),
           "real syscall enters the first callback and jumps back to its actual thunk return" );
    check( !replacement_status && replacement_count == 1 && replacement_return >= (void *)NtFlushProcessWriteBuffers &&
           replacement_return < (void *)((BYTE *)NtFlushProcessWriteBuffers + 0x20),
           "real syscall enters the replacement callback and returns successfully" );
    executor_instrumentation_calls = executor_instrumentation_replacement_calls = 0;
    check( !NtQueryPerformanceCounter( &counter, NULL ) && !executor_instrumentation_calls &&
           !executor_instrumentation_replacement_calls, "cleared instrumentation permits a healthy syscall without callbacks" );
    printf( "managed-executor-pe: instrumentation original=%p installed=%p first=%ld replacement=%ld cleared=%p\n",
            original, instrumented, first_count, replacement_count, dispatcher_pointer() );
    test_thread();
}

static void test_image_boundaries(void)
{
    char filename[32768];
    HANDLE file, section = NULL;
    IMAGE_DOS_HEADER *dos = (void *)GetModuleHandleA( NULL );
    IMAGE_NT_HEADERS *nt = (void *)((BYTE *)dos + dos->e_lfanew);
    static const ULONG_PTR rejected[] =
    {
        0x20000,
        WINE_MANAGED_HOST_NTDLL_START + 0x10000,
        WINE_MANAGED_KUSER_START,
        WINE_MANAGED_DISPATCH_START,
        WINE_MANAGED_HOST_END,
        WINE_MANAGED_HOST_END - 0x10000
    };
    NTSTATUS status;
    unsigned int i;

    image_boundary_padding[sizeof(image_boundary_padding) - 1] = 0x2f;
    check( nt->OptionalHeader.SizeOfImage > 0x10000,
           "benign image size genuinely crosses the last host allocation unit" );
    if (!GetModuleFileNameA( NULL, filename, sizeof(filename) ))
    {
        check( 0, "own benign image file path is available" );
        return;
    }
    check( 1, "own benign image file path is available" );
    file = CreateFileA( filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL );
    check( file != INVALID_HANDLE_VALUE, "own benign image file opens for SEC_IMAGE" );
    if (file == INVALID_HANDLE_VALUE) return;
    status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file );
    check( status >= 0 && section, "actual SEC_IMAGE section creates from the well-formed benign PE" );
    if (status >= 0 && section)
    {
        void *view = NULL;
        SIZE_T size = 0;
        MEMORY_BASIC_INFORMATION memory;

        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READONLY );
        check( status >= 0 && ordinary_host( view ) && size >= nt->OptionalHeader.SizeOfImage &&
               (ULONG_PTR)view + size <= WINE_MANAGED_HOST_END,
               "normal well-formed SEC_IMAGE view maps wholly inside the ordinary host domain" );
        if (status >= 0)
        {
            check( ((IMAGE_DOS_HEADER *)view)->e_magic == IMAGE_DOS_SIGNATURE,
                   "actual image view preserves the benign PE header" );
            check( VirtualQuery( view, &memory, sizeof(memory) ) == sizeof(memory) && memory.Type == MEM_IMAGE,
                   "normal image-section view reports the genuine image mapping type" );
            check( !NtUnmapViewOfSection( NtCurrentProcess(), view ), "normal benign image view unmaps" );
        }
        for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
        {
            void *view = (void *)rejected[i];
            SIZE_T size = 0;

            status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                        ViewUnmap, 0, PAGE_READONLY );
            check( status < 0 && view == (void *)rejected[i] && !size,
                   "explicit forbidden SEC_IMAGE view rejects without relocating or changing outputs" );
            printf( "managed-executor-pe: image rejection va=%p image_size=%lx status=%08lx result=%p/%Ix\n",
                    (void *)rejected[i], nt->OptionalHeader.SizeOfImage, status, view, size );
            if (status >= 0) check( !NtUnmapViewOfSection( NtCurrentProcess(), view ),
                                   "unexpected successful image view is cleaned after recording failure" );
        }
        check( !NtClose( section ), "benign image section handle closes" );
    }
    check( CloseHandle( file ), "benign image file handle closes" );
}

static void test_allocations( unsigned int value, DWORD hold_ms, DWORD release_hold_ms, DWORD instrumentation_hold_ms )
{
    void *address, *view;
    SIZE_T size;
    NTSTATUS status;
    HANDLE section = NULL;
    LARGE_INTEGER section_size;
    MEMORY_BASIC_INFORMATION memory;
    unsigned int mode;

    /* Fixed MEM_RESERVE only: the real image proves this exact whole-host span
     * is occupied. map_fixed_area rejects overlap via find_view_range before
     * create_view or per-page protection metadata can materialize this span.
     * Skip the syscall if the required occupied-range proof is unavailable. */
    {
        HMODULE image = GetModuleHandleA( NULL );
        BOOL occupied = VirtualQuery( image, &memory, sizeof(memory) ) == sizeof(memory) &&
                        memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
                        ordinary_host( memory.AllocationBase ) && ordinary_host( image );

        check( occupied, "whole-host reserve rejection has an existing live image overlap" );
        if (occupied)
        {
            const SIZE_T extent = WINE_MANAGED_HOST_END - WINE_MANAGED_HOST_ALLOC_START;

            address = (void *)WINE_MANAGED_HOST_ALLOC_START;
            size = extent;
            status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size,
                                              MEM_RESERVE, PAGE_NOACCESS );
            check( status == STATUS_CONFLICTING_ADDRESSES &&
                   (ULONG_PTR)address == WINE_MANAGED_HOST_ALLOC_START && size == extent,
                   "fixed whole occupied host-domain reserve reports conflict without modifying outputs" );
            printf( "managed-executor-pe: occupied-reserve va=%p size=%Ix status=%08lx result=%p/%Ix\n",
                    (void *)WINE_MANAGED_HOST_ALLOC_START, extent, status, address, size );
            if (status >= 0) free_allocation( address );
        }
    }

    for (mode = 0; mode < 2; mode++)
    {
        address = NULL;
        size = 0x20000;
        status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size,
                                          MEM_RESERVE | MEM_COMMIT | (mode ? MEM_TOP_DOWN : 0),
                                          PAGE_READWRITE );
        check( !status && ordinary_host( address ) && (ULONG_PTR)address + size <= WINE_MANAGED_HOST_END,
               mode ? "top-down allocation uses the ordinary host domain" : "default allocation uses the ordinary host domain" );
        if (!status)
        {
            *(volatile BYTE *)address = 0x69;
            check( *(volatile BYTE *)address == 0x69, "host allocation retains an ordinary pointer write" );
            free_allocation( address );
        }
    }
    reject_allocation( 0x20000, 0x10000, "guest allocation rejects without modifying caller outputs" );
    reject_allocation( WINE_MANAGED_HOST_NTDLL_START + 0x10000, 0x10000,
                       "canonical ntdll slot allocation rejects without modifying caller outputs" );
    reject_allocation( WINE_MANAGED_HOST_END, 0x10000,
                       "outside-host allocation rejects without modifying caller outputs" );
    reject_allocation( WINE_MANAGED_HOST_END - 0x10000, 0x20000,
                       "cross-boundary allocation rejects without modifying caller outputs" );

    test_shared_data();
    section_size.QuadPart = 0x20000;
    status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                              SEC_COMMIT, NULL );
    check( !status, "real ordinary section creates" );
    if (!status)
    {
        view = (void *)(WINE_MANAGED_HOST_ALLOC_START + 0x10000000);
        size = 0x10000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( !status && (ULONG_PTR)view == WINE_MANAGED_HOST_ALLOC_START + 0x10000000,
               "fixed section view maps at the requested ordinary host address" );
        if (!status)
        {
            *(volatile BYTE *)view = 0x4a;
            check( !NtUnmapViewOfSection( NtCurrentProcess(), view ), "fixed section view unmaps" );
        }
        view = NULL;
        size = 0;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( !status && ordinary_host( view ) && (ULONG_PTR)view + size <= WINE_MANAGED_HOST_END,
               "default section view uses the ordinary host domain" );
        if (!status)
        {
            *(volatile BYTE *)view = 0x4a;
            check( *(volatile BYTE *)view == 0x4a, "ordinary section pointer write works" );
            check( !NtUnmapViewOfSection( NtCurrentProcess(), view ), "section view unmaps" );
        }
        view = (void *)0x20000;
        size = 0x10000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( status < 0 && view == (void *)0x20000 && size == 0x10000,
               "guest section view rejects without modifying caller outputs" );
        if (!status) NtUnmapViewOfSection( NtCurrentProcess(), view );
        view = (void *)(WINE_MANAGED_HOST_NTDLL_START + 0x10000);
        size = 0x10000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( status < 0 && (ULONG_PTR)view == WINE_MANAGED_HOST_NTDLL_START + 0x10000 && size == 0x10000,
               "canonical ntdll slot section view rejects without modifying caller outputs" );
        if (!status) NtUnmapViewOfSection( NtCurrentProcess(), view );
        view = (void *)WINE_MANAGED_HOST_END;
        size = 0x10000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( status < 0 && (ULONG_PTR)view == WINE_MANAGED_HOST_END && size == 0x10000,
               "outside-host section view rejects without modifying caller outputs" );
        if (!status) NtUnmapViewOfSection( NtCurrentProcess(), view );
        view = (void *)(WINE_MANAGED_HOST_END - 0x10000);
        size = 0x20000;
        status = NtMapViewOfSection( section, NtCurrentProcess(), &view, 0, 0, NULL, &size,
                                    ViewUnmap, 0, PAGE_READWRITE );
        check( status < 0 && (ULONG_PTR)view == WINE_MANAGED_HOST_END - 0x10000 && size == 0x20000,
               "cross-boundary section view rejects without modifying caller outputs" );
        if (!status) NtUnmapViewOfSection( NtCurrentProcess(), view );
        check( !NtClose( section ), "section handle closes" );
    }

    /* Explicit benign fixture VA within the ordinary host domain, unrelated to
     * E05 addresses. Two independently launched fixtures use the same VA with
     * different --value bytes; an external read-only observer verifies isolation. */
    address = (void *)(WINE_MANAGED_HOST_ALLOC_START + 0x20000000);
    size = 0x10000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    check( !status && (ULONG_PTR)address == WINE_MANAGED_HOST_ALLOC_START + 0x20000000,
           "fixed ordinary-host allocation retains the requested address" );
    if (!status)
    {
        HANDLE observation_thread = NULL;
        DWORD exit_code = 0;
        BOOL released, free_state;
        void *original_dispatcher = NULL;
        DWORD observation_ms = max( hold_ms, instrumentation_hold_ms );

        memset( address, value, size );
        if (instrumentation_hold_ms)
        {
            original_dispatcher = dispatcher_pointer();
            set_instrumentation( executor_instrumentation_callback );
            check( dispatcher_pointer() != original_dispatcher && native_address( dispatcher_pointer() ),
                   "explicit observation option enables instrumentation only in this physical process" );
            printf( "managed-executor-pe: instrumentation-checkpoint state=enabled original=%p current=%p\n",
                    original_dispatcher, dispatcher_pointer() );
        }
        if (observation_ms)
        {
            observation_ready = CreateEventA( NULL, TRUE, FALSE, NULL );
            observation_release = CreateEventA( NULL, TRUE, FALSE, NULL );
            check( observation_ready && observation_release, "observation synchronization events create" );
            if (observation_ready && observation_release)
            {
                observation_thread = CreateThread( NULL, 0, worker_thread, NULL, 0, NULL );
                check( !!observation_thread, "live observation worker starts" );
                if (observation_thread)
                    require_join( observation_ready, 10000,
                                  "worker TEB and syscall metadata are live before checkpoint" );
            }
        }
        printf( "managed-executor-pe: checkpoint pid=%lu va=%p size=%Ix value=%u hold_ms=%lu\n",
                GetCurrentProcessId(), address, size, value, observation_ms );
        fflush( stdout );
        if (observation_ms) Sleep( observation_ms );
        if (instrumentation_hold_ms)
        {
            clear_instrumentation( original_dispatcher );
            printf( "managed-executor-pe: instrumentation-checkpoint state=cleared current=%p\n", dispatcher_pointer() );
        }
        if (observation_thread)
        {
            if (!SetEvent( observation_release ))
            {
                check( 0, "observation worker releases deterministically" );
                ExitProcess( 1 );
            }
            check( 1, "observation worker releases deterministically" );
            require_join( observation_thread, 10000, "observation worker joins before its events close" );
            check( GetExitCodeThread( observation_thread, &exit_code ) && exit_code == 0x75,
                   "observation worker returns after its native wait" );
            check( CloseHandle( observation_thread ), "observation thread handle closes" );
        }
        if (observation_ready) check( CloseHandle( observation_ready ), "observation ready event closes" );
        if (observation_release) check( CloseHandle( observation_release ), "observation release event closes" );
        observation_ready = observation_release = NULL;
        check( *(volatile BYTE *)address == value && ((volatile BYTE *)address)[size - 1] == value,
               "fixed private bytes survive the observation checkpoint" );
        released = free_allocation( address );
        free_state = released && VirtualQuery( address, &memory, sizeof(memory) ) == sizeof(memory) &&
                     memory.State == MEM_FREE;
        check( free_state,
               "fixed host allocation reports free after release" );
        if (!released || !free_state) ExitProcess( 1 );
        printf( "managed-executor-pe: released pid=%lu va=%p size=%Ix hold_ms=%lu\n",
                GetCurrentProcessId(), address, size, release_hold_ms );
        if (release_hold_ms) Sleep( release_hold_ms );
    }
}

static void test_fault_unwind(void)
{
    ULONG_PTR result, image_base = 0;
    RUNTIME_FUNCTION *function;
    LARGE_INTEGER counter;
    SIZE_T size = 0x1000;
    NTSTATUS status;
    HANDLE original_event;
    DWORD handle_flags;
    TEB *original_teb = NtCurrentTeb();
    void *original_stack_limit = original_teb->Tib.StackLimit;
    void *original_stack_base = original_teb->Tib.StackBase;

    fault_page = NULL;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &fault_page, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS );
    check( !status && ordinary_host( fault_page ), "real PAGE_NOACCESS fault allocation creates" );
    if (status) return;
    leaf_resource = HeapAlloc( GetProcessHeap(), 0, 64 );
    root_resource = CreateEventA( NULL, TRUE, FALSE, NULL );
    original_event = root_resource;
    check( leaf_resource && ordinary_host( leaf_resource ) && root_resource,
           "leaf heap and root event resources acquire before frame ownership transfer" );
    if (!leaf_resource || !root_resource)
    {
        /* Preparation did not complete, so neither frame owns a resource yet. */
        if (leaf_resource) check( HeapFree( GetProcessHeap(), 0, leaf_resource ), "failed preparation releases leaf resource" );
        if (root_resource) check( !NtClose( root_resource ), "failed preparation closes root event" );
        leaf_resource = root_resource = NULL;
        free_allocation( fault_page );
        fault_page = NULL;
        return;
    }
    function = RtlLookupFunctionEntry( (ULONG_PTR)executor_fault_root, &image_base, NULL );
    check( !!function, "root has a real registered PE runtime function entry" );
    function = RtlLookupFunctionEntry( (ULONG_PTR)executor_fault_leaf, &image_base, NULL );
    check( !!function, "leaf has a real registered PE runtime function entry" );
    result = executor_fault_root( fault_page );
    check( result == 0x51a7 && landed == 1, "targeted unwind lands and returns through the native host" );
    check( leaf_search == 1 && root_search == 1, "actual access violation searched both PE table handlers" );
    check( leaf_cleanup == 1 && root_cleanup == 1,
           "real unwind consumes leaf cleanup and target root cleanup exactly once" );
    check( leaf_cleanup_success == 1 && root_cleanup_success == 1 && !leaf_resource && !root_resource,
           "actual unwind handlers free leaf allocation and close root event exactly once" );
    SetLastError( 0 );
    check( !GetHandleInformation( original_event, &handle_flags ) && GetLastError() == ERROR_INVALID_HANDLE,
           "root event is observably closed before post-recovery calls" );
    printf( "managed-executor-pe: unwind result=%Ix search=%ld/%ld cleanup=%ld/%ld consumed=%ld/%ld landed=%ld\n",
            result, leaf_search, root_search, leaf_cleanup, root_cleanup,
            leaf_cleanup_success, root_cleanup_success, landed );
    /* A failed ownership assertion stays failed; this only avoids leaking a
     * leftover if the runtime returned without executing the expected handler. */
    if (leaf_resource) HeapFree( GetProcessHeap(), 0, leaf_resource );
    if (root_resource) NtClose( root_resource );
    leaf_resource = root_resource = NULL;
    free_allocation( fault_page );
    fault_page = NULL;
    check( NtCurrentTeb() == original_teb && original_teb->Tib.StackLimit == original_stack_limit &&
           original_teb->Tib.StackBase == original_stack_base,
           "fault return preserves the original main TEB and PE stack bounds" );
    inspect_thread( "main-after-unwind" );
    check( !NtQueryPerformanceCounter( &counter, NULL ), "healthy syscall succeeds after native fault recovery" );
    test_thread();
}

static void test_environment_cleared_child(void)
{
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION process;
    char filename[32768], command[32800];
    DWORD exit_code = 0;
    DWORD wait;
    NTSTATUS (WINAPI *set_unix_env)( const char *, const char * );

    set_unix_env = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "__wine_set_unix_env" );
    check( !!set_unix_env, "real Unix environment API is available" );
    if (!set_unix_env) return;
    check( !set_unix_env( "WINE_MANAGED_LAYOUT", NULL ), "Unix layout setting clears before child launch" );
    check( SetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", NULL ), "Windows layout setting clears before child launch" );
    if (!GetModuleFileNameA( NULL, filename, sizeof(filename) ))
    {
        check( 0, "real executable path is available for child launch" );
        return;
    }
    check( 1, "real executable path is available for child launch" );
    snprintf( command, sizeof(command), "\"%s\" --child", filename );
    memset( &process, 0, sizeof(process) );
    check( CreateProcessA( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process ),
           "environment-cleared child launches through the real Wine loader" );
    if (!process.hProcess) return;
    wait = WaitForSingleObject( process.hProcess, 30000 );
    check( wait == WAIT_OBJECT_0, "environment-cleared child completes" );
    if (wait != WAIT_OBJECT_0)
    {
        check( TerminateProcess( process.hProcess, 1 ), "failed child terminates for deterministic cleanup" );
        check( WaitForSingleObject( process.hProcess, 10000 ) == WAIT_OBJECT_0,
               "failed child is reaped before closing its handles" );
    }
    check( GetExitCodeProcess( process.hProcess, &exit_code ) && !exit_code,
           "environment-cleared child preserves the managed executor contract" );
    check( CloseHandle( process.hThread ), "child thread handle closes" );
    check( CloseHandle( process.hProcess ), "child process handle closes" );
}

int main( int argc, char **argv )
{
    unsigned int value = 0x41;
    DWORD hold_ms = 0;
    DWORD release_hold_ms = 0;
    DWORD instrumentation_hold_ms = 0;
    BOOL child = FALSE;
    int i;

    setvbuf( stdout, NULL, _IONBF, 0 );
    main_peb = NtCurrentTeb()->Peb;
    for (i = 1; i < argc; i++)
    {
        if (!strcmp( argv[i], "--child" )) child = TRUE;
        else if (!strncmp( argv[i], "--value=", 8 )) value = strtoul( argv[i] + 8, NULL, 0 );
        else if (!strncmp( argv[i], "--hold-ms=", 10 )) hold_ms = strtoul( argv[i] + 10, NULL, 0 );
        else if (!strncmp( argv[i], "--release-hold-ms=", 18 )) release_hold_ms = strtoul( argv[i] + 18, NULL, 0 );
        else if (!strncmp( argv[i], "--instrumentation-hold-ms=", 26 )) instrumentation_hold_ms = strtoul( argv[i] + 26, NULL, 0 );
        else return 2;
    }
    if (value > 255 || hold_ms > 30000 || release_hold_ms > 30000 || instrumentation_hold_ms > 30000) return 2;
    printf( "managed-executor-pe: begin pid=%lu child=%u\n", GetCurrentProcessId(), child );
    if (child)
    {
        char setting[128];
        check( !GetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", setting, sizeof(setting) ),
               "child Windows layout environment remains cleared" );
    }
    test_runtime();
    test_private_dispatcher();
    test_instrumentation();
    test_image_boundaries();
    test_allocations( value, hold_ms, release_hold_ms, instrumentation_hold_ms );
    test_thread();
    test_fault_unwind();
    if (!child) test_environment_cleared_child();
    printf( "managed-executor-pe: summary checks=%u failures=%u child=%u\n", checks, failures, child );
    return !!failures;
}
