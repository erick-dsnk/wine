/*
 * Benign standalone Linux AMD64 managed TARGET -> EXECUTOR live-view proof.
 * This tests an internal default-off lease protocol, not Windows attach APIs.
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
#include "wine/server.h"
#include "wine/managed_layout.h"
#include "wine/unixlib.h"

#if !defined(_WIN64) || (!defined(__x86_64__) && !defined(_M_X64)) || defined(__ELF__)
#error AMD64 PE fixture required
#endif
#ifndef __WINE_PE_BUILD
#define __WINE_PE_BUILD
#endif
#include "wine/asm.h"

#define PROBE_ADDRESS ((void *)0x23000000)
#define PROBE_SIZE 0x10000
#define PROBE_FAULT 0x10000
#define TIMEOUT 10000

enum command { CMD_ALLOC, CMD_READ, CMD_WRITE, CMD_PROTECT, CMD_DECOMMIT,
               CMD_COMMIT, CMD_FREE, CMD_ACQUIRE, CMD_DROP, CMD_LOOP,
               CMD_LOOP_RESULT, CMD_EXIT, CMD_BEGIN_ACQUIRE, CMD_END_ACQUIRE, CMD_QUERY, CMD_COLLISION_INSTALL, CMD_COLLISION_REMOVE, CMD_MUTATION_BEGIN, CMD_MUTATION_POLL, CMD_MUTATION_WAIT, CMD_OWNER_STATE, CMD_WATCH_NATIVE_PID, CMD_SUSPENDED_CREATE, CMD_SUSPENDED_KILL, CMD_CPU_BARRIER, CMD_NEGATIVE_VM, CMD_DENIED_ACQUIRE, CMD_STALE_QUERY, CMD_CANCEL_BEGIN, CMD_CANCEL_END };
struct packet
{
    unsigned int command, value, target_pid, status;
    unsigned int state, lease_status, count, faults, offset, size, native_pid, native_dead;
    unsigned __int64 token, generation, mapping_id;
};
struct child { HANDLE process, pipe; DWORD pid, native_pid; const char *role; };
struct lease { HANDLE handle, ready; unsigned __int64 token, generation, mapping_id; };
static struct lease lease;
static LONG checks, failures;
static volatile LONG loop_stop, loop_reads, loop_faults;
static HANDLE loop_thread, mutation_thread, mutation_observer, acquire_thread, suspended_thread;
static unsigned int mutation_protection;
static NTSTATUS mutation_status, acquire_status;
static struct packet acquire_packet;
static BOOL watch_native_death;
static HANDLE cancelled_main, cancel_pipe;
static DWORD cancelled_main_tid;
static struct packet cancel_packet;
static int child_loop( HANDLE pipe );
struct loop_observation { volatile LONG completed, successful_after_completion, reads, faults, cpu_active, release_cpu, mutation_go, mutation_done, owner_updating, observer_ready, acquire_go; };
static struct loop_observation *loop_observation;

static void check( int ok, const char *description )
{
    ++checks;
    if (ok && getenv( "A1B_VERBOSE_CHECKS" )) printf( "a1b-live-private-view: PASS: %s\n", description );
    if (!ok)
    {
        ++failures;
        fprintf( stderr, "a1b-live-private-view: FAIL: %s\n", description );
    }
}
static void fatal( const char *description )
{
    fprintf( stderr, "a1b-live-private-view: fail-stop: %s, winerr=%lu\n", description, GetLastError() );
    ExitProcess( 2 );
}

/* Only the deliberately faultable single instructions are intercepted.
 * Real unrelated exceptions continue normal dispatch. Ordinary loads/stores
 * execute at the target's original VA; no Read/WriteProcessMemory substitute. */
unsigned int WINAPI probe_read( const volatile BYTE *address );
unsigned int WINAPI probe_write( volatile BYTE *address, unsigned int value );
extern char probe_read_fault, probe_read_landing, probe_write_fault, probe_write_landing;
__ASM_GLOBAL_FUNC( probe_read,
    ".seh_endprologue\n\t"
    ".globl probe_read_fault\nprobe_read_fault:\n\t"
    "movzbl (%rcx),%eax\n\t"
    ".globl probe_read_landing\nprobe_read_landing:\n\tret\n\t" );
__ASM_GLOBAL_FUNC( probe_write,
    ".seh_endprologue\n\t"
    ".globl probe_write_fault\nprobe_write_fault:\n\t"
    "movb %dl,(%rcx)\n\txorl %eax,%eax\n\t"
    ".globl probe_write_landing\nprobe_write_landing:\n\tret\n\t" );
static LONG CALLBACK fault_handler( EXCEPTION_POINTERS *exception )
{
    EXCEPTION_RECORD *record = exception->ExceptionRecord;
    CONTEXT *context = exception->ContextRecord;
    if (record->ExceptionCode != (DWORD)STATUS_ACCESS_VIOLATION || record->NumberParameters < 2 ||
        record->ExceptionInformation[1] != context->Rcx ||
        context->Rcx < (ULONG_PTR)PROBE_ADDRESS || context->Rcx >= (ULONG_PTR)PROBE_ADDRESS + PROBE_SIZE)
        return EXCEPTION_CONTINUE_SEARCH;
    if (context->Rip == (ULONG_PTR)&probe_read_fault && record->ExceptionInformation[0] == 0)
        context->Rip = (ULONG_PTR)&probe_read_landing;
    else if (context->Rip == (ULONG_PTR)&probe_write_fault && record->ExceptionInformation[0] == 1)
        context->Rip = (ULONG_PTR)&probe_write_landing;
    else return EXCEPTION_CONTINUE_SEARCH;
    context->Rax = PROBE_FAULT;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI read_loop( void *unused )
{
    (void)unused;
    while (!InterlockedCompareExchange( &loop_stop, 0, 0 ))
    {
        LONG completed = InterlockedCompareExchange( &loop_observation->completed, 0, 0 );
        if (probe_read( PROBE_ADDRESS ) == PROBE_FAULT)
        {
            InterlockedIncrement( &loop_faults );
            InterlockedIncrement( &loop_observation->faults );
            return 0;
        }
        if (completed) InterlockedIncrement( &loop_observation->successful_after_completion );
        InterlockedIncrement( &loop_reads );
        InterlockedIncrement( &loop_observation->reads );
    }
    return 0;
}

static DWORD WINAPI suspended_worker( void *unused )
{
    (void)unused;
    return 0x5a;
}
static NTSTATUS owner_state( struct packet *packet );
static DWORD WINAPI observe_mutation( void *unused )
{
    struct packet packet;
    DWORD start = GetTickCount();
    (void)unused;
    InterlockedExchange( &loop_observation->observer_ready, 1 );
    while (!InterlockedCompareExchange( &loop_observation->mutation_done, 0, 0 ) &&
           GetTickCount() - start < TIMEOUT)
    {
        memset( &packet, 0, sizeof(packet) );
        if (owner_state( &packet )) fatal( "observe authoritative owner fence" );
        if (packet.state) InterlockedExchange( &loop_observation->owner_updating, 1 );
        Sleep( 0 );
    }
    return 0;
}
static DWORD WINAPI mutation_worker( void *unused )
{
    DWORD old, start = GetTickCount();
    (void)unused;
    while ((!loop_observation->mutation_go || !loop_observation->observer_ready) &&
           GetTickCount() - start < TIMEOUT) YieldProcessor();
    if (!loop_observation->mutation_go || !loop_observation->observer_ready)
        fatal( "parent did not start asynchronous mutation" );
    mutation_status = VirtualProtect( PROBE_ADDRESS, PROBE_SIZE, mutation_protection, &old ) ?
                      STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    InterlockedExchange( &loop_observation->mutation_done, 1 );
    return 0;
}
static NTSTATUS query_lease( struct packet *packet )
{
    NTSTATUS status;
    SERVER_START_REQ( query_private_mapping_lease )
    {
        req->handle = wine_server_obj_handle( lease.handle );
        req->token = lease.token;
        req->generation = lease.generation;
        status = wine_server_call( req );
        packet->state = reply->state;
        packet->lease_status = reply->status;
    }
    SERVER_END_REQ;
    packet->token = lease.token;
    packet->generation = lease.generation;
    packet->mapping_id = lease.mapping_id;
    return status;
}
static NTSTATUS wait_lease( struct packet *packet )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;
    timeout.QuadPart = -(LONGLONG)TIMEOUT * 10000;
    status = NtWaitForSingleObject( lease.ready, FALSE, &timeout );
    if (status) return status;
    return query_lease( packet );
}
static NTSTATUS acquire_lease( struct packet *packet, BOOL wait )
{
    NTSTATUS status;
    HANDLE target;
    if (lease.handle) return STATUS_INVALID_HANDLE;
    if (!(target = OpenProcess( PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                               PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, packet->target_pid )))
        return STATUS_INVALID_CID;
    SERVER_START_REQ( acquire_private_mapping )
    {
        req->process = wine_server_obj_handle( target );
        req->address = (ULONG_PTR)PROBE_ADDRESS;
        req->size = PROBE_SIZE;
        req->access = packet->value;
        status = wine_server_call( req );
        if (!status)
        {
            lease.handle = wine_server_ptr_handle( reply->handle );
            lease.ready = wine_server_ptr_handle( reply->ready );
            lease.token = reply->token;
            lease.generation = reply->generation;
            lease.mapping_id = reply->mapping_id;
        }
    }
    SERVER_END_REQ;
    CloseHandle( target );
    if (!status && wait) status = wait_lease( packet );
    return status;
}
static DWORD WINAPI acquire_worker( void *unused )
{
    DWORD start = GetTickCount();
    (void)unused;
    while (!loop_observation->acquire_go && GetTickCount() - start < TIMEOUT) YieldProcessor();
    if (!loop_observation->acquire_go) fatal( "parent did not start asynchronous acquisition" );
    acquire_status = acquire_lease( &acquire_packet, FALSE );
    return 0;
}
static NTSTATUS denied_acquire( struct packet *packet )
{
    HANDLE target = OpenProcess( PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, packet->target_pid );
    NTSTATUS status;
    if (!target) return STATUS_INVALID_CID;
    SERVER_START_REQ( acquire_private_mapping )
    {
        req->process = wine_server_obj_handle( target );
        req->address = (ULONG_PTR)PROBE_ADDRESS;
        req->size = PROBE_SIZE;
        req->access = FILE_READ_DATA | FILE_WRITE_DATA;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    CloseHandle( target );
    return status;
}
static NTSTATUS stale_query( unsigned int field )
{
    NTSTATUS status;
    SERVER_START_REQ( query_private_mapping_lease )
    {
        req->handle = wine_server_obj_handle( lease.handle );
        req->token = lease.token + !field;
        req->generation = lease.generation + !!field;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}
static NTSTATUS drop_lease( struct packet *packet )
{
    NTSTATUS status;
    HANDLE ready = NULL;
    if (!lease.handle) return STATUS_INVALID_HANDLE;
    SERVER_START_REQ( release_private_mapping_lease )
    {
        req->handle = wine_server_obj_handle( lease.handle );
        req->token = lease.token;
        req->generation = lease.generation;
        status = wine_server_call( req );
        if (!status) ready = wine_server_ptr_handle( reply->ready );
    }
    SERVER_END_REQ;
    if (!status)
    {
        if (lease.ready) CloseHandle( lease.ready );
        lease.ready = ready;
        status = wait_lease( packet );
    }
    if (status) return status; /* failure keeps lease owned; fail-stop caller */
    CloseHandle( lease.handle );
    CloseHandle( lease.ready );
    memset( &lease, 0, sizeof(lease) );
    return STATUS_SUCCESS;
}
static NTSTATUS owner_state( struct packet *packet )
{
    HANDLE mapping = NULL;
    NTSTATUS status;
    SERVER_START_REQ( lookup_private_mapping )
    {
        req->address = (ULONG_PTR)PROBE_ADDRESS;
        status = wine_server_call( req );
        if (!status) mapping = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (status) return status;
    SERVER_START_REQ( query_private_mapping )
    {
        req->handle = wine_server_obj_handle( mapping );
        status = wine_server_call( req );
        if (!status) { packet->state = reply->updating; packet->generation = reply->generation; }
    }
    SERVER_END_REQ;
    CloseHandle( mapping );
    return status;
}
static NTSTATUS native_helper( unsigned int action, ULONG_PTR value, unsigned int *output )
{
    struct { UINT64 address, size; UINT action; } args;
    unixlib_handle_t handle;
    HMODULE helper = LoadLibraryA( "a1b-live-private-view-helper.dll" );
    NTSTATUS (WINAPI **dispatcher)( unixlib_handle_t, unsigned int, void * );
    NTSTATUS status;
    if (!helper) return STATUS_DLL_NOT_FOUND;
    status = NtQueryVirtualMemory( GetCurrentProcess(), helper, MemoryWineUnixFuncs,
                                   &handle, sizeof(handle), NULL );
    if (status) return status;
    dispatcher = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "__wine_unix_call_dispatcher" );
    if (!dispatcher || !*dispatcher) return STATUS_ENTRYPOINT_NOT_FOUND;
    args.address = value; args.size = PROBE_SIZE; args.action = action;
    status = (*dispatcher)( handle, 0, &args );
    if (!status && output) *output = args.address;
    return status;
}
/* Fixture-only queue-before-dequeue control. The oldest main thread is parked
 * in a native helper with SIGUSR1 blocked. This earlier-created survivor keeps
 * its original signal mask and makes no Wine SELECT wait before cancellation.
 * The external runner authorizes termination only after a queued trace names
 * that exact main TID; neither thread assumes CREATE_SUSPENDED inhibits APCs. */
static DWORD WINAPI cancel_survivor( void *unused )
{
    unsigned int phase = cancel_packet.offset;
    (void)unused;
    if (native_helper( 6, phase, NULL )) fatal( "recipient never entered native signal barrier" );
    if (!phase) acquire_status = acquire_lease( &cancel_packet, FALSE );
    if (native_helper( 7, phase, NULL )) fatal( "authoritative queued recipient kill was never authorized" );
    if (!TerminateThread( cancelled_main, 0x51 )) fatal( "terminate authoritative queued APC recipient" );
    if (WaitForSingleObject( cancelled_main, TIMEOUT ) != WAIT_OBJECT_0)
        fatal( "authoritative recipient termination did not finish" );
    printf( "a1b-live-private-view: cancelled-recipient phase=%s main_tid=%04lx survivor_tid=%04lx\n",
            phase ? "revoke" : "map", cancelled_main_tid, GetCurrentThreadId() );
    CloseHandle( cancelled_main ); cancelled_main = NULL;
    if (native_helper( 8, 0, NULL )) fatal( "dump survivor native probe reservation" );
    ExitProcess( child_loop( cancel_pipe ) );
    return 0;
}
static NTSTATUS negative_alias_vm( unsigned int operation )
{
    void *base = PROBE_ADDRESS;
    SIZE_T size = PROBE_SIZE;
    ULONG old, flag = 0;
    MEMORY_RANGE_ENTRY range = { PROBE_ADDRESS, PROBE_SIZE };
    LARGE_INTEGER section_size;
    HANDLE section;
    NTSTATUS status;
    switch (operation)
    {
    case 0: return NtAllocateVirtualMemory( GetCurrentProcess(), &base, 0, &size, MEM_COMMIT, PAGE_READWRITE );
    case 1: return NtAllocateVirtualMemory( GetCurrentProcess(), &base, 0, &size, MEM_RESET, PAGE_READWRITE );
    case 2: return NtProtectVirtualMemory( GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &old );
    case 3:
        section_size.QuadPart = PROBE_SIZE;
        status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &section_size,
                                  PAGE_READWRITE, SEC_COMMIT, NULL );
        if (status) return status;
        status = NtMapViewOfSection( section, GetCurrentProcess(), &base, 0, 0, NULL, &size,
                                     ViewUnmap, 0, PAGE_READWRITE );
        CloseHandle( section );
        return status;
    case 4: return NtSetInformationVirtualMemory( GetCurrentProcess(), VmPageDirtyStateInformation,
                                                1, &range, &flag, sizeof(flag) );
    case 5: size = 0; return NtFreeVirtualMemory( GetCurrentProcess(), &base, &size, MEM_RELEASE );
    case 6: return NtFreeVirtualMemory( GetCurrentProcess(), &base, &size, MEM_DECOMMIT );
    case 7: return NtUnmapViewOfSection( GetCurrentProcess(), base );
    }
    return STATUS_INVALID_PARAMETER;
}
static void pipe_transfer( HANDLE pipe, void *packet, BOOL write )
{
    DWORD count;
    BOOL result = write ? WriteFile( pipe, packet, sizeof(struct packet), &count, NULL ) :
                          ReadFile( pipe, packet, sizeof(struct packet), &count, NULL );
    if (!result || count != sizeof(struct packet)) fatal( "fixed-size pipe transfer" );
}
static int child_main( const char *role, const char *pipe_name, const char *observation_name )
{
    struct packet packet;
    HANDLE pipe;
    {
        HANDLE observation = OpenFileMappingA( FILE_MAP_ALL_ACCESS, FALSE, observation_name );
        if (!observation || !(loop_observation = MapViewOfFile( observation, FILE_MAP_ALL_ACCESS, 0, 0, 0 )))
            fatal( "map shared completion observation" );
        CloseHandle( observation );
        if (!strcmp( role, "executor" ) &&
            ((ULONG_PTR)loop_observation < WINE_MANAGED_HOST_ALLOC_START ||
             (ULONG_PTR)loop_observation >= WINE_MANAGED_HOST_END))
            fatal( "executor observation escaped host domain" );
    }
    if (!AddVectoredExceptionHandler( 1, fault_handler )) fatal( "install actual exception observer" );
    if (!(pipe = CreateFileA( pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             OPEN_EXISTING, 0, NULL )) || pipe == INVALID_HANDLE_VALUE)
        fatal( "open child pipe" );
    memset( &packet, 0, sizeof(packet) );
    packet.value = GetCurrentProcessId();
    packet.status = native_helper( 2, 0, &packet.native_pid );
    if (packet.status) fatal( "native fixture companion failed to report Linux PID" );
    packet.status = !strcmp( role, "executor" ) &&
                    (ULONG_PTR)GetModuleHandleA( "ntdll.dll" ) != WINE_MANAGED_HOST_NTDLL_START ?
                    STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
    pipe_transfer( pipe, &packet, TRUE );
    return child_loop( pipe );
}
static int child_loop( HANDLE pipe )
{
    struct packet packet;
    DWORD old;
    void *pointer;
    for (;;)
    {
        pipe_transfer( pipe, &packet, FALSE );
        packet.status = STATUS_SUCCESS;
        switch (packet.command)
        {
        case CMD_ALLOC:
            pointer = VirtualAlloc( PROBE_ADDRESS, PROBE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
            if (pointer != PROBE_ADDRESS) packet.status = STATUS_CONFLICTING_ADDRESSES;
            else
            {
                *(volatile BYTE *)pointer = packet.value;
                *((volatile BYTE *)pointer + PROBE_SIZE - 1) = packet.value;
            }
            break;
        case CMD_READ: packet.value = probe_read( (BYTE *)PROBE_ADDRESS + packet.offset ); break;
        case CMD_WRITE: packet.value = probe_write( (BYTE *)PROBE_ADDRESS + packet.offset, packet.value ); break;
        case CMD_WATCH_NATIVE_PID:
            packet.status = native_helper( 3, packet.value, NULL );
            if (!packet.status) watch_native_death = TRUE;
            break;
        case CMD_PROTECT:
            if (!VirtualProtect( (BYTE *)PROBE_ADDRESS + packet.offset, packet.size ? packet.size : PROBE_SIZE, packet.value, &old ))
                packet.status = STATUS_UNSUCCESSFUL;
            else if (watch_native_death)
            {
                packet.status = native_helper( 4, 0, NULL );
                packet.native_dead = !packet.status;
                watch_native_death = FALSE;
            }
            break;
        case CMD_DECOMMIT:
            if (!VirtualFree( (BYTE *)PROBE_ADDRESS + packet.offset, packet.size ? packet.size : PROBE_SIZE, MEM_DECOMMIT )) packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_COMMIT:
            if (VirtualAlloc( PROBE_ADDRESS, PROBE_SIZE, MEM_COMMIT, PAGE_READWRITE ) != PROBE_ADDRESS)
                packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_FREE:
            if (!VirtualFree( PROBE_ADDRESS, 0, MEM_RELEASE )) packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_ACQUIRE: packet.status = acquire_lease( &packet, TRUE ); break;
        case CMD_BEGIN_ACQUIRE:
            if (acquire_thread || lease.handle) { packet.status = STATUS_INVALID_HANDLE; break; }
            acquire_packet = packet; acquire_status = STATUS_PENDING;
            InterlockedExchange( &loop_observation->acquire_go, 0 );
            acquire_thread = CreateThread( NULL, 0, acquire_worker, NULL, 0, NULL );
            if (!acquire_thread) packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_END_ACQUIRE:
            if (!acquire_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            if (WaitForSingleObject( acquire_thread, TIMEOUT ) != WAIT_OBJECT_0)
                fatal( "async acquisition did not finish" );
            CloseHandle( acquire_thread ); acquire_thread = NULL;
            packet.status = acquire_status ? acquire_status : wait_lease( &packet );
            break;
        case CMD_DROP: packet.status = drop_lease( &packet ); break;
        case CMD_QUERY: packet.status = query_lease( &packet ); break;
        case CMD_OWNER_STATE: packet.status = owner_state( &packet ); break;
        case CMD_COLLISION_INSTALL: packet.status = native_helper( 0, (ULONG_PTR)PROBE_ADDRESS, NULL ); break;
        case CMD_COLLISION_REMOVE: packet.status = native_helper( 1, (ULONG_PTR)PROBE_ADDRESS, NULL ); break;
        case CMD_DENIED_ACQUIRE: packet.status = denied_acquire( &packet ); break;
        case CMD_STALE_QUERY: packet.status = stale_query( packet.value ); break;
        case CMD_NEGATIVE_VM: packet.status = negative_alias_vm( packet.value ); break;
        case CMD_CANCEL_BEGIN:
            if (cancelled_main || packet.offset > 1) { packet.status = STATUS_INVALID_PARAMETER; break; }
            if (!DuplicateHandle( GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                                  &cancelled_main, 0, FALSE, DUPLICATE_SAME_ACCESS ))
                fatal( "duplicate native-barrier recipient handle" );
            cancelled_main_tid = GetCurrentThreadId(); cancel_pipe = pipe; cancel_packet = packet;
            packet.count = cancelled_main_tid;
            {
                HANDLE survivor = CreateThread( NULL, 0, cancel_survivor, NULL, 0, NULL );
                if (!survivor) fatal( "create independent cancellation survivor" );
                CloseHandle( survivor );
            }
            pipe_transfer( pipe, &packet, TRUE );
            if (native_helper( 5, packet.offset, NULL )) fatal( "native recipient barrier failed" );
            fatal( "native recipient barrier returned without termination" );
            break;
        case CMD_CANCEL_END:
            packet.count = cancelled_main_tid;
            packet.status = cancel_packet.offset ? STATUS_SUCCESS :
                            (acquire_status ? acquire_status : wait_lease( &packet ));
            break;
        case CMD_SUSPENDED_CREATE:
            if (suspended_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            suspended_thread = CreateThread( NULL, 0, suspended_worker, NULL, CREATE_SUSPENDED, NULL );
            if (!suspended_thread || WaitForSingleObject( suspended_thread, 0 ) != WAIT_TIMEOUT)
                packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_SUSPENDED_KILL:
            if (!suspended_thread || !TerminateThread( suspended_thread, 0x51 ))
                fatal( "terminate suspended queued-APC recipient" );
            if (WaitForSingleObject( suspended_thread, TIMEOUT ) != WAIT_OBJECT_0)
                fatal( "suspended queued-APC recipient did not terminate" );
            CloseHandle( suspended_thread ); suspended_thread = NULL;
            break;
        case CMD_CPU_BARRIER:
            {
                DWORD start = GetTickCount();
                InterlockedExchange( &loop_observation->cpu_active, 1 );
                while (!InterlockedCompareExchange( &loop_observation->release_cpu, 0, 0 ) &&
                       GetTickCount() - start < TIMEOUT) YieldProcessor();
                if (!loop_observation->release_cpu) fatal( "executor CPU barrier timed out" );
                InterlockedExchange( &loop_observation->cpu_active, 0 );
            }
            break;
        case CMD_MUTATION_BEGIN:
            if (mutation_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            mutation_protection = packet.value; mutation_status = STATUS_PENDING;
            loop_observation->mutation_go = loop_observation->mutation_done = 0;
            loop_observation->owner_updating = loop_observation->observer_ready = 0;
            mutation_observer = CreateThread( NULL, 0, observe_mutation, NULL, 0, NULL );
            if (!mutation_observer) fatal( "create owner fence observer" );
            mutation_thread = CreateThread( NULL, 0, mutation_worker, NULL, 0, NULL );
            if (!mutation_thread) packet.status = STATUS_UNSUCCESSFUL;
            break;
        case CMD_MUTATION_POLL:
            if (!mutation_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            packet.status = WaitForSingleObject( mutation_thread, 0 ) == WAIT_TIMEOUT ?
                            STATUS_PENDING : mutation_status;
            break;
        case CMD_MUTATION_WAIT:
            if (!mutation_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            if (WaitForSingleObject( mutation_thread, TIMEOUT ) != WAIT_OBJECT_0)
                fatal( "async target mutation did not finish" );
            packet.status = mutation_status;
            if (WaitForSingleObject( mutation_observer, TIMEOUT ) != WAIT_OBJECT_0)
                fatal( "owner fence observer did not finish" );
            CloseHandle( mutation_observer ); mutation_observer = NULL;
            CloseHandle( mutation_thread ); mutation_thread = NULL;
            break;
        case CMD_LOOP:
            if (loop_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            loop_reads = loop_faults = loop_stop = 0;
            loop_observation->reads = loop_observation->faults = 0;
            loop_thread = CreateThread( NULL, 0, read_loop, NULL, 0, NULL );
            if (!loop_thread) packet.status = STATUS_UNSUCCESSFUL;
            else
            {
                DWORD start = GetTickCount();
                while (!InterlockedCompareExchange( &loop_reads, 0, 0 ) &&
                       !InterlockedCompareExchange( &loop_faults, 0, 0 ) &&
                       GetTickCount() - start < TIMEOUT) Sleep( 0 );
                packet.count = loop_reads;
                packet.faults = loop_faults;
                if (!packet.count) packet.status = STATUS_UNSUCCESSFUL;
            }
            break;
        case CMD_LOOP_RESULT:
            if (!loop_thread) { packet.status = STATUS_INVALID_HANDLE; break; }
            /* Join proves the active ordinary pointer loop faulted after revoke.
             * Never substitute a parent stop flag for the expected fault. */
            if (WaitForSingleObject( loop_thread, TIMEOUT ) != WAIT_OBJECT_0)
                fatal( "revoked read-loop never faulted" );
            packet.count = loop_reads;
            packet.faults = loop_faults;
            CloseHandle( loop_thread ); loop_thread = NULL;
            break;
        case CMD_EXIT:
            pipe_transfer( pipe, &packet, TRUE );
            CloseHandle( pipe );
            /* Deliberately retain a live view: process teardown must release it. */
            return 0;
        default: packet.status = STATUS_INVALID_PARAMETER; break;
        }
        pipe_transfer( pipe, &packet, TRUE );
    }
}
static struct child spawn_child( const char *role, unsigned int index )
{
    struct child child;
    STARTUPINFOA startup;
    PROCESS_INFORMATION info;
    char exe[MAX_PATH], pipe_name[128], observation_name[128], command_line[2 * MAX_PATH + 512];
    DWORD length;
    const char *setting, *backing = getenv( "A1B_DISABLE_BACKING" ) ? NULL : "1";
    NTSTATUS (WINAPI *set_unix_env)( const char *, const char * );
    memset( &child, 0, sizeof(child) );
    memset( &startup, 0, sizeof(startup) ); startup.cb = sizeof(startup);
    length = GetModuleFileNameA( NULL, exe, sizeof(exe) );
    if (!length || length >= sizeof(exe)) fatal( "obtain complete executable path" );
    if (!strcmp( role, "executor" ))
    {
        char *name = strrchr( exe, '\\' );
        if (!name || strlen(exe) + strlen("executor\\") >= sizeof(exe))
            fatal( "executor host-image path unavailable" );
        memmove( name + 1 + strlen("executor\\"), name + 1, strlen(name + 1) + 1 );
        memcpy( name + 1, "executor\\", strlen("executor\\") );
    }
    sprintf( observation_name, "a1b-live-view-observation-%lu", GetCurrentProcessId() );
    sprintf( pipe_name, "\\\\.\\pipe\\a1b-live-view-%lu-%u", GetCurrentProcessId(), index );
    child.pipe = CreateNamedPipeA( pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT,
                                  1, 4096, 4096, TIMEOUT, NULL );
    if (child.pipe == INVALID_HANDLE_VALUE) fatal( "create parent pipe" );
    sprintf( command_line, "\"%s\" %s \"%s\" \"%s\"", exe, role, pipe_name, observation_name );
    setting = !strcmp( role, "executor" ) ? WINE_MANAGED_EXECUTOR_SETTING : WINE_MANAGED_LAYOUT_SETTING;
    set_unix_env = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "__wine_set_unix_env" );
    if (!set_unix_env || set_unix_env( "WINE_MANAGED_LAYOUT", setting ) ||
        set_unix_env( "WINE_SHARED_PRIVATE_BACKING", backing ) ||
        !SetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", setting ) ||
        !SetEnvironmentVariableA( "WINE_SHARED_PRIVATE_BACKING", backing ))
        fatal( "set actual preloader and Wine backing environments" );
    if (!CreateProcessA( NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info ))
        fatal( "start preloader-managed child" );
    if (set_unix_env( "WINE_MANAGED_LAYOUT", NULL ) ||
        !SetEnvironmentVariableA( "WINE_MANAGED_LAYOUT", NULL ))
        fatal( "clear actual preloader role after child launch" );
    CloseHandle( info.hThread );
    child.process = info.hProcess; child.pid = info.dwProcessId; child.role = role;
    if (!ConnectNamedPipe( child.pipe, NULL ) && GetLastError() != ERROR_PIPE_CONNECTED)
        fatal( "connect parent pipe" );
    {
        struct packet packet;
        pipe_transfer( child.pipe, &packet, FALSE );
        child.native_pid = packet.native_pid;
        check( !packet.status && packet.native_pid && packet.value == child.pid, "child managed-role boot and PID handshake" );
        if (packet.status) fatal( "managed child boot rejected" );
    }
    printf( "a1b-live-private-view: %s wine_pid=%lu linux_pid=%lu\n", role, child.pid, child.native_pid );
    return child;
}
static struct packet request_range( struct child *child, unsigned int command, unsigned int value, DWORD target_pid, unsigned int offset, unsigned int size )
{
    struct packet packet;
    memset( &packet, 0, sizeof(packet) );
    packet.command = command; packet.value = value; packet.target_pid = target_pid;
    packet.offset = offset; packet.size = size;
    pipe_transfer( child->pipe, &packet, TRUE );
    pipe_transfer( child->pipe, &packet, FALSE );
    printf( "a1b-live-private-view: pid=%lu command=%u status=%#x value=%#x state=%u result=%#x "
            "token=%I64u generation=%I64u mapping=%I64u reads=%u faults=%u native_dead=%u\n", child->pid, command,
            packet.status, packet.value, packet.state, packet.lease_status,
            packet.token, packet.generation, packet.mapping_id, packet.count, packet.faults, packet.native_dead );
    if (command == CMD_BEGIN_ACQUIRE && !packet.status)
        InterlockedExchange( &loop_observation->acquire_go, 1 );
    if (command == CMD_MUTATION_BEGIN && !packet.status)
        InterlockedExchange( &loop_observation->mutation_go, 1 );
    return packet;
}
static struct packet request( struct child *child, unsigned int command, unsigned int value, DWORD target_pid )
{
    return request_range( child, command, value, target_pid, 0, 0 );
}
static void operation( struct child *child, unsigned int command, unsigned int value, const char *description )
{
    struct packet packet = request( child, command, value, 0 );
    check( !packet.status, description );
    if (packet.status) fatal( description );
}
static void read_value( struct child *child, unsigned int value, const char *description )
{
    struct packet packet = request( child, CMD_READ, 0, 0 );
    check( !packet.status && packet.value == value, description );
}
static void write_value( struct child *child, unsigned int value, unsigned int result, const char *description )
{
    struct packet packet = request( child, CMD_WRITE, value, 0 );
    check( !packet.status && packet.value == result, description );
}
static struct packet acquire( struct child *executor, struct child *target, unsigned int access )
{
    struct packet packet = request( executor, CMD_ACQUIRE, access, target->pid );
    check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_LIVE && !packet.lease_status,
           "acknowledged live lease" );
    if (packet.status || packet.state != PRIVATE_MAPPING_LEASE_LIVE || packet.lease_status)
        fatal( "lease failed admission" );
    return packet;
}
static void drop( struct child *executor )
{
    struct packet packet = request( executor, CMD_DROP, 0, 0 );
    check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED,
           "explicit lease release waits for acknowledged revoke" );
    if (packet.status || packet.state != PRIVATE_MAPPING_LEASE_REVOKED) fatal( "lease failed revoke" );
    read_value( executor, PROBE_FAULT, "ordinary read faults after acknowledged revoke" );
    write_value( executor, 0x97, PROBE_FAULT, "ordinary write faults after acknowledged revoke" );
    packet = request_range( executor, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
    check( !packet.status && packet.value == PROBE_FAULT, "final-byte read faults after acknowledged revoke" );
    packet = request_range( executor, CMD_WRITE, 0x97, 0, PROBE_SIZE - 1, 0 );
    check( !packet.status && packet.value == PROBE_FAULT, "final-byte write faults after acknowledged revoke" );
}
static void exit_child( struct child *child )
{
    DWORD exit_code;
    operation( child, CMD_EXIT, 0, "child requests clean process termination" );
    if (WaitForSingleObject( child->process, TIMEOUT ) != WAIT_OBJECT_0)
        fatal( "process exit was not observable within bound" );
    check( GetExitCodeProcess( child->process, &exit_code ) && !exit_code,
           "Wine-observable child process termination" );
    CloseHandle( child->process ); CloseHandle( child->pipe );
    child->process = child->pipe = NULL;
}
static void active_loop_revoke( struct child *executor, struct child *target, unsigned int command,
                                unsigned int value, const char *description )
{
    struct packet packet;
    InterlockedExchange( &loop_observation->completed, 0 );
    InterlockedExchange( &loop_observation->successful_after_completion, 0 );
    packet = request( executor, CMD_LOOP, 0, 0 );
    check( !packet.status && packet.count && !packet.faults, "active loop executes successful ordinary reads" );
    if (packet.status) fatal( "start active read-loop" );
    operation( target, command, value, description );
    InterlockedExchange( &loop_observation->completed, 1 );
    packet = request( executor, CMD_LOOP_RESULT, 0, 0 );
    check( !packet.status && packet.count && packet.faults == 1,
           "ordinary active executor read-loop faults following target mutation" );
    check( !loop_observation->successful_after_completion,
           "active ordinary loop observes no successful read started after mutation completion" );
    read_value( executor, PROBE_FAULT, "completed target mutation leaves direct read inaccessible" );
    packet = request_range( executor, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
    check( !packet.status && packet.value == PROBE_FAULT,
           "completed target mutation revokes final alias byte before explicit release" );
}
static void marker_path( char *path, const char *name, const char *phase )
{
    const char *directory = getenv( "A1B_VIEW_GATE_DIR" );
    if (!directory || strlen(directory) > MAX_PATH - 50) fatal( "native gate directory unavailable" );
    sprintf( path, "Z:%s/%s-%s", directory, name, phase );
}
static void marker_create( const char *name, const char *phase )
{
    char path[MAX_PATH];
    HANDLE file;
    marker_path( path, name, phase );
    file = CreateFileA( path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if (file == INVALID_HANDLE_VALUE) fatal( "create native test marker" );
    CloseHandle( file );
}
static void marker_identity( const char *phase, DWORD pid, DWORD tid )
{
    char path[MAX_PATH], identity[64];
    DWORD count, length;
    HANDLE file;
    marker_path( path, "armed", phase );
    length = sprintf( identity, "%04lx %04lx\n", pid, tid );
    file = CreateFileA( path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if (file == INVALID_HANDLE_VALUE || !WriteFile( file, identity, length, &count, NULL ) || count != length)
        fatal( "write authoritative cancellation identity marker" );
    CloseHandle( file );
}
static void marker_wait( const char *name, const char *phase )
{
    char path[MAX_PATH];
    DWORD start = GetTickCount();
    marker_path( path, name, phase );
    while (GetFileAttributesA( path ) == INVALID_FILE_ATTRIBUTES && GetTickCount() - start < 1500) Sleep( 1 );
    if (GetFileAttributesA( path ) == INVALID_FILE_ATTRIBUTES) fatal( "native syscall gate was never entered" );
}
static void marker_delete( const char *name, const char *phase )
{
    char path[MAX_PATH];
    marker_path( path, name, phase );
    DeleteFileA( path );
}
static void revoke_ack_barrier( struct child *executor, struct child *target )
{
    struct packet packet;
    LONG before;
    if (!getenv( "A1B_VIEW_GATE_DIR" ))
    {
        fprintf( stderr, "a1b-live-private-view: strict native ACK barrier NOT RUN (no native injector)\n" );
        return;
    }
    acquire( executor, target, FILE_READ_DATA | FILE_WRITE_DATA );
    InterlockedExchange( &loop_observation->completed, 0 );
    InterlockedExchange( &loop_observation->successful_after_completion, 0 );
    packet = request( executor, CMD_LOOP, 0, 0 );
    check( !packet.status && packet.count && !packet.faults, "active read-loop before withheld revoke syscall" );
    marker_delete( "entered", "revoke" ); marker_delete( "release", "revoke" );
    marker_create( "gate", "revoke" );
    operation( target, CMD_MUTATION_BEGIN, PAGE_READONLY, "start target protection asynchronously" );
    marker_wait( "entered", "revoke" );
    check( !loop_observation->mutation_done,
           "target mutation cannot complete while native revoke and ACK are withheld" );
    check( !loop_observation->completed, "withheld revoke leaves mutation completion unpublished" );
    before = InterlockedCompareExchange( &loop_observation->reads, 0, 0 );
    Sleep( 20 );
    check( InterlockedCompareExchange( &loop_observation->reads, 0, 0 ) > before &&
           !loop_observation->faults, "executor keeps ordinary live reads while owner mutation is blocked" );
    marker_create( "release", "revoke" );
    operation( target, CMD_MUTATION_WAIT, 0, "target protection succeeds after permitting native revoke and ACK" );
    InterlockedExchange( &loop_observation->completed, 1 );
    packet = request( executor, CMD_LOOP_RESULT, 0, 0 );
    check( !packet.status && packet.faults == 1 && !loop_observation->successful_after_completion,
           "acknowledged mutation makes active ordinary reader inaccessible" );
    drop( executor );
    operation( target, CMD_PROTECT, PAGE_READWRITE, "restore target after revoke ACK barrier" );
}
static void rejected_executor_vm( struct child *executor, struct child *target )
{
    static const char *names[] = { "COMMIT", "RESET", "EXECUTE protection", "overlapping section",
                                  "dirty-state reset", "RELEASE", "DECOMMIT", "unmap" };
    struct packet before = request( executor, CMD_QUERY, 0, 0 ), packet;
    unsigned int i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        packet = request( executor, CMD_NEGATIVE_VM, i, 0 );
        check( packet.status == (unsigned int)STATUS_ACCESS_DENIED ||
               packet.status == (unsigned int)STATUS_INVALID_PARAMETER ||
               packet.status == (unsigned int)STATUS_CONFLICTING_ADDRESSES ||
               (i == 4 && packet.status == (unsigned int)STATUS_NOT_SUPPORTED), names[i] );
        if (!packet.status) fatal( "executor mutation unexpectedly changed foreign view" );
        read_value( executor, 0x71, "rejected executor VM operation preserves ordinary live alias byte" );
        read_value( target, 0x71, "rejected executor VM operation preserves target private byte" );
        packet = request( executor, CMD_QUERY, 0, 0 );
        check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_LIVE &&
               packet.token == before.token && packet.generation == before.generation &&
               packet.mapping_id == before.mapping_id,
               "rejected executor VM operation preserves live lease identity and generation" );
    }
}
/* Process-wide system APC routing does not guarantee that a suspended
 * auxiliary thread receives a particular MAP/REVOKE. This fixture checks
 * surviving-process lifetime without claiming deterministic queued-APC
 * cancellation. The separate native-barrier cases below test that contract. */
static void consumer_thread_lifetime( struct child *executor, struct child *target )
{
    operation( executor, CMD_SUSPENDED_CREATE, 0, "create auxiliary consumer thread before admission" );
    operation( executor, CMD_SUSPENDED_KILL, 0, "terminate auxiliary thread while consumer main survives" );
    acquire( executor, target, FILE_READ_DATA | FILE_WRITE_DATA );
    read_value( executor, 0x71, "surviving consumer acquires ordinary live view after auxiliary thread exit" );
    operation( executor, CMD_SUSPENDED_CREATE, 0, "create auxiliary consumer thread while lease is live" );
    operation( executor, CMD_SUSPENDED_KILL, 0, "auxiliary thread exit does not destroy process-owned live lease" );
    read_value( executor, 0x71, "consumer ordinary pointer stays coherent after auxiliary thread exit" );
    operation( target, CMD_PROTECT, PAGE_READONLY, "owner mutation revokes surviving consumer after auxiliary thread exit" );
    check( WaitForSingleObject( executor->process, 0 ) == WAIT_TIMEOUT,
           "surviving consumer was not terminated as a revocation shortcut" );
    read_value( executor, PROBE_FAULT, "surviving consumer pointer faults after owner mutation" );
    drop( executor );
    operation( target, CMD_PROTECT, PAGE_READWRITE, "restore target after consumer thread lifetime case" );
}
static void queued_recipient_cancel( struct child *target, unsigned int phase )
{
    struct child executor = spawn_child( "executor", 20 + phase );
    struct packet packet;
    const char *name = phase ? "revoke" : "map";
    marker_delete( "parked", name ); marker_delete( "kill", name );
    marker_delete( "queued", name ); marker_delete( "verified", name ); marker_delete( "armed", name );
    if (phase) acquire( &executor, target, FILE_READ_DATA | FILE_WRITE_DATA );
    packet = request_range( &executor, CMD_CANCEL_BEGIN, FILE_READ_DATA | FILE_WRITE_DATA,
                            target->pid, phase, 0 );
    check( !packet.status && packet.count, "cancellation fixture advertises exact oldest recipient TID" );
    if (packet.status || !packet.count) fatal( "begin native recipient barrier" );
    marker_identity( name, executor.pid, packet.count );
    printf( "a1b-live-private-view: cancellation-armed op=%s recipient_pid=%04lx recipient_tid=%04x\n",
            phase ? "REVOKE" : "MAP", executor.pid, packet.count );
    marker_wait( "parked", name );
    if (phase)
    {
        operation( target, CMD_MUTATION_BEGIN, PAGE_READONLY, "start owner mutation for queued REVOKE cancellation" );
        marker_wait( "queued", name );
        {
            DWORD start = GetTickCount();
            while (!loop_observation->owner_updating && GetTickCount() - start < 1000) Sleep( 1 );
        }
        check( loop_observation->owner_updating && !loop_observation->mutation_done,
               "queued REVOKE leaves authoritative owner fence pending before recipient death" );
        if (!loop_observation->owner_updating || loop_observation->mutation_done)
            fatal( "queued REVOKE did not preserve owner fence" );
        marker_create( "verified", name );
    }
    packet = request( &executor, CMD_CANCEL_END, 0, 0 );
    check( !packet.status, "survivor command controller responds after queued recipient death" );
    check( WaitForSingleObject( executor.process, 0 ) == WAIT_TIMEOUT,
           "queued recipient cancellation preserves surviving executor process" );
    if (!phase)
    {
        check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED &&
               packet.lease_status == (unsigned int)STATUS_CANCELLED,
               "queued MAP recipient death cancels lease instead of admitting an alias" );
    }
    else
    {
        operation( target, CMD_MUTATION_WAIT, 0, "owner mutation drains after REVOKE retry to survivor and native ACK" );
        packet = request( &executor, CMD_QUERY, 0, 0 );
        check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED,
               "cancelled queued REVOKE ultimately reaches acknowledged revoked lease" );
    }
    read_value( &executor, PROBE_FAULT, "queued recipient cancellation leaves no readable alias" );
    write_value( &executor, 0x96, PROBE_FAULT, "queued recipient cancellation leaves no writable alias" );
    drop( &executor );
    if (phase) operation( target, CMD_PROTECT, PAGE_READWRITE, "restore target after queued REVOKE cancellation" );
    acquire( &executor, target, FILE_READ_DATA | FILE_WRITE_DATA );
    read_value( &executor, 0x41, "survivor acquires healthy later lease after queued cancellation" );
    drop( &executor ); exit_child( &executor );
}
static int cancellation_main( unsigned int phases )
{
    struct child target;
    HANDLE observation;
    char name[128];
    sprintf( name, "a1b-live-view-observation-%lu", GetCurrentProcessId() );
    observation = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                     sizeof(*loop_observation), name );
    if (!observation || !(loop_observation = MapViewOfFile( observation, FILE_MAP_ALL_ACCESS, 0, 0, 0 )))
        fatal( "create cancellation observation" );
    target = spawn_child( "target", 19 );
    operation( &target, CMD_ALLOC, 0x41, "target allocates coherent backing for cancellation cases" );
    if (phases & 1) queued_recipient_cancel( &target, 0 );
    if (phases & 2) queued_recipient_cancel( &target, 1 );
    operation( &target, CMD_FREE, 0, "target releases backing after queued cancellation cases" );
    exit_child( &target );
    UnmapViewOfFile( loop_observation ); CloseHandle( observation );
    printf( "a1b-live-private-view: %ld checks, %ld failures (queued cancellation)\n", checks, failures );
    return !!failures;
}
static void pending_acquire_race( struct child *executor, struct child *target )
{
    struct packet packet;
    DWORD start;
    if (!getenv( "A1B_VIEW_GATE_DIR" )) return;
    marker_delete( "entered", "map" ); marker_delete( "release", "map" );
    marker_create( "gate", "map" );
    packet = request( executor, CMD_BEGIN_ACQUIRE, FILE_READ_DATA | FILE_WRITE_DATA, target->pid );
    check( !packet.status, "start asynchronous lease acquisition before native map gate" );
    if (packet.status) fatal( "begin gated acquire" );
    marker_wait( "entered", "map" );
    operation( target, CMD_MUTATION_BEGIN, PAGE_READONLY, "start target mutation while lease MAP remains pending" );
    start = GetTickCount();
    do
    {
        if (!loop_observation->owner_updating) Sleep( 1 );
    } while (!loop_observation->owner_updating && GetTickCount() - start < 1000);
    check( loop_observation->owner_updating, "authoritative owner transaction fences pending acquisition before map resumes" );
    check( !loop_observation->mutation_done,
           "owner mutation waits for pending lease revocation" );
    marker_create( "release", "map" );
    packet = request( executor, CMD_END_ACQUIRE, 0, 0 );
    check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED &&
           packet.lease_status == (unsigned int)STATUS_CANCELLED,
           "raced MAP never admits live lease and revokes before ready notification" );
    operation( target, CMD_MUTATION_WAIT, 0, "pending-acquire owner mutation drains after acknowledged revoke" );
    read_value( executor, PROBE_FAULT, "pending-acquire race leaves no readable alias" );
    write_value( executor, 0x93, PROBE_FAULT, "pending-acquire race leaves no writable alias" );
    drop( executor );
    operation( target, CMD_PROTECT, PAGE_READWRITE, "restore target after pending acquire race" );
}
static void injected_map_failure( struct child *executor, struct child *target )
{
    struct packet packet;
    if (!getenv( "A1B_VIEW_GATE_DIR" )) return;
    marker_delete( "entered", "map" ); marker_create( "arm", "map" );
    packet = request( executor, CMD_ACQUIRE, FILE_READ_DATA | FILE_WRITE_DATA, target->pid );
    marker_wait( "entered", "map" );
    check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED &&
           packet.lease_status == (unsigned int)STATUS_NO_MEMORY,
           "native injected alias mmap failure is explicit and never admits a live lease" );
    read_value( executor, PROBE_FAULT, "failed native mmap restores inaccessible executor reservation" );
    read_value( target, 0x41, "failed alias mmap preserves owning target contents" );
    if (!packet.status) drop( executor );
}
static void injected_revoke_failure( struct child *target )
{
    struct child executor;
    DWORD exit_code;
    if (!getenv( "A1B_VIEW_GATE_DIR" )) return;
    executor = spawn_child( "executor", 4 );
    acquire( &executor, target, FILE_READ_DATA | FILE_WRITE_DATA );
    read_value( &executor, 0x62, "disposable executor reads target before injected revoke failure" );
    operation( target, CMD_WATCH_NATIVE_PID, executor.native_pid,
               "target opens native pidfd before requesting executor revocation" );
    marker_delete( "entered", "revoke" ); marker_create( "arm", "revoke" );
    {
        struct packet packet = request( target, CMD_PROTECT, PAGE_READONLY, 0 );
        check( !packet.status && packet.native_dead,
               "owner mutation completion observes native executor death through preopened pidfd" );
        if (packet.status || !packet.native_dead) fatal( "owner completion preceded native executor death" );
    }
    marker_wait( "entered", "revoke" );
    if (WaitForSingleObject( executor.process, TIMEOUT ) != WAIT_OBJECT_0)
        fatal( "failed-revoke executor never terminates" );
    check( GetExitCodeProcess( executor.process, &exit_code ) && exit_code,
           "failed native revoke fail-stops executor rather than acknowledging stale readable view" );
    read_value( target, 0x62, "failed revoke preserves owning target's private contents" );
    write_value( target, 0x98, PROBE_FAULT, "post-death owner mutation applies requested protection" );
    CloseHandle( executor.process ); CloseHandle( executor.pipe );
    operation( target, CMD_PROTECT, PAGE_READWRITE, "restore target after executor fail-stop" );
}
static int parent_main(void)
{
    struct child a, b, executor;
    struct packet initial, reused;
    HANDLE observation;
    char observation_name[128];
    sprintf( observation_name, "a1b-live-view-observation-%lu", GetCurrentProcessId() );
    observation = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                     sizeof(*loop_observation), observation_name );
    if (!observation || !(loop_observation = MapViewOfFile( observation, FILE_MAP_ALL_ACCESS, 0, 0, 0 )))
        fatal( "create shared completion observation" );
    a = spawn_child( "target", 1 ); b = spawn_child( "target", 2 );
    executor = spawn_child( "executor", 3 );
    operation( &a, CMD_ALLOC, 0x41, "target A reserves private bytes at original address" );
    operation( &b, CMD_ALLOC, 0x42, "target B reserves different private bytes at same address" );
    read_value( &executor, PROBE_FAULT, "executor guest address initially inaccessible" );
    operation( &executor, CMD_COLLISION_INSTALL, 0, "install separate benign native collision in reserved guest range" );
    read_value( &executor, 0xcc, "ordinary executor pointer sees native collision sentinel" );
    {
        struct packet packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA | FILE_WRITE_DATA, a.pid );
        check( packet.status == (unsigned int)STATUS_CONFLICTING_ADDRESSES ||
               (!packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED &&
                packet.lease_status == (unsigned int)STATUS_CONFLICTING_ADDRESSES),
               "existing mapping collision rejects acquisition explicitly" );
        read_value( &executor, 0xcc, "failed alias admission preserves existing collision bytes" );
        read_value( &a, 0x41, "collision rejection preserves original target bytes" );
        if (!packet.status)
        {
            packet = request( &executor, CMD_DROP, 0, 0 );
            check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED,
                   "failed collision lease cleans up without overwriting existing native mapping" );
            read_value( &executor, 0xcc, "failed lease cleanup preserves existing collision mapping" );
        }
    }
    operation( &executor, CMD_COLLISION_REMOVE, 0, "remove owned native collision and restore noaccess reservation" );
    read_value( &executor, PROBE_FAULT, "removed collision leaves original guest range inaccessible" );
    injected_map_failure( &executor, &a );
    {
        struct packet packet = request( &executor, CMD_DENIED_ACQUIRE, 0, a.pid );
        check( packet.status == (unsigned int)STATUS_ACCESS_DENIED,
               "insufficient target process handle rights deny alias admission" );
        memset( &packet, 0, sizeof(packet) );
        packet.target_pid = a.pid; packet.value = FILE_READ_DATA;
        check( acquire_lease( &packet, FALSE ) == STATUS_NOT_SUPPORTED,
               "ordinary default-mode consumer cannot acquire managed target alias" );
    }
    initial = acquire( &executor, &a, FILE_READ_DATA | FILE_WRITE_DATA );
    {
        struct packet packet = request( &executor, CMD_STALE_QUERY, 0, 0 );
        check( packet.status == (unsigned int)STATUS_INVALID_PARAMETER, "stale lease token is rejected" );
        packet = request( &executor, CMD_STALE_QUERY, 1, 0 );
        check( packet.status == (unsigned int)STATUS_INVALID_PARAMETER, "stale lease generation is rejected" );
        packet = request( &executor, CMD_QUERY, 0, 0 );
        check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_LIVE &&
               packet.token == initial.token && packet.generation == initial.generation,
               "rejected stale requests preserve the acknowledged live lease" );
    }
    read_value( &executor, 0x41, "ordinary executor pointer sees A's live byte" );
    {
        struct packet packet = request_range( &executor, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
        check( !packet.status && packet.value == 0x41, "ordinary alias read reaches final backing byte" );
        packet = request_range( &executor, CMD_WRITE, 0x63, 0, PROBE_SIZE - 1, 0 );
        check( !packet.status && !packet.value, "ordinary alias write reaches final backing byte" );
        packet = request_range( &a, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
        check( !packet.status && packet.value == 0x63, "target final byte sees executor store" );
        packet = request_range( &b, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
        check( !packet.status && packet.value == 0x42, "other target final byte stays private" );
    }
    write_value( &executor, 0x61, 0, "ordinary executor store writes A's backing" );
    read_value( &a, 0x61, "A immediately sees executor store" );
    read_value( &b, 0x42, "same-VA B remains private after executor store" );
    write_value( &a, 0x71, 0, "A stores through its original pointer" );
    read_value( &executor, 0x71, "executor immediately sees A's later store" );
    rejected_executor_vm( &executor, &a );
    drop( &executor );
    acquire( &executor, &b, FILE_READ_DATA | FILE_WRITE_DATA );
    read_value( &executor, 0x42, "switching lease sees B's distinct live contents" );
    write_value( &executor, 0x62, 0, "executor writes B's backing" );
    read_value( &b, 0x62, "B sees executor store" );
    read_value( &a, 0x71, "A remains isolated from B's store" );
    drop( &executor );
    acquire( &executor, &a, FILE_READ_DATA );
    read_value( &executor, 0x71, "read-only admitted lease reads ordinary memory" );
    write_value( &executor, 0x99, PROBE_FAULT, "read-only lease rejects ordinary write" );
    read_value( &a, 0x71, "failed read-only alias write preserves target bytes" );
    drop( &executor );

    consumer_thread_lifetime( &executor, &a );
    pending_acquire_race( &executor, &a );
    revoke_ack_barrier( &executor, &a );
    acquire( &executor, &a, FILE_READ_DATA | FILE_WRITE_DATA );
    active_loop_revoke( &executor, &a, CMD_PROTECT, PAGE_READONLY,
                        "target protection completes only after active alias revoke" );
    drop( &executor );
    acquire( &executor, &a, FILE_READ_DATA );
    read_value( &executor, 0x71, "target PAGE_READONLY permits fresh read lease" );
    write_value( &executor, 0x99, PROBE_FAULT, "target PAGE_READONLY denies fresh alias store" );
    drop( &executor );
    operation( &a, CMD_PROTECT, PAGE_NOACCESS, "target PAGE_NOACCESS protection" );
    read_value( &a, PROBE_FAULT, "target itself faults under PAGE_NOACCESS" );
    {
        struct packet packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA, a.pid );
        check( packet.status == (unsigned int)STATUS_NOT_SUPPORTED,
               "PAGE_NOACCESS acquire rejects with explicit unsupported status" );
        read_value( &executor, PROBE_FAULT, "PAGE_NOACCESS target provides no readable alias" );
        if (!packet.status) drop( &executor );
    }
    operation( &a, CMD_PROTECT, PAGE_READWRITE, "restore target protection" );
    {
        struct packet packet = request_range( &a, CMD_WRITE, 0x77, 0, 0x2000, 0 );
        check( !packet.status && !packet.value, "target writes middle page before mixed-protection proof" );
        packet = request_range( &a, CMD_PROTECT, PAGE_READONLY, 0, 0x2000, 0x1000 );
        check( !packet.status, "target creates mixed RW/READONLY readable extent" );
        acquire( &executor, &a, FILE_READ_DATA );
        packet = request_range( &executor, CMD_READ, 0, 0, 0x2000, 0 );
        check( !packet.status && packet.value == 0x77, "read-only lease reads authoritative middle-page bytes" );
        packet = request_range( &executor, CMD_WRITE, 0x78, 0, 0x2000, 0 );
        check( !packet.status && packet.value == PROBE_FAULT, "read-only middle-page alias rejects direct store" );
        drop( &executor );
        packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA | FILE_WRITE_DATA, a.pid );
        check( packet.status == (unsigned int)STATUS_NOT_SUPPORTED,
               "WRITE lease cannot override READONLY page in heterogeneous extent" );
        if (!packet.status) drop( &executor );
        packet = request_range( &a, CMD_PROTECT, PAGE_NOACCESS, 0, 0x2000, 0x1000 );
        check( !packet.status, "target creates mixed readable/NOACCESS extent" );
        packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA, a.pid );
        check( packet.status == (unsigned int)STATUS_NOT_SUPPORTED,
               "whole extent containing NOACCESS page rejects acquisition explicitly" );
        if (!packet.status) drop( &executor );
        read_value( &executor, PROBE_FAULT, "rejected mixed-NOACCESS extent creates no partial alias" );
        packet = request_range( &a, CMD_PROTECT, PAGE_READWRITE, 0, 0x2000, 0x1000 );
        check( !packet.status, "target restores readable middle page" );
        packet = request_range( &a, CMD_DECOMMIT, 0, 0, 0x2000, 0x1000 );
        check( !packet.status, "target decommits middle page of live private reservation" );
        packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA, a.pid );
        check( packet.status == (unsigned int)STATUS_NOT_SUPPORTED,
               "whole extent containing decommitted page rejects acquisition explicitly" );
        if (!packet.status) drop( &executor );
        read_value( &executor, PROBE_FAULT, "rejected sparse extent creates no partial alias" );
        operation( &a, CMD_COMMIT, 0, "target recommits sparse extent" );
        packet = request_range( &a, CMD_READ, 0, 0, 0x2000, 0 );
        check( !packet.status && !packet.value, "recommitted middle page is zero" );
        read_value( &a, 0x71, "recommitting middle page preserves committed first page" );
    }
    acquire( &executor, &a, FILE_READ_DATA | FILE_WRITE_DATA );
    active_loop_revoke( &executor, &a, CMD_DECOMMIT, 0, "decommit waits for active alias revoke" );
    drop( &executor );
    operation( &a, CMD_COMMIT, 0, "target recommits private extent" );
    read_value( &a, 0, "target recommit zeroes previous backing bytes" );
    acquire( &executor, &a, FILE_READ_DATA | FILE_WRITE_DATA );
    read_value( &executor, 0, "fresh alias sees zeroed recommitted backing" );
    write_value( &executor, 0x81, 0, "fresh recommit alias remains live and writable" );
    active_loop_revoke( &executor, &a, CMD_FREE, 0, "release waits for active alias revoke" );
    operation( &a, CMD_ALLOC, 0x91, "target reuses original address with new private mapping" );
    read_value( &executor, PROBE_FAULT, "address reuse never reactivates old alias" );
    {
        struct packet packet = request( &executor, CMD_QUERY, 0, 0 );
        check( !packet.status && packet.state == PRIVATE_MAPPING_LEASE_REVOKED,
               "retained old lease stays revoked after address reuse" );
    }
    drop( &executor );
    reused = acquire( &executor, &a, FILE_READ_DATA | FILE_WRITE_DATA );
    check( reused.mapping_id != initial.mapping_id || reused.generation != initial.generation,
           "address reuse produces a distinct mapping identity or generation" );
    read_value( &executor, 0x91, "fresh reused-address lease exposes only new target contents" );
    {
        struct packet packet;
        InterlockedExchange( &loop_observation->completed, 0 );
        InterlockedExchange( &loop_observation->successful_after_completion, 0 );
        packet = request( &executor, CMD_LOOP, 0, 0 );
        check( !packet.status && packet.count && !packet.faults, "executor actively reads before target exit" );
        if (packet.status) fatal( "start exit read-loop" );
    }
    exit_child( &a );
    InterlockedExchange( &loop_observation->completed, 1 );
    {
        struct packet packet = request( &executor, CMD_LOOP_RESULT, 0, 0 );
        check( !packet.status && packet.count && packet.faults == 1,
               "Wine-observable target exit revokes actively reading executor" );
        check( !loop_observation->successful_after_completion,
               "active loop observes no successful read started after target exit observation" );
    }
    read_value( &executor, PROBE_FAULT, "observable target exit guarantees alias no longer readable" );
    write_value( &executor, 0x98, PROBE_FAULT, "observable target exit guarantees alias no longer writable" );
    {
        struct packet packet = request_range( &executor, CMD_READ, 0, 0, PROBE_SIZE - 1, 0 );
        check( !packet.status && packet.value == PROBE_FAULT,
               "Wine-observable target exit revokes final alias byte before explicit release" );
    }
    drop( &executor );
    acquire( &executor, &b, FILE_READ_DATA | FILE_WRITE_DATA );
    operation( &b, CMD_WATCH_NATIVE_PID, executor.native_pid, "watch original executor Linux lifetime" );
    exit_child( &executor );
    {
        struct packet packet = request( &b, CMD_PROTECT, PAGE_READWRITE, 0 );
        check( !packet.status && packet.native_dead,
               "old consumer lease drains only after pidfd-confirmed native death" );
    }
    injected_revoke_failure( &b );
    operation( &b, CMD_FREE, 0, "target release after OS-confirmed executor death never hangs" );
    exit_child( &b );
    UnmapViewOfFile( loop_observation ); CloseHandle( observation );
    printf( "a1b-live-private-view: %ld checks, %ld failures\n", checks, failures );
    return !!failures;
}
static int backing_disabled_main(void)
{
    struct child target, executor;
    struct packet packet;
    HANDLE observation;
    char name[128];
    if (!getenv( "A1B_DISABLE_BACKING" )) fatal( "negative fixture requires backing opt-in absent" );
    sprintf( name, "a1b-live-view-observation-%lu", GetCurrentProcessId() );
    observation = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                     sizeof(*loop_observation), name );
    if (!observation || !(loop_observation = MapViewOfFile( observation, FILE_MAP_ALL_ACCESS, 0, 0, 0 )))
        fatal( "create negative fixture observation" );
    target = spawn_child( "target", 1 ); executor = spawn_child( "executor", 2 );
    operation( &target, CMD_ALLOC, 0x41, "backing-disabled target ordinary private allocation works" );
    packet = request( &executor, CMD_ACQUIRE, FILE_READ_DATA | FILE_WRITE_DATA, target.pid );
    check( packet.status == (unsigned int)STATUS_NOT_FOUND,
           "backing default-off creates no eligible foreign mapping" );
    if (!packet.status) fatal( "disabled backing unexpectedly admitted a lease" );
    read_value( &executor, PROBE_FAULT, "backing-disabled executor ordinary read stays inaccessible" );
    write_value( &executor, 0x99, PROBE_FAULT, "backing-disabled executor ordinary write stays inaccessible" );
    read_value( &target, 0x41, "denied default-off admission preserves target bytes" );
    operation( &target, CMD_FREE, 0, "backing-disabled target releases normally" );
    exit_child( &executor ); exit_child( &target );
    UnmapViewOfFile( loop_observation ); CloseHandle( observation );
    printf( "a1b-live-private-view: %ld checks, %ld failures (backing default-off)\n", checks, failures );
    return !!failures;
}
int main( int argc, char **argv )
{
    setvbuf( stdout, NULL, _IONBF, 0 );
    if (argc == 2 && !strcmp( argv[1], "--cancel-queued" )) return cancellation_main( 3 );
    if (argc == 2 && !strcmp( argv[1], "--cancel-map" )) return cancellation_main( 1 );
    if (argc == 2 && !strcmp( argv[1], "--cancel-revoke" )) return cancellation_main( 2 );
    if (argc == 2 && !strcmp( argv[1], "--backing-off" )) return backing_disabled_main();
    if (argc == 4) return child_main( argv[1], argv[2], argv[3] );
    if (argc != 1) return 2;
    return parent_main();
}
