/*
 * Benign Wine-only client for the private-backing server protocol.
 * The protocol matrix tests server metadata, not live foreign pointer access.
 * Build with the configured Wine winegcc and -lntdll -lkernel32 -lmsvcrt.
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

static unsigned int checks, failures;

static void check( int condition, const char *description )
{
    checks++;
    if (!condition)
    {
        fprintf( stderr, "private-backing-protocol: FAIL: %s\n", description );
        failures++;
    }
}

static void check_status( NTSTATUS actual, NTSTATUS expected, const char *description )
{
    checks++;
    if (actual != expected)
    {
        fprintf( stderr, "private-backing-protocol: FAIL: %s: %#lx expected %#lx\n",
                 description, actual, expected );
        failures++;
    }
}

static NTSTATUS create_backing( SIZE_T size, HANDLE *handle, ULONGLONG *generation )
{
    NTSTATUS status;

    *handle = NULL;
    *generation = 0;
    SERVER_START_REQ( create_private_mapping )
    {
        req->size = size;
        status = wine_server_call( req );
        if (!status)
        {
            *handle = wine_server_ptr_handle( reply->handle );
            *generation = reply->generation;
        }
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS begin_change( HANDLE handle, ULONGLONG generation, void *base,
                              SIZE_T offset, SIZE_T size, unsigned int operation,
                              ULONGLONG *token )
{
    NTSTATUS status;

    *token = 0;
    SERVER_START_REQ( begin_private_mapping_change )
    {
        req->handle = wine_server_obj_handle( handle );
        req->base = wine_server_client_ptr( base );
        req->offset = offset;
        req->size = size;
        req->generation = generation;
        req->operation = operation;
        status = wine_server_call( req );
        if (!status) *token = reply->generation;
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS finish_change( HANDLE handle, ULONGLONG token, int commit,
                               ULONGLONG *generation )
{
    NTSTATUS status;

    SERVER_START_REQ( finish_private_mapping_change )
    {
        req->handle = wine_server_obj_handle( handle );
        req->generation = token;
        req->commit = commit;
        status = wine_server_call( req );
        if (!status) *generation = reply->generation;
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS query_backing( HANDLE handle, struct query_private_mapping_reply *result )
{
    NTSTATUS status;

    memset( result, 0, sizeof(*result) );
    SERVER_START_REQ( query_private_mapping )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        if (!status) *result = *reply;
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS acquire_backing( HANDLE process, void *base, SIZE_T size, unsigned int access )
{
    NTSTATUS status;

    SERVER_START_REQ( acquire_private_mapping )
    {
        req->process = wine_server_obj_handle( process );
        req->address = wine_server_client_ptr( base );
        req->size = size;
        req->access = access;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

static void foreign_owner_child( HANDLE handle )
{
    struct query_private_mapping_reply result;
    HANDLE child_backing;
    ULONGLONG token, generation;

    check_status( query_backing( handle, &result ), STATUS_NOT_SUPPORTED,
                  "inherited handle cannot query another owner's backing" );
    check_status( begin_change( handle, 1, (void *)0x200000, 0, 0x1000,
                               PRIVATE_MAPPING_PUBLISH, &token ), STATUS_NOT_SUPPORTED,
                  "inherited handle cannot mutate another owner's backing" );
    check_status( finish_change( handle, 1, 1, &generation ), STATUS_NOT_SUPPORTED,
                  "inherited handle cannot complete another owner's mutation" );
    check( CloseHandle( handle ), "child closes inherited capability" );
    check_status( create_backing( 0x1000, &child_backing, &generation ), STATUS_SUCCESS,
                  "child creates its own backing" );
    /* Deliberately leave one owner handle open: process exit must dispose it.
     * This only exercises that path. FD closure is a separate observer check. */
    check( child_backing != NULL && generation == 1, "child has its own generation" );
}

static void injected_creation(void)
{
    HANDLE handle;
    ULONGLONG generation;
    ULONG handles_before = ~0u, handles_after = ~0u;

    check_status( NtQueryInformationProcess( GetCurrentProcess(), ProcessHandleCount,
                                             &handles_before, sizeof(handles_before), NULL ),
                  STATUS_SUCCESS, "count handles before injected creation" );
    check_status( create_backing( 0x39000, &handle, &generation ), STATUS_DISK_FULL,
                  "injected server backing creation reports disk full" );
    check( !handle && !generation, "failed creation returns no capability or generation" );
    check_status( create_backing( 0x39000, &handle, &generation ), STATUS_SUCCESS,
                  "creation retries after injected failure" );
    check( handle != NULL && generation == 1, "retry returns fresh capability and generation" );
    if (handle) check( CloseHandle( handle ), "close successful retry capability" );
    check_status( NtQueryInformationProcess( GetCurrentProcess(), ProcessHandleCount,
                                             &handles_after, sizeof(handles_after), NULL ),
                  STATUS_SUCCESS, "count handles after injected creation" );
    check( handles_before != ~0u && handles_after != ~0u && handles_after == handles_before,
           "injected creation and retry leave no owner handle leak" );
}

#ifdef A1B_HAS_LOOKUP_PRIVATE_MAPPING
static NTSTATUS lookup_allocation( void *base, struct lookup_private_mapping_reply *result,
                                   BYTE *pages, SIZE_T capacity )
{
    NTSTATUS status;

    memset( result, 0, sizeof(*result) );
    memset( pages, 0xff, capacity );
    SERVER_START_REQ( lookup_private_mapping )
    {
        req->address = wine_server_client_ptr( base );
        wine_server_set_reply( req, pages, capacity );
        status = wine_server_call( req );
        if (!status) *result = *reply;
    }
    SERVER_END_REQ;
    return status;
}

static void actual_owner_metadata(void)
{
    struct lookup_private_mapping_reply result;
    struct query_private_mapping_reply old_result;
    BYTE pages[4], *base, *replacement;
    HANDLE old_handle = NULL;
    ULONGLONG identity = 0, generation = 0, token;
    SYSTEM_INFO info;
    DWORD old_protect;
    SIZE_T page, size;
    char option[8];
    BOOL enabled, live = FALSE;
    NTSTATUS status;

    enabled = GetEnvironmentVariableA( "WINE_SHARED_PRIVATE_BACKING", option, sizeof(option) ) == 1 &&
              option[0] == '1';
    GetSystemInfo( &info );
    page = info.dwPageSize;
    size = sizeof(pages) * page;
    base = VirtualAlloc( NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    check( base != NULL, "allocate real eligible private pages for owner lookup" );
    if (!base) return;
    live = TRUE;
    base[11] = 0x51;
    base[2 * page + 11] = 0x72;
    status = lookup_allocation( base, &result, pages, sizeof(pages) );
    check_status( status, enabled ? STATUS_SUCCESS : STATUS_NOT_FOUND,
                  "lookup reflects actual opt-in allocation publication" );
    if (!enabled || status) goto cleanup;
    old_handle = wine_server_ptr_handle( result.handle );
    identity = result.mapping_id;
    generation = result.generation;
    check( old_handle != NULL && identity != 0 && generation >= 3,
           "real allocation has nonzero authoritative identity and published epoch" );
    check( result.base == wine_server_client_ptr( base ) && result.size == size &&
           wine_server_reply_size( &result ) == sizeof(pages), "real lookup returns exact allocation extent" );
    check( pages[0] == 0x23 && pages[1] == 0x23 && pages[2] == 0x23 && pages[3] == 0x23,
           "server records four committed read-write NX pages" );
    check_status( begin_change( old_handle, generation - 1, base, 0, page,
                               PRIVATE_MAPPING_PROTECT, &token ), STATUS_INVALID_PARAMETER,
                  "stale real allocation epoch cannot begin a mutation" );
    check( base[11] == 0x51 && base[2 * page + 11] == 0x72,
           "rejected stale request preserves real allocation bytes" );
    check( VirtualProtect( base + page, page, PAGE_READONLY, &old_protect ),
           "real protection mutation succeeds through ntdll" );
    check( old_protect == PAGE_READWRITE, "real protection mutation reports previous permissions" );
    status = lookup_allocation( base, &result, pages, sizeof(pages) );
    check_status( status, STATUS_SUCCESS, "lookup real allocation after protection update" );
    if (status) goto cleanup;
    check( result.mapping_id == identity && result.generation > generation,
           "real protection update retains identity and advances authoritative epoch" );
    generation = result.generation;
    check( pages[0] == 0x23 && pages[1] == 0x21 && pages[2] == 0x23 && pages[3] == 0x23,
           "authoritative metadata matches partial read-only protection" );
    check( CloseHandle( wine_server_ptr_handle( result.handle ) ), "close protection lookup duplicate" );
    check( VirtualFree( base + 2 * page, page, MEM_DECOMMIT ),
           "real partial decommit succeeds through ntdll" );
    status = lookup_allocation( base, &result, pages, sizeof(pages) );
    check_status( status, STATUS_SUCCESS, "lookup real allocation after decommit" );
    if (status) goto cleanup;
    check( result.mapping_id == identity && result.generation > generation,
           "real decommit retains identity and advances authoritative epoch" );
    generation = result.generation;
    check( pages[0] == 0x23 && pages[1] == 0x21 && pages[2] == 0 && pages[3] == 0x23,
           "authoritative metadata marks only decommitted page absent" );
    check( CloseHandle( wine_server_ptr_handle( result.handle ) ), "close decommit lookup duplicate" );
    replacement = VirtualAlloc( base + 2 * page, page, MEM_COMMIT, PAGE_READWRITE );
    check( replacement == base + 2 * page,
           "real decommitted page recommits at its original address" );
    if (replacement != base + 2 * page) goto cleanup;
    check( base[2 * page + 11] == 0 && base[11] == 0x51,
           "real recommit zeroes only decommitted page" );
    status = lookup_allocation( base, &result, pages, sizeof(pages) );
    check_status( status, STATUS_SUCCESS, "lookup real allocation after recommit" );
    if (status) goto cleanup;
    check( result.mapping_id == identity && result.generation > generation && pages[2] == 0x23,
           "real recommit records committed page and a later epoch" );
    generation = result.generation;
    check( CloseHandle( wine_server_ptr_handle( result.handle ) ), "close recommit lookup duplicate" );
    if (!VirtualFree( base, 0, MEM_RELEASE ))
    {
        check( FALSE, "release actual published allocation" );
        goto cleanup;
    }
    check( TRUE, "release actual published allocation" );
    live = FALSE;
    check_status( lookup_allocation( base, &result, pages, sizeof(pages) ), STATUS_NOT_FOUND,
                  "released actual allocation is no longer published" );
    check_status( begin_change( old_handle, generation, base, 0, page, PRIVATE_MAPPING_COMMIT,
                               &token ), STATUS_INVALID_PARAMETER,
                  "pre-release actual epoch is rejected after release" );
    replacement = VirtualAlloc( base, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    check( replacement == base, "reuse released private address" );
    if (replacement != base)
    {
        if (replacement) VirtualFree( replacement, 0, MEM_RELEASE );
        goto cleanup;
    }
    live = TRUE;
    status = lookup_allocation( base, &result, pages, sizeof(pages) );
    check_status( status, STATUS_SUCCESS, "lookup replacement at reused address" );
    if (!status)
    {
        check( result.mapping_id != 0 && result.mapping_id != identity && base[11] == 0,
               "address reuse has fresh backing identity and zero-filled private storage" );
        check( CloseHandle( wine_server_ptr_handle( result.handle ) ), "close replacement lookup duplicate" );
        check_status( query_backing( old_handle, &old_result ), STATUS_SUCCESS,
                      "retained diagnostic capability still names old backing" );
        check( old_result.last_operation == PRIVATE_MAPPING_RELEASE,
               "old capability remains retired release metadata instead of replacement" );
    }
cleanup:
    if (old_handle) check( CloseHandle( old_handle ), "close retained old diagnostic capability" );
    if (live) check( VirtualFree( base, 0, MEM_RELEASE ), "release actual owner metadata fixture" );
}
#endif

int main( int argc, char **argv )
{
    struct query_private_mapping_reply result;
    SYSTEM_INFO info;
    HANDLE handle = NULL, inherited = NULL;
    ULONGLONG generation, token, other_token, previous;
    SIZE_T size, page;
    void *base;
    NTSTATUS status;
    unsigned int operation, i;
    const unsigned int operations[] = { PRIVATE_MAPPING_COMMIT, PRIVATE_MAPPING_PROTECT,
        PRIVATE_MAPPING_DECOMMIT, PRIVATE_MAPPING_RESET, PRIVATE_MAPPING_RELEASE };
    char command[2 * MAX_PATH], executable[MAX_PATH];
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION process;
    DWORD exit_code, length, handles_before = ~0u, handles_after = ~0u;

    if (argc == 3 && !strcmp( argv[1], "--foreign-owner" ))
    {
        foreign_owner_child( (HANDLE)(ULONG_PTR)strtoul( argv[2], NULL, 16 ) );
        printf( "private-backing-protocol: child checks=%u failures=%u\n", checks, failures );
        return failures ? 1 : 0;
    }
    if (argc == 2 && !strcmp( argv[1], "--injected-create" ))
    {
        injected_creation();
        printf( "private-backing-protocol: injected-create checks=%u failures=%u\n", checks, failures );
        return failures ? 1 : 0;
    }

    check_status( NtQueryInformationProcess( GetCurrentProcess(), ProcessHandleCount,
                                             &handles_before, sizeof(handles_before), NULL ),
                  STATUS_SUCCESS, "record owner handle count before matrix" );
    GetSystemInfo( &info );
    page = info.dwPageSize;
    size = 4 * page;
    base = VirtualAlloc( NULL, size, MEM_RESERVE, PAGE_READWRITE );
    check( base != NULL, "allocate owned reservation for metadata's original address" );
    if (!base) return 1;

    /* This client creates and publishes protocol metadata independently of
     * ntdll's mapping path. It never maps this backing over the reservation,
     * and makes no claim about bytes, protections or live aliases. */
    check_status( create_backing( 0, &handle, &generation ), STATUS_INVALID_PARAMETER,
                  "zero extent rejected" );
    check_status( create_backing( page + 1, &handle, &generation ), STATUS_INVALID_PARAMETER,
                  "unaligned extent rejected" );
    check_status( create_backing( size, &handle, &generation ), STATUS_SUCCESS,
                  "create aligned owner backing" );
    if (!handle) goto cleanup;
    check( generation == 1, "initial generation is one" );
    check_status( query_backing( handle, &result ), STATUS_SUCCESS, "lookup before publication" );
    check( !result.base && result.size == size && result.generation == generation &&
           !result.updating && !result.last_operation, "unpublished metadata has no mapping" );

    check_status( begin_change( handle, generation, base, 0, size, PRIVATE_MAPPING_COMMIT,
                               &token ), STATUS_INVALID_PARAMETER,
                  "mutation before publication rejected" );
    check_status( begin_change( handle, generation, base, page, size - page,
                               PRIVATE_MAPPING_PUBLISH, &token ), STATUS_INVALID_PARAMETER,
                  "partial publication rejected" );
    check_status( begin_change( handle, generation, (char *)base + 1, 0, size,
                               PRIVATE_MAPPING_PUBLISH, &token ), STATUS_INVALID_PARAMETER,
                  "unaligned original address rejected" );
    check_status( begin_change( handle, generation, base, 0, size, PRIVATE_MAPPING_PUBLISH,
                               &token ), STATUS_SUCCESS, "begin publication" );
    check( token == generation + 1, "publication advances transaction epoch" );
    check_status( query_backing( handle, &result ), STATUS_SUCCESS, "lookup fenced publication" );
    check( result.updating && result.generation == token && !result.base,
           "pending publication is fenced and not committed" );
    check_status( begin_change( handle, token, base, 0, size, PRIVATE_MAPPING_PUBLISH,
                               &other_token ), STATUS_DEVICE_BUSY, "second mutation is fenced" );
    check_status( finish_change( handle, token - 1, 1, &generation ), STATUS_INVALID_PARAMETER,
                  "wrong completion token rejected" );
    check_status( query_backing( handle, &result ), STATUS_SUCCESS, "lookup after rejected finish" );
    check( result.updating && result.generation == token && !result.base,
           "rejected finish preserves pending transaction" );
    check_status( finish_change( handle, token, 1, &generation ), STATUS_SUCCESS,
                  "commit publication" );
    check( generation == token + 1, "publication completion advances epoch" );
    check_status( query_backing( handle, &result ), STATUS_SUCCESS, "lookup committed publication" );
    check( result.base == wine_server_client_ptr( base ) && result.size == size &&
           result.generation == generation && !result.updating &&
           result.last_operation == PRIVATE_MAPPING_PUBLISH && result.last_offset == 0 &&
           result.last_size == size, "publication records original address and extent" );

    check_status( begin_change( handle, generation - 1, base, 0, page,
                               PRIVATE_MAPPING_PROTECT, &token ), STATUS_INVALID_PARAMETER,
                  "stale generation rejected" );
    check_status( begin_change( handle, generation, base, size, page,
                               PRIVATE_MAPPING_PROTECT, &token ), STATUS_INVALID_PARAMETER,
                  "out-of-range offset rejected" );
    check_status( begin_change( handle, generation, base, page, size,
                               PRIVATE_MAPPING_PROTECT, &token ), STATUS_INVALID_PARAMETER,
                  "extent overrun rejected" );
    check_status( begin_change( handle, generation, base, 0, page, 0, &token ),
                  STATUS_INVALID_PARAMETER, "invalid operation rejected" );
    check_status( begin_change( handle, generation, base, 0, size, PRIVATE_MAPPING_PUBLISH,
                               &token ), STATUS_INVALID_PARAMETER,
                  "republication rejected" );
    check_status( finish_change( handle, generation, 1, &other_token ), STATUS_INVALID_PARAMETER,
                  "completion without pending mutation rejected" );

    previous = generation;
    check_status( begin_change( handle, generation, base, page, page,
                               PRIVATE_MAPPING_PROTECT, &token ), STATUS_SUCCESS,
                  "begin abortable update after invalid requests" );
    check_status( finish_change( handle, token, 0, &generation ), STATUS_SUCCESS, "abort update" );
    check( generation == previous + 2, "abort consumes both epochs" );
    check_status( query_backing( handle, &result ), STATUS_SUCCESS, "lookup aborted update" );
    check( !result.updating && result.generation == generation &&
           result.last_operation == PRIVATE_MAPPING_PUBLISH && result.last_offset == 0 &&
           result.last_size == size, "abort preserves last committed metadata" );
    check_status( begin_change( handle, previous, base, 0, page, PRIVATE_MAPPING_PROTECT,
                               &token ), STATUS_INVALID_PARAMETER,
                  "aborted generation cannot be reused" );

    for (i = 0; i < sizeof(operations) / sizeof(operations[0]); i++)
    {
        operation = operations[i];
        previous = generation;
        check_status( begin_change( handle, generation, base, page, page, operation, &token ),
                      STATUS_SUCCESS, "begin supported metadata operation" );
        check( token == previous + 1, "update token increments epoch" );
        check_status( finish_change( handle, token, 1, &generation ), STATUS_SUCCESS,
                      "complete supported metadata operation" );
        check( generation == previous + 2, "update completion increments epoch" );
        check_status( query_backing( handle, &result ), STATUS_SUCCESS,
                      "lookup completed metadata operation" );
        check( !result.updating && result.generation == generation &&
               result.base == wine_server_client_ptr( base ) && result.last_operation == operation &&
               result.last_offset == page && result.last_size == page,
               "operation records affected range without changing original extent" );
    }

    check_status( acquire_backing( GetCurrentProcess(), base, size, FILE_READ_DATA ),
                  STATUS_NOT_SUPPORTED, "ordinary process cannot acquire a backing capability" );
    check_status( acquire_backing( GetCurrentProcess(), base, size, FILE_WRITE_DATA ),
                  STATUS_INVALID_PARAMETER, "write-only foreign acquisition rejected" );
    check_status( acquire_backing( GetCurrentProcess(), base, 0, FILE_READ_DATA ),
                  STATUS_INVALID_PARAMETER, "zero foreign extent rejected" );

    status = DuplicateHandle( GetCurrentProcess(), handle, GetCurrentProcess(), &inherited,
                              0, TRUE, DUPLICATE_SAME_ACCESS );
    check( status, "make inheritable duplicate for foreign ownership test" );
    if (status)
    {
        length = GetModuleFileNameA( NULL, executable, sizeof(executable) );
        check( length && length < sizeof(executable), "obtain fixture executable path" );
        if (length && length < sizeof(executable))
        {
            snprintf( command, sizeof(command), "\"%s\" --foreign-owner %lx", executable,
                      (ULONG)(ULONG_PTR)inherited );
            memset( &process, 0, sizeof(process) );
            status = CreateProcessA( NULL, command, NULL, NULL, TRUE, 0, NULL, NULL,
                                     &startup, &process );
            check( status, "create process inheriting another owner's backing handle" );
            if (status)
            {
                DWORD wait = WaitForSingleObject( process.hProcess, 15000 );
                check( wait == WAIT_OBJECT_0, "foreign owner child exits in bound" );
                if (wait != WAIT_OBJECT_0)
                {
                    TerminateProcess( process.hProcess, 1 );
                    WaitForSingleObject( process.hProcess, 5000 );
                }
                exit_code = ~0u;
                check( GetExitCodeProcess( process.hProcess, &exit_code ) && !exit_code,
                       "foreign owner child checks pass" );
                check( CloseHandle( process.hThread ), "close foreign owner child thread" );
                check( CloseHandle( process.hProcess ), "close foreign owner child process" );
            }
        }
        check( CloseHandle( inherited ), "close inheritable duplicate" );
        check_status( query_backing( handle, &result ), STATUS_SUCCESS,
                      "owner metadata survives unrelated child exit" );
        check( result.generation == generation && !result.updating,
               "foreign child cannot alter owner generation" );
    }

    check( CloseHandle( handle ), "release backing handle" );
    check_status( query_backing( handle, &result ), STATUS_INVALID_HANDLE,
                  "closed capability lookup rejected" );
    check_status( begin_change( handle, generation, base, 0, page, PRIVATE_MAPPING_COMMIT,
                               &token ), STATUS_INVALID_HANDLE,
                  "closed capability mutation rejected" );
    handle = NULL;
cleanup:
    if (handle) CloseHandle( handle );
    check( VirtualFree( base, 0, MEM_RELEASE ), "release metadata address reservation" );
#ifdef A1B_HAS_LOOKUP_PRIVATE_MAPPING
    actual_owner_metadata();
#endif
    check_status( NtQueryInformationProcess( GetCurrentProcess(), ProcessHandleCount,
                                             &handles_after, sizeof(handles_after), NULL ),
                  STATUS_SUCCESS, "record owner handle count after matrix" );
    check( handles_before != ~0u && handles_after != ~0u && handles_after == handles_before,
           "matrix leaves no owner handle leak" );
    printf( "private-backing-protocol: parent checks=%u failures=%u\n", checks, failures );
    return failures ? 1 : 0;
}
