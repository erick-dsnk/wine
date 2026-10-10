/*
 * ntoskrnl.exe testing framework
 *
 * Copyright 2015 Sebastian Lackner
 * Copyright 2015 Michael Müller
 * Copyright 2015 Christian Costa
 * Copyright 2020-2021 Zebediah Figura for CodeWeavers
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
#include "windows.h"
#include "winsvc.h"
#include "winioctl.h"
#include "winternl.h"
#include "winsock2.h"
#include "wincrypt.h"
#include "ntsecapi.h"
#include "mscat.h"
#include "mssip.h"
#include "setupapi.h"
#include "cfgmgr32.h"
#include "devfiltertypes.h"
#include "devquery.h"
#include "newdev.h"
#include "regstr.h"
#include "dbt.h"
#include "initguid.h"
#include "devguid.h"
#include "devpkey.h"
#include "ddk/hidclass.h"
#include "ddk/hidsdi.h"
#include "ddk/hidpi.h"
#include "wine/test.h"
#include "wine/mssign.h"
#include "wine/asm.h"
#include "rtlsupportapi.h"
#include "excpt.h"

#include "driver.h"

static const GUID GUID_NULL;

static HANDLE device;

static struct test_data *test_data;

static BOOL (WINAPI *pCancelIoEx)(HANDLE, OVERLAPPED *);
static BOOL (WINAPI *pSetFileCompletionNotificationModes)(HANDLE, UCHAR);

static HRESULT (WINAPI *pDevCreateObjectQuery)(DEV_OBJECT_TYPE, ULONG, ULONG, const DEVPROPCOMPKEY*, ULONG,
                                               const DEVPROP_FILTER_EXPRESSION*, PDEV_QUERY_RESULT_CALLBACK, void*, HDEVQUERY*);
static void (WINAPI *pDevCloseObjectQuery)(HDEVQUERY);

static void load_resource(const WCHAR *name, WCHAR *filename)
{
    static WCHAR path[MAX_PATH];
    DWORD written;
    HANDLE file;
    HRSRC res;
    void *ptr;

    GetTempPathW(ARRAY_SIZE(path), path);
    GetTempFileNameW(path, name, 0, filename);

    file = CreateFileW(filename, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "failed to create %s, error %lu\n", debugstr_w(filename), GetLastError());

    res = FindResourceW(NULL, name, L"TESTDLL");
    ok( res != 0, "couldn't find resource\n" );
    ptr = LockResource( LoadResource( GetModuleHandleA(NULL), res ));
    WriteFile( file, ptr, SizeofResource( GetModuleHandleA(NULL), res ), &written, NULL );
    ok( written == SizeofResource( GetModuleHandleA(NULL), res ), "couldn't write resource\n" );
    CloseHandle( file );
}

struct testsign_context
{
    HCRYPTPROV provider;
    const CERT_CONTEXT *cert, *root_cert, *publisher_cert;
    HCERTSTORE root_store, publisher_store;
};

static BOOL testsign_create_cert(struct testsign_context *ctx)
{
    BYTE encoded_name[100], encoded_key_id[200], public_key_info_buffer[1000];
    WCHAR container_name[26];
    BYTE hash_buffer[16], cert_buffer[1000], provider_nameA[100], serial[16];
    CERT_PUBLIC_KEY_INFO *public_key_info = (CERT_PUBLIC_KEY_INFO *)public_key_info_buffer;
    CRYPT_KEY_PROV_INFO provider_info = {0};
    CRYPT_ALGORITHM_IDENTIFIER algid = {0};
    CERT_AUTHORITY_KEY_ID_INFO key_info;
    CERT_INFO cert_info = {0};
    WCHAR provider_nameW[100];
    CERT_EXTENSION extension;
    HCRYPTKEY key;
    DWORD size;
    BOOL ret;

    memset(ctx, 0, sizeof(*ctx));

    srand(time(NULL));
    swprintf(container_name, ARRAY_SIZE(container_name), L"wine_testsign%u", rand());

    ret = CryptAcquireContextW(&ctx->provider, container_name, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    ok(ret, "Failed to create container, error %#lx\n", GetLastError());

    ret = CryptGenKey(ctx->provider, AT_SIGNATURE, CRYPT_EXPORTABLE, &key);
    ok(ret, "Failed to create key, error %#lx\n", GetLastError());
    ret = CryptDestroyKey(key);
    ok(ret, "Failed to destroy key, error %#lx\n", GetLastError());
    ret = CryptGetUserKey(ctx->provider, AT_SIGNATURE, &key);
    ok(ret, "Failed to get user key, error %#lx\n", GetLastError());
    ret = CryptDestroyKey(key);
    ok(ret, "Failed to destroy key, error %#lx\n", GetLastError());

    size = sizeof(encoded_name);
    ret = CertStrToNameA(X509_ASN_ENCODING, "CN=winetest_cert", CERT_X500_NAME_STR, NULL, encoded_name, &size, NULL);
    ok(ret, "Failed to convert name, error %#lx\n", GetLastError());
    key_info.CertIssuer.cbData = size;
    key_info.CertIssuer.pbData = encoded_name;

    size = sizeof(public_key_info_buffer);
    ret = CryptExportPublicKeyInfo(ctx->provider, AT_SIGNATURE, X509_ASN_ENCODING, public_key_info, &size);
    ok(ret, "Failed to export public key, error %#lx\n", GetLastError());
    cert_info.SubjectPublicKeyInfo = *public_key_info;

    size = sizeof(hash_buffer);
    ret = CryptHashPublicKeyInfo(ctx->provider, CALG_MD5, 0, X509_ASN_ENCODING, public_key_info, hash_buffer, &size);
    ok(ret, "Failed to hash public key, error %#lx\n", GetLastError());

    key_info.KeyId.cbData = size;
    key_info.KeyId.pbData = hash_buffer;

    RtlGenRandom(serial, sizeof(serial));
    key_info.CertSerialNumber.cbData = sizeof(serial);
    key_info.CertSerialNumber.pbData = serial;

    size = sizeof(encoded_key_id);
    ret = CryptEncodeObject(X509_ASN_ENCODING, X509_AUTHORITY_KEY_ID, &key_info, encoded_key_id, &size);
    ok(ret, "Failed to convert name, error %#lx\n", GetLastError());

    extension.pszObjId = (char *)szOID_AUTHORITY_KEY_IDENTIFIER;
    extension.fCritical = TRUE;
    extension.Value.cbData = size;
    extension.Value.pbData = encoded_key_id;

    cert_info.dwVersion = CERT_V3;
    cert_info.SerialNumber = key_info.CertSerialNumber;
    cert_info.SignatureAlgorithm.pszObjId = (char *)szOID_RSA_SHA1RSA;
    cert_info.Issuer = key_info.CertIssuer;
    GetSystemTimeAsFileTime(&cert_info.NotBefore);
    GetSystemTimeAsFileTime(&cert_info.NotAfter);
    cert_info.NotAfter.dwHighDateTime += 1;
    cert_info.Subject = key_info.CertIssuer;
    cert_info.cExtension = 1;
    cert_info.rgExtension = &extension;
    algid.pszObjId = (char *)szOID_RSA_SHA1RSA;
    size = sizeof(cert_buffer);
    ret = CryptSignAndEncodeCertificate(ctx->provider, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &cert_info, &algid, NULL, cert_buffer, &size);
    ok(ret, "Failed to create certificate, error %#lx\n", GetLastError());

    ctx->cert = CertCreateCertificateContext(X509_ASN_ENCODING, cert_buffer, size);
    ok(!!ctx->cert, "Failed to create context, error %#lx\n", GetLastError());

    size = sizeof(provider_nameA);
    ret = CryptGetProvParam(ctx->provider, PP_NAME, provider_nameA, &size, 0);
    ok(ret, "Failed to get prov param, error %#lx\n", GetLastError());
    MultiByteToWideChar(CP_ACP, 0, (char *)provider_nameA, -1, provider_nameW, ARRAY_SIZE(provider_nameW));

    provider_info.pwszContainerName = (WCHAR *)container_name;
    provider_info.pwszProvName = provider_nameW;
    provider_info.dwProvType = PROV_RSA_FULL;
    provider_info.dwKeySpec = AT_SIGNATURE;
    ret = CertSetCertificateContextProperty(ctx->cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &provider_info);
    ok(ret, "Failed to set provider info, error %#lx\n", GetLastError());

    ctx->root_store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "root");
    if (!ctx->root_store && GetLastError() == ERROR_ACCESS_DENIED)
    {
        skip("Failed to open root store.\n");

        ret = CertFreeCertificateContext(ctx->cert);
        ok(ret, "Failed to free certificate, error %lu\n", GetLastError());
        ret = CryptReleaseContext(ctx->provider, 0);
        ok(ret, "failed to release context, error %lu\n", GetLastError());

        return FALSE;
    }
    ok(!!ctx->root_store, "Failed to open store, error %lu\n", GetLastError());
    ret = CertAddCertificateContextToStore(ctx->root_store, ctx->cert, CERT_STORE_ADD_ALWAYS, &ctx->root_cert);
    if (!ret && GetLastError() == ERROR_ACCESS_DENIED)
    {
        skip("Failed to add self-signed certificate to store.\n");

        ret = CertFreeCertificateContext(ctx->cert);
        ok(ret, "Failed to free certificate, error %lu\n", GetLastError());
        ret = CertCloseStore(ctx->root_store, CERT_CLOSE_STORE_CHECK_FLAG);
        ok(ret, "Failed to close store, error %lu\n", GetLastError());
        ret = CryptReleaseContext(ctx->provider, 0);
        ok(ret, "failed to release context, error %lu\n", GetLastError());

        return FALSE;
    }
    ok(ret, "Failed to add certificate, error %lu\n", GetLastError());

    ctx->publisher_store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_A, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE, "trustedpublisher");
    ok(!!ctx->publisher_store, "Failed to open store, error %lu\n", GetLastError());
    ret = CertAddCertificateContextToStore(ctx->publisher_store, ctx->cert,
            CERT_STORE_ADD_ALWAYS, &ctx->publisher_cert);
    ok(ret, "Failed to add certificate, error %lu\n", GetLastError());

    return TRUE;
}

static void testsign_cleanup(struct testsign_context *ctx)
{
    BOOL ret;

    ret = CertFreeCertificateContext(ctx->cert);
    ok(ret, "Failed to free certificate, error %lu\n", GetLastError());

    ret = CertFreeCertificateContext(ctx->root_cert);
    ok(ret, "Failed to free certificate context, error %lu\n", GetLastError());
    ret = CertCloseStore(ctx->root_store, CERT_CLOSE_STORE_CHECK_FLAG);
    ok(ret, "Failed to close store, error %lu\n", GetLastError());

    ret = CertFreeCertificateContext(ctx->publisher_cert);
    ok(ret, "Failed to free certificate context, error %lu\n", GetLastError());
    ret = CertCloseStore(ctx->publisher_store, CERT_CLOSE_STORE_CHECK_FLAG);
    ok(ret, "Failed to close store, error %lu\n", GetLastError());

    ret = CryptReleaseContext(ctx->provider, 0);
    ok(ret, "failed to release context, error %lu\n", GetLastError());
}

static void testsign_sign(struct testsign_context *ctx, const WCHAR *filename)
{
    static HRESULT (WINAPI *pSignerSign)(SIGNER_SUBJECT_INFO *subject, SIGNER_CERT *cert,
            SIGNER_SIGNATURE_INFO *signature, SIGNER_PROVIDER_INFO *provider,
            const WCHAR *timestamp, CRYPT_ATTRIBUTES *attr, void *sip_data);

    SIGNER_ATTR_AUTHCODE authcode = {sizeof(authcode)};
    SIGNER_SIGNATURE_INFO signature = {sizeof(signature)};
    SIGNER_SUBJECT_INFO subject = {sizeof(subject)};
    SIGNER_CERT_STORE_INFO store = {sizeof(store)};
    SIGNER_CERT cert_info = {sizeof(cert_info)};
    SIGNER_FILE_INFO file = {sizeof(file)};
    DWORD index = 0;
    HRESULT hr;

    if (!pSignerSign)
        pSignerSign = (void *)GetProcAddress(LoadLibraryA("mssign32"), "SignerSign");

    subject.dwSubjectChoice = 1;
    subject.pdwIndex = &index;
    subject.pSignerFileInfo = &file;
    file.pwszFileName = (WCHAR *)filename;
    cert_info.dwCertChoice = 2;
    cert_info.pCertStoreInfo = &store;
    store.pSigningCert = ctx->cert;
    store.dwCertPolicy = 0;
    signature.algidHash = CALG_SHA_256;
    signature.dwAttrChoice = SIGNER_AUTHCODE_ATTR;
    signature.pAttrAuthcode = &authcode;
    authcode.pwszName = L"";
    authcode.pwszInfo = L"";
    hr = pSignerSign(&subject, &cert_info, &signature, NULL, NULL, NULL, NULL);
    todo_wine ok(hr == S_OK || broken(hr == NTE_BAD_ALGID) /* < 7 */, "Failed to sign, hr %#lx\n", hr);
}

static void unload_driver(SC_HANDLE service)
{
    SERVICE_STATUS status;

    ControlService(service, SERVICE_CONTROL_STOP, &status);
    while (status.dwCurrentState == SERVICE_STOP_PENDING)
    {
        BOOL ret;
        Sleep(100);
        ret = QueryServiceStatus(service, &status);
        ok(ret, "QueryServiceStatus failed: %lu\n", GetLastError());
    }
    ok(status.dwCurrentState == SERVICE_STOPPED,
       "expected SERVICE_STOPPED, got %ld\n", status.dwCurrentState);

    DeleteService(service);
    CloseServiceHandle(service);
}

static SC_HANDLE load_driver(struct testsign_context *ctx, WCHAR *filename,
        const WCHAR *resname, const WCHAR *driver_name)
{
    SC_HANDLE manager, service;

    manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager && GetLastError() == ERROR_ACCESS_DENIED)
    {
        skip("Failed to open SC manager, not enough permissions\n");
        return FALSE;
    }
    ok(!!manager, "OpenSCManager failed\n");

    /* stop any old drivers running under this name */
    service = OpenServiceW(manager, driver_name, SERVICE_ALL_ACCESS);
    if (service) unload_driver(service);

    load_resource(resname, filename);
    testsign_sign(ctx, filename);
    trace("Trying to load driver %s\n", debugstr_w(filename));

    service = CreateServiceW(manager, driver_name, driver_name,
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             filename, NULL, NULL, NULL, NULL, NULL);
    ok(!!service, "CreateService failed: %lu\n", GetLastError());

    CloseServiceHandle(manager);
    return service;
}

static BOOL start_driver(HANDLE service, BOOL vista_plus)
{
    SERVICE_STATUS status;
    BOOL ret;

    SetLastError(0xdeadbeef);
    ret = StartServiceA(service, 0, NULL);
    if (!ret && (GetLastError() == ERROR_DRIVER_BLOCKED || GetLastError() == ERROR_INVALID_IMAGE_HASH
            || (vista_plus && GetLastError() == ERROR_FILE_NOT_FOUND)))
    {
        if (vista_plus && GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            skip("Windows Vista or newer is required to run this service.\n");
        }
        else
        {
            /* If Secure Boot is enabled or the machine is 64-bit, it will reject an unsigned driver. */
            skip("Failed to start service; probably your machine doesn't accept unsigned drivers.\n");
        }
        DeleteService(service);
        CloseServiceHandle(service);
        return FALSE;
    }
    ok(ret, "StartService failed: %lu\n", GetLastError());

    /* wait for the service to start up properly */
    ret = QueryServiceStatus(service, &status);
    ok(ret, "QueryServiceStatus failed: %lu\n", GetLastError());
    while (status.dwCurrentState == SERVICE_START_PENDING)
    {
        Sleep(100);
        ret = QueryServiceStatus(service, &status);
        ok(ret, "QueryServiceStatus failed: %lu\n", GetLastError());
    }
    ok(status.dwCurrentState == SERVICE_RUNNING,
       "expected SERVICE_RUNNING, got %ld\n", status.dwCurrentState);
    ok(status.dwServiceType == SERVICE_KERNEL_DRIVER,
       "expected SERVICE_KERNEL_DRIVER, got %#lx\n", status.dwServiceType);

    return TRUE;
}

static HANDLE okfile;

static void cat_okfile(void)
{
    char buffer[512];
    DWORD size;

    SetFilePointer(okfile, 0, NULL, FILE_BEGIN);

    do
    {
        ReadFile(okfile, buffer, sizeof(buffer), &size, NULL);
        printf("%.*s", (int)size, buffer);
    } while (size == sizeof(buffer));

    SetFilePointer(okfile, 0, NULL, FILE_BEGIN);
    SetEndOfFile(okfile);

    InterlockedAdd(&winetest_successes, InterlockedExchange(&test_data->successes, 0));
    winetest_add_failures(InterlockedExchange(&test_data->failures, 0));
    InterlockedAdd(&winetest_todo_successes, InterlockedExchange(&test_data->todo_successes, 0));
    winetest_add_failures(InterlockedExchange(&test_data->todo_failures, 0));
    InterlockedAdd(&winetest_skipped, InterlockedExchange(&test_data->skipped, 0));
}

static ULONG64 modified_value;

#ifdef __x86_64__
/* A1b gate 1 only: cooperative execution at common mappings. Each invocation
 * returns to its own process; this is not continuation migration or attachment.
 * The leaf never calls Wine or raises an intentional fault on the shared stack. */
#define EXECUTION_REGION_SIZE 0x10000

struct execution_data
{
    DWORD sequence, common_value, target_value, stack_value;
    ULONG_PTR rip, rsp, native_before, native_after;
    DWORD registers, owner, previous_stack;
};
C_ASSERT(FIELD_OFFSET(struct execution_data, rip) == 0x10);
C_ASSERT(FIELD_OFFSET(struct execution_data, rsp) == 0x18);
C_ASSERT(FIELD_OFFSET(struct execution_data, native_before) == 0x20);
C_ASSERT(FIELD_OFFSET(struct execution_data, native_after) == 0x28);
C_ASSERT(FIELD_OFFSET(struct execution_data, registers) == 0x30);
C_ASSERT(FIELD_OFFSET(struct execution_data, previous_stack) == 0x38);

static const BYTE execution_code[] =
{
    0x49,0x89,0xe2,                  /* mov rsp,r10: remember native stack */
    0x4c,0x89,0xc4,                  /* mov r8,rsp: enter shared stack */
    0x48,0x83,0xec,0x28,             /* reserve aligned entry/shadow space */
    0x48,0x8d,0x05,0,0,0,0,          /* lea 0(rip),rax: actual mapped RIP */
    0x48,0x89,0x41,0x10,             /* record RIP */
    0x48,0x89,0x61,0x18,             /* record actual RSP */
    0x8b,0x44,0x24,0x20,             /* read preceding shared stack value */
    0x89,0x41,0x38,
    0xff,0x01,                        /* ++shared sequence (serial owner) */
    0x8b,0x01,
    0x89,0x41,0x0c,
    0x89,0x44,0x24,0x20,             /* write shared stack value */
    0x0f,0xb6,0x02,                  /* direct private common-byte load */
    0x89,0x41,0x04,
    0xc7,0x41,0x08,0,0,0,0,
    0x4d,0x85,0xc9,                  /* caller never loads absent target */
    0x74,0x07,
    0x41,0x0f,0xb6,0x01,             /* direct private target-only load */
    0x89,0x41,0x08,
    0x4c,0x89,0xd4,0xc3,             /* restore native RSP and return */
};

/* Keep the ABI control on the native stack, with ordinary unwind metadata.
 * The mapped leaf touches only volatile registers. Check representative
 * nonvolatile GPRs and native-stack restoration after each invocation. */
void WINAPI invoke_execution(struct execution_data *, void *, BYTE *, void *, BYTE *);
__ASM_GLOBAL_FUNC(invoke_execution,
    "pushq %rbp\n\t"
    __ASM_SEH(".seh_pushreg %rbp\n\t")
    "pushq %rbx\n\t"
    __ASM_SEH(".seh_pushreg %rbx\n\t")
    "subq $0x38,%rsp\n\t"
    __ASM_SEH(".seh_stackalloc 0x38\n\t.seh_endprologue\n\t")
    "movq %rcx,0x20(%rsp)\n\t"
    "movq %rdx,%rax\n\t"
    "movq %r8,%rdx\n\t"
    "movq %r9,%r8\n\t"
    "movq 0x70(%rsp),%r9\n\t"
    "movq %rsp,0x20(%rcx)\n\t"
    "movl $0x13579bdf,%ebx\n\t"
    "movl $0x2468ace0,%ebp\n\t"
    "call *%rax\n\t"
    "movq 0x20(%rsp),%rax\n\t"
    "movq %rsp,0x28(%rax)\n\t"
    "xorl %ecx,%ecx\n\t"
    "cmpq $0x13579bdf,%rbx\n\t"
    "sete %cl\n\t"
    "xorl %edx,%edx\n\t"
    "cmpq $0x2468ace0,%rbp\n\t"
    "sete %dl\n\t"
    "leal (%ecx,%edx,2),%ecx\n\t"
    "movl %ecx,0x30(%rax)\n\t"
    "addq $0x38,%rsp\n\t"
    "popq %rbx\n\t"
    "popq %rbp\n\t"
    "ret")


/* A1b gate 2 is a raw cooperative continuation, never a runtime attachment.
 * Only this serial owner uses the shared stack. Separate bounded fault tests
 * exercise first-chance VEH abort and x64 table-based frame unwinding.
 * The snapshot covers GPRs, XMM0..15, MXCSR and
 * safe status flags; x87, AVX/XSTATE and logical thread identity are excluded. */
#define CONTINUATION_CODE_OFFSET 0x100
#define CONTINUATION_DATA_OFFSET 0x1000
#define CONTINUATION_GENERATION 0xa1b00002
#define CONTINUATION_UNWIND_OFFSET 0x1000

struct continuation_frame
{
    BYTE xmm[16][16];
    DWORD mxcsr, reserved[3];
    ULONG64 gpr[15]; /* r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rbx,rdx,rcx,rax */
    ULONG64 flags, rip;
};
struct continuation_observation
{
    DWORD owner, common, target, phase;
    ULONG_PTR rsp, return_rip;
};
struct continuation_fault_result
{
    DWORD caught, rejected, native_caught, native_unchanged, pid, tid;
    DWORD code, flags, parameters, access, removed, released, teb_unchanged;
    ULONG_PTR address, rip, rsp, handler_rsp, native_rsp, native_return;
    ULONG_PTR stack_base, stack_limit;
};
struct continuation_unwind_event
{
    DWORD frame_id, flags, resource, reserved;
    ULONG_PTR frame, handler_rsp, control_pc, cookie;
};
struct continuation_unwind_result
{
    DWORD search_count, cleanup_count, target_count, landing_count, errors;
    DWORD pid, tid, code, flags, parameters, access, registered, removed, lookup_absent;
    DWORD released, tls_removed, native_bounds, native_identity, rejected, control_caught, control_unchanged;
    DWORD veh_search, handlers_removed, bounds_entered, bounds_restored;
    ULONG_PTR address, rip, rsp, native_rsp, native_return;
    ULONG_PTR stack_limit, stack_base, deallocation;
    ULONG_PTR native_limit, native_base, native_deallocation, teb, tls;
    ULONG_PTR landing_rsp, landing_rip;
    ULONG64 landing_local;
    struct continuation_unwind_event search[3], cleanup[3];
};
struct continuation_finally_event
{
    DWORD id, abnormal, resource, identity, error_mask;
    ULONG_PTR handler_rsp, resource_address, cookie_address;
    ULONG64 cookie;
};
struct continuation_finally_result
{
    DWORD entered, normal_returned, abnormal_returned, normal_count, abnormal_count, errors, metadata, resources_cleared;
    DWORD error_mask, protected_returned;
    ULONG_PTR helper_address, helper_image, fault_rsp;
    struct continuation_finally_event normal[2], abnormal[2];
};
struct continuation_data
{
    ULONG_PTR native_rsp, saved_rsp, saved_rip, initial_rsp, common, target, native_return;
    DWORD phase, state, cancelled, starts, completed, checks, errors, owner;
    DWORD generation, expected_generation, expected_owner, dispatches;
    ULONG64 accumulator;
    struct continuation_observation observations[5];
    ULONG_PTR native_after;
    DWORD native_checks, native_mxcsr;
    ULONG_PTR fault_scope, fault_address;
    DWORD fault_enabled;
    DWORD unwind_enabled;
    ULONG_PTR unwind_scope;
    DWORD resources[3], preserve_mappings;
    ULONG_PTR compiler_entry;
    DWORD compiler_enabled;
    BYTE reserved[0x200 - 0x15c];
    struct continuation_frame expected;
    struct continuation_fault_result fault;
    struct continuation_unwind_result unwind;
    struct continuation_finally_result finally;
};
C_ASSERT(sizeof(struct continuation_frame) == 0x198);
C_ASSERT(FIELD_OFFSET(struct continuation_frame, mxcsr) == 0x100);
C_ASSERT(FIELD_OFFSET(struct continuation_frame, gpr) == 0x110);
C_ASSERT(FIELD_OFFSET(struct continuation_frame, flags) == 0x188);
C_ASSERT(FIELD_OFFSET(struct continuation_frame, rip) == 0x190);
C_ASSERT(sizeof(struct continuation_observation) == 0x20);
C_ASSERT(FIELD_OFFSET(struct continuation_data, phase) == 0x38);
C_ASSERT(FIELD_OFFSET(struct continuation_data, state) == 0x3c);
C_ASSERT(FIELD_OFFSET(struct continuation_data, starts) == 0x44);
C_ASSERT(FIELD_OFFSET(struct continuation_data, completed) == 0x48);
C_ASSERT(FIELD_OFFSET(struct continuation_data, checks) == 0x4c);
C_ASSERT(FIELD_OFFSET(struct continuation_data, errors) == 0x50);
C_ASSERT(FIELD_OFFSET(struct continuation_data, owner) == 0x54);
C_ASSERT(FIELD_OFFSET(struct continuation_data, dispatches) == 0x64);
C_ASSERT(FIELD_OFFSET(struct continuation_data, accumulator) == 0x68);
C_ASSERT(FIELD_OFFSET(struct continuation_data, observations) == 0x70);
C_ASSERT(FIELD_OFFSET(struct continuation_data, expected) == 0x200);
C_ASSERT(FIELD_OFFSET(struct continuation_data, native_after) == 0x110);
C_ASSERT(FIELD_OFFSET(struct continuation_data, native_checks) == 0x118);
C_ASSERT(FIELD_OFFSET(struct continuation_data, native_mxcsr) == 0x11c);
extern const BYTE continuation_code_start[], continuation_code_end[];
extern const BYTE continuation_after_a[], continuation_after_b[];
extern const BYTE continuation_after_restore_a[], continuation_after_caller[], continuation_terminal[];
extern const BYTE continuation_root_return[], continuation_outer_return[], continuation_finish[];
extern const BYTE continuation_fault_instruction[], continuation_native_return[];
extern const BYTE continuation_root_prolog[], continuation_root_end[], continuation_unwind_landing[];
extern const BYTE continuation_outer_start[], continuation_outer_prolog[], continuation_outer_end[];
extern const BYTE continuation_inner_start[], continuation_inner_prolog[], continuation_inner_end[];
extern const BYTE continuation_unwind_thunk[], continuation_compiler_fault[];
C_ASSERT(FIELD_OFFSET(struct continuation_data, compiler_entry) == 0x150);
C_ASSERT(FIELD_OFFSET(struct continuation_data, compiler_enabled) == 0x158);
extern const BYTE native_fault_instruction[], native_fault_return[];
void WINAPI native_fault_control(void *);
C_ASSERT(FIELD_OFFSET(struct continuation_data, fault_scope) == 0x120);
C_ASSERT(FIELD_OFFSET(struct continuation_data, fault_address) == 0x128);
C_ASSERT(FIELD_OFFSET(struct continuation_data, fault_enabled) == 0x130);
C_ASSERT(FIELD_OFFSET(struct continuation_data, unwind_enabled) == 0x134);
C_ASSERT(FIELD_OFFSET(struct continuation_data, unwind_scope) == 0x138);
C_ASSERT(FIELD_OFFSET(struct continuation_data, resources) == 0x140);
C_ASSERT(FIELD_OFFSET(TEB, Tib.StackBase) == 0x8);
C_ASSERT(FIELD_OFFSET(TEB, Tib.StackLimit) == 0x10);
C_ASSERT(FIELD_OFFSET(TEB, DeallocationStack) == 0x1478);
void WINAPI invoke_continuation(struct continuation_data *, void *);

__ASM_GLOBAL_FUNC(continuation_code_start,
    "incl 0x44(%r15)\n\t"
    "subq $0x28,%rsp\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_root_prolog")) "\n\t"
    "cmpl $0,0x134(%r15)\n\t"
    "je 12f\n\t"
    "movl $0xcafe0001,0x140(%r15)\n\t"
    "12:\n\t"
    "movabsq $0x1122334455667788,%rax\n\t"
    "movq %rax,0x20(%rsp)\n\t"
    "movq $0x10,0x18(%rsp)\n\t"
    "call .Lcontinuation_sample\n\t"
    "call .Lcontinuation_outer\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_root_return")) "\n\t"
    "movabsq $0x1122334455667788,%rax\n\t"
    "cmpq %rax,0x20(%rsp)\n\t"
    "je 1f\n\t"
    "incl 0x50(%r15)\n\t"
    "1:\n\t"
    "call .Lcontinuation_sample\n\t"
    "cmpq $0x2b6,0x18(%rsp)\n\t"
    "je 9f\n\t"
    "incl 0x50(%r15)\n\t"
    "9:\n\t"
    "addq $0x28,%rsp\n\t"
    "ret\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_unwind_landing")) "\n\t"
    /* RtlUnwindEx supplies the current process-local scope in RAX and the
     * genuine surviving root RSP. Its shadow space is already allocated. */
    "movq %rax,%rcx\n\t"
    "movq %rsp,%rdx\n\t"
    "leaq " __ASM_NAME("continuation_unwind_landing") "(%rip),%r8\n\t"
    "movq 0x18(%rsp),%r9\n\t"
    "call *0x60(%rax)\n\t"
    "movq %rax,%r15\n\t"
    "movq 0(%r15),%rsp\n\t"
    "jmp *0x30(%r15)\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_root_end")) "\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_finish")) "\n\t"
    /* Root returns to this mapped completion thunk, never to a stale native
     * bridge. Reserve below its retired frame so terminal capture preserves
     * the completed root's mutable local for the native evidence check. */
    "subq $0x100,%rsp\n\t"
    "incl 0x48(%r15)\n\t"
    "movl $2,0x3c(%r15)\n\t"
    "movl $5,0x38(%r15)\n\t"
    "call .Lcontinuation_yield\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_terminal")) "\n\t"
    "ud2\n\t"
    ".Lcontinuation_outer:\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_outer_start")) "\n\t"
    "subq $0x28,%rsp\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_outer_prolog")) "\n\t"
    "cmpl $0,0x134(%r15)\n\t"
    "je 13f\n\t"
    "movl $0xcafe0002,0x144(%r15)\n\t"
    "13:\n\t"
    "movabsq $0x2233445566778899,%rax\n\t"
    "movq %rax,0x20(%rsp)\n\t"
    "movl $1,0x38(%r15)\n\t"
    "call .Lcontinuation_seed\n\t"
    "call .Lcontinuation_yield\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_after_a")) "\n\t"
    "call .Lcontinuation_check\n\t"
    "call .Lcontinuation_sample\n\t"
    "call .Lcontinuation_inner\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_outer_return")) "\n\t"
    "movabsq $0x2233445566778899,%rax\n\t"
    "cmpq %rax,0x20(%rsp)\n\t"
    "je 2f\n\t"
    "incl 0x50(%r15)\n\t"
    "2:\n\t"
    "call .Lcontinuation_sample\n\t"
    "movl $4,0x38(%r15)\n\t"
    "call .Lcontinuation_seed\n\t"
    "call .Lcontinuation_yield\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_after_caller")) "\n\t"
    "call .Lcontinuation_check\n\t"
    "addq $0x28,%rsp\n\t"
    "ret\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_outer_end")) "\n\t"
    ".Lcontinuation_inner:\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_inner_start")) "\n\t"
    "subq $0x28,%rsp\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_inner_prolog")) "\n\t"
    "cmpl $0,0x134(%r15)\n\t"
    "je 14f\n\t"
    "movl $0xcafe0003,0x148(%r15)\n\t"
    "14:\n\t"
    "movabsq $0x33445566778899aa,%rax\n\t"
    "movq %rax,0x20(%rsp)\n\t"
    "movl $2,0x38(%r15)\n\t"
    "call .Lcontinuation_seed\n\t"
    "call .Lcontinuation_yield\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_after_b")) "\n\t"
    "call .Lcontinuation_check\n\t"
    "call .Lcontinuation_sample\n\t"
    "cmpl $0,0x158(%r15)\n\t"
    "je 17f\n\t"
    /* The PE helper is resolved in the current host after migration. Its
     * compiler-generated scopes are entered in B, never copied or relocated. */
    "movq 0x138(%r15),%rcx\n\t"
    "call *0x150(%r15)\n\t"
    "ud2\n\t"
    "17:\n\t"
    "cmpl $0,0x130(%r15)\n\t"
    "je 10f\n\t"
    "movq 0x128(%r15),%rax\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_fault_instruction")) "\n\t"
    "movzbl (%rax),%eax\n\t"
    "10:\n\t"
    "movl $3,0x38(%r15)\n\t"
    "call .Lcontinuation_seed\n\t"
    "call .Lcontinuation_yield\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_after_restore_a")) "\n\t"
    "call .Lcontinuation_check\n\t"
    "movabsq $0x33445566778899aa,%rax\n\t"
    "cmpq %rax,0x20(%rsp)\n\t"
    "je 3f\n\t"
    "incl 0x50(%r15)\n\t"
    "3:\n\t"
    "addq $0x28,%rsp\n\t"
    "ret\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_inner_end")) "\n\t"
    ".Lcontinuation_sample:\n\t"
    "movl 0x38(%r15),%ecx\n\t"
    "shlq $5,%rcx\n\t"
    "leaq 0x70(%r15,%rcx),%rdx\n\t"
    "movl 0x54(%r15),%eax\n\t"
    "movl %eax,0(%rdx)\n\t"
    "movq 0x20(%r15),%rax\n\t"
    "movzbl (%rax),%eax\n\t"
    "movl %eax,4(%rdx)\n\t"
    "addq %rax,0x68(%r15)\n\t"
    "movq 0x18(%r15),%rcx\n\t"
    "addq %rax,-0x10(%rcx)\n\t"
    "movl $0,8(%rdx)\n\t"
    "cmpl $0,0x38(%r15)\n\t"
    "je 4f\n\t"
    "cmpl $4,0x38(%r15)\n\t"
    "je 4f\n\t"
    "movq 0x28(%r15),%rax\n\t"
    "movzbl (%rax),%eax\n\t"
    "movl %eax,8(%rdx)\n\t"
    "4:\n\t"
    "movl 0x38(%r15),%eax\n\t"
    "movl %eax,12(%rdx)\n\t"
    "movq %rsp,16(%rdx)\n\t"
    "movq (%rsp),%rax\n\t"
    "movq %rax,24(%rdx)\n\t"
    "ret\n\t"
    ".Lcontinuation_seed:\n\t"
    "movdqu 0x200(%r15),%xmm0\n\t"
    "movdqu 0x210(%r15),%xmm1\n\t"
    "movdqu 0x220(%r15),%xmm2\n\t"
    "movdqu 0x230(%r15),%xmm3\n\t"
    "movdqu 0x240(%r15),%xmm4\n\t"
    "movdqu 0x250(%r15),%xmm5\n\t"
    "movdqu 0x260(%r15),%xmm6\n\t"
    "movdqu 0x270(%r15),%xmm7\n\t"
    "movdqu 0x280(%r15),%xmm8\n\t"
    "movdqu 0x290(%r15),%xmm9\n\t"
    "movdqu 0x2a0(%r15),%xmm10\n\t"
    "movdqu 0x2b0(%r15),%xmm11\n\t"
    "movdqu 0x2c0(%r15),%xmm12\n\t"
    "movdqu 0x2d0(%r15),%xmm13\n\t"
    "movdqu 0x2e0(%r15),%xmm14\n\t"
    "movdqu 0x2f0(%r15),%xmm15\n\t"
    "ldmxcsr 0x300(%r15)\n\t"
    "movq 0x380(%r15),%rax\n\t"
    "movq 0x378(%r15),%rcx\n\t"
    "movq 0x370(%r15),%rdx\n\t"
    "movq 0x368(%r15),%rbx\n\t"
    "movq 0x360(%r15),%rbp\n\t"
    "movq 0x358(%r15),%rsi\n\t"
    "movq 0x350(%r15),%rdi\n\t"
    "movq 0x348(%r15),%r8\n\t"
    "movq 0x340(%r15),%r9\n\t"
    "movq 0x338(%r15),%r10\n\t"
    "movq 0x330(%r15),%r11\n\t"
    "movq 0x328(%r15),%r12\n\t"
    "movq 0x320(%r15),%r13\n\t"
    "movq 0x318(%r15),%r14\n\t"
    "pushq $0x247\n\t"
    "popfq\n\t"
    "ret\n\t"
    ".Lcontinuation_check:\n\t"
    "pushfq\n\t"
    "pushq %rax\n\t"
    "pushq %rcx\n\t"
    "pushq %rdx\n\t"
    "pushq %rbx\n\t"
    "pushq %rbp\n\t"
    "pushq %rsi\n\t"
    "pushq %rdi\n\t"
    "pushq %r8\n\t"
    "pushq %r9\n\t"
    "pushq %r10\n\t"
    "pushq %r11\n\t"
    "pushq %r12\n\t"
    "pushq %r13\n\t"
    "pushq %r14\n\t"
    "pushq %r15\n\t"
    "subq $0x110,%rsp\n\t"
    "movdqu %xmm0,0x0(%rsp)\n\t"
    "movdqu %xmm1,0x10(%rsp)\n\t"
    "movdqu %xmm2,0x20(%rsp)\n\t"
    "movdqu %xmm3,0x30(%rsp)\n\t"
    "movdqu %xmm4,0x40(%rsp)\n\t"
    "movdqu %xmm5,0x50(%rsp)\n\t"
    "movdqu %xmm6,0x60(%rsp)\n\t"
    "movdqu %xmm7,0x70(%rsp)\n\t"
    "movdqu %xmm8,0x80(%rsp)\n\t"
    "movdqu %xmm9,0x90(%rsp)\n\t"
    "movdqu %xmm10,0xa0(%rsp)\n\t"
    "movdqu %xmm11,0xb0(%rsp)\n\t"
    "movdqu %xmm12,0xc0(%rsp)\n\t"
    "movdqu %xmm13,0xd0(%rsp)\n\t"
    "movdqu %xmm14,0xe0(%rsp)\n\t"
    "movdqu %xmm15,0xf0(%rsp)\n\t"
    "stmxcsr 0x100(%rsp)\n\t"
    "cld\n\t"
    "leaq 0(%rsp),%rsi\n\t"
    "leaq 0x200(%r15),%rdi\n\t"
    "movl $32,%ecx\n\t"
    "repe cmpsq\n\t"
    "jne .Lcontinuation_bad\n\t"
    "movl 0x100(%rsp),%eax\n\t"
    "cmpl 0x300(%r15),%eax\n\t"
    "jne .Lcontinuation_bad\n\t"
    "leaq 0x110(%rsp),%rsi\n\t"
    "leaq 0x310(%r15),%rdi\n\t"
    "movl $15,%ecx\n\t"
    "repe cmpsq\n\t"
    "jne .Lcontinuation_bad\n\t"
    "movq 0x188(%rsp),%rax\n\t"
    "andq $0x8d5,%rax\n\t"
    "cmpq $0x45,%rax\n\t"
    "jne .Lcontinuation_bad\n\t"
    "incl 0x4c(%r15)\n\t"
    "jmp .Lcontinuation_checked\n\t"
    ".Lcontinuation_bad:\n\t"
    "incl 0x50(%r15)\n\t"
    ".Lcontinuation_checked:\n\t"
    "movdqu 0x0(%rsp),%xmm0\n\t"
    "movdqu 0x10(%rsp),%xmm1\n\t"
    "movdqu 0x20(%rsp),%xmm2\n\t"
    "movdqu 0x30(%rsp),%xmm3\n\t"
    "movdqu 0x40(%rsp),%xmm4\n\t"
    "movdqu 0x50(%rsp),%xmm5\n\t"
    "movdqu 0x60(%rsp),%xmm6\n\t"
    "movdqu 0x70(%rsp),%xmm7\n\t"
    "movdqu 0x80(%rsp),%xmm8\n\t"
    "movdqu 0x90(%rsp),%xmm9\n\t"
    "movdqu 0xa0(%rsp),%xmm10\n\t"
    "movdqu 0xb0(%rsp),%xmm11\n\t"
    "movdqu 0xc0(%rsp),%xmm12\n\t"
    "movdqu 0xd0(%rsp),%xmm13\n\t"
    "movdqu 0xe0(%rsp),%xmm14\n\t"
    "movdqu 0xf0(%rsp),%xmm15\n\t"
    "ldmxcsr 0x100(%rsp)\n\t"
    "addq $0x110,%rsp\n\t"
    "popq %r15\n\t"
    "popq %r14\n\t"
    "popq %r13\n\t"
    "popq %r12\n\t"
    "popq %r11\n\t"
    "popq %r10\n\t"
    "popq %r9\n\t"
    "popq %r8\n\t"
    "popq %rdi\n\t"
    "popq %rsi\n\t"
    "popq %rbp\n\t"
    "popq %rbx\n\t"
    "popq %rdx\n\t"
    "popq %rcx\n\t"
    "popq %rax\n\t"
    "popfq\n\t"
    "ret\n\t"
    ".Lcontinuation_yield:\n\t"
    "pushfq\n\t"
    "pushq %rax\n\t"
    "pushq %rcx\n\t"
    "pushq %rdx\n\t"
    "pushq %rbx\n\t"
    "pushq %rbp\n\t"
    "pushq %rsi\n\t"
    "pushq %rdi\n\t"
    "pushq %r8\n\t"
    "pushq %r9\n\t"
    "pushq %r10\n\t"
    "pushq %r11\n\t"
    "pushq %r12\n\t"
    "pushq %r13\n\t"
    "pushq %r14\n\t"
    "pushq %r15\n\t"
    "subq $0x110,%rsp\n\t"
    "movdqu %xmm0,0x0(%rsp)\n\t"
    "movdqu %xmm1,0x10(%rsp)\n\t"
    "movdqu %xmm2,0x20(%rsp)\n\t"
    "movdqu %xmm3,0x30(%rsp)\n\t"
    "movdqu %xmm4,0x40(%rsp)\n\t"
    "movdqu %xmm5,0x50(%rsp)\n\t"
    "movdqu %xmm6,0x60(%rsp)\n\t"
    "movdqu %xmm7,0x70(%rsp)\n\t"
    "movdqu %xmm8,0x80(%rsp)\n\t"
    "movdqu %xmm9,0x90(%rsp)\n\t"
    "movdqu %xmm10,0xa0(%rsp)\n\t"
    "movdqu %xmm11,0xb0(%rsp)\n\t"
    "movdqu %xmm12,0xc0(%rsp)\n\t"
    "movdqu %xmm13,0xd0(%rsp)\n\t"
    "movdqu %xmm14,0xe0(%rsp)\n\t"
    "movdqu %xmm15,0xf0(%rsp)\n\t"
    "stmxcsr 0x100(%rsp)\n\t"
    "movq %rsp,8(%r15)\n\t"
    "movq 0x190(%rsp),%rax\n\t"
    "movq %rax,16(%r15)\n\t"
    "cmpl $2,0x3c(%r15)\n\t"
    "je 5f\n\t"
    "movl $1,0x3c(%r15)\n\t"
    "5:\n\t"
    "movq 0(%r15),%rsp\n\t"
    "jmp *0x30(%r15)\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_unwind_thunk")) "\n\t"
    /* A leaf tail thunk: R9 is the actual DISPATCHER_CONTEXT. Resolve the
     * current host's handler from ImageBase, never from a migrated register. */
    "movq 8(%r9),%rax\n\t"
    "movq 0x11138(%rax),%rax\n\t"
    "jmp *0x58(%rax)\n\t"
    /* A genuine ordinary-read fault leaf called inside compiler scopes. With
     * no stack adjustment it uses the x64 leaf virtual-unwind convention. */
    __ASM_GLOBL(__ASM_NAME("continuation_compiler_fault")) "\n\t"
    "movzbl (%rcx),%eax\n\t"
    "ret\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_code_end")) "\n\t")

__ASM_GLOBAL_FUNC(invoke_continuation,
    "pushq %rbx\n\t"
    __ASM_SEH(".seh_pushreg %rbx\n\t")
    "pushq %rbp\n\t"
    __ASM_SEH(".seh_pushreg %rbp\n\t")
    "pushq %rsi\n\t"
    __ASM_SEH(".seh_pushreg %rsi\n\t")
    "pushq %rdi\n\t"
    __ASM_SEH(".seh_pushreg %rdi\n\t")
    "pushq %r12\n\t"
    __ASM_SEH(".seh_pushreg %r12\n\t")
    "pushq %r13\n\t"
    __ASM_SEH(".seh_pushreg %r13\n\t")
    "pushq %r14\n\t"
    __ASM_SEH(".seh_pushreg %r14\n\t")
    "pushq %r15\n\t"
    __ASM_SEH(".seh_pushreg %r15\n\t")
    "subq $0xb8,%rsp\n\t"
    __ASM_SEH(".seh_stackalloc 0xb8\n\t")
    "movdqu %xmm6,0x0(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm6,0x0\n\t")
    "movdqu %xmm7,0x10(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm7,0x10\n\t")
    "movdqu %xmm8,0x20(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm8,0x20\n\t")
    "movdqu %xmm9,0x30(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm9,0x30\n\t")
    "movdqu %xmm10,0x40(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm10,0x40\n\t")
    "movdqu %xmm11,0x50(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm11,0x50\n\t")
    "movdqu %xmm12,0x60(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm12,0x60\n\t")
    "movdqu %xmm13,0x70(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm13,0x70\n\t")
    "movdqu %xmm14,0x80(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm14,0x80\n\t")
    "movdqu %xmm15,0x90(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm15,0x90\n\t")
    __ASM_SEH(".seh_endprologue\n\t")
    "stmxcsr 0xa0(%rsp)\n\t"
    "movq %rcx,0xa8(%rsp)\n\t"
    "movq %rsp,0(%rcx)\n\t"
    "leaq " __ASM_NAME("continuation_native_return") "(%rip),%rax\n\t"
    "movq %rax,0x30(%rcx)\n\t"
    /* Capture the actual current bridge in process-local storage, separate
     * from the shared fields that are overwritten by every host. */
    "movq 0x120(%rcx),%r8\n\t"
    "testq %r8,%r8\n\t"
    "jz 11f\n\t"
    "movq %rsp,0(%r8)\n\t"
    "movq %rax,8(%r8)\n\t"
    "11:\n\t"
    "movq 0x138(%rcx),%r8\n\t"
    "testq %r8,%r8\n\t"
    "jz 15f\n\t"
    "movq %rsp,0(%r8)\n\t"
    "movq %rax,8(%r8)\n\t"
    /* Table SEH must see truthful bounds for the single currently active
     * stack. Change them only after all native calls, just before migration. */
    "movq 0x18(%r8),%rax\n\t"
    "movq %rax,%gs:0x10\n\t"
    "movq %rax,%gs:0x1478\n\t"
    "movq 0x20(%r8),%rax\n\t"
    "movq %rax,%gs:0x8\n\t"
    "incl 0xb0(%r8)\n\t"
    "15:\n\t"
    "movq %rcx,%r15\n\t"
    "cmpl $0,0x3c(%r15)\n\t"
    "jne .Lcontinuation_resume\n\t"
    "movq 0x18(%r15),%rsp\n\t"
    "jmp *%rdx\n\t"
    ".Lcontinuation_resume:\n\t"
    "movq 8(%r15),%rsp\n\t"
    "movdqu 0x0(%rsp),%xmm0\n\t"
    "movdqu 0x10(%rsp),%xmm1\n\t"
    "movdqu 0x20(%rsp),%xmm2\n\t"
    "movdqu 0x30(%rsp),%xmm3\n\t"
    "movdqu 0x40(%rsp),%xmm4\n\t"
    "movdqu 0x50(%rsp),%xmm5\n\t"
    "movdqu 0x60(%rsp),%xmm6\n\t"
    "movdqu 0x70(%rsp),%xmm7\n\t"
    "movdqu 0x80(%rsp),%xmm8\n\t"
    "movdqu 0x90(%rsp),%xmm9\n\t"
    "movdqu 0xa0(%rsp),%xmm10\n\t"
    "movdqu 0xb0(%rsp),%xmm11\n\t"
    "movdqu 0xc0(%rsp),%xmm12\n\t"
    "movdqu 0xd0(%rsp),%xmm13\n\t"
    "movdqu 0xe0(%rsp),%xmm14\n\t"
    "movdqu 0xf0(%rsp),%xmm15\n\t"
    "ldmxcsr 0x100(%rsp)\n\t"
    "addq $0x110,%rsp\n\t"
    "popq %r15\n\t"
    "popq %r14\n\t"
    "popq %r13\n\t"
    "popq %r12\n\t"
    "popq %r11\n\t"
    "popq %r10\n\t"
    "popq %r9\n\t"
    "popq %r8\n\t"
    "popq %rdi\n\t"
    "popq %rsi\n\t"
    "popq %rbp\n\t"
    "popq %rbx\n\t"
    "popq %rdx\n\t"
    "popq %rcx\n\t"
    "popq %rax\n\t"
    "popfq\n\t"
    "ret\n\t"
    __ASM_GLOBL(__ASM_NAME("continuation_native_return")) "\n\t"
    /* Restore the real native stack description before the canary caller or
     * any ordinary native-host code can execute. Other modes leave it alone. */
    "movq 0xa8(%rsp),%rax\n\t"
    "movq 0x138(%rax),%r8\n\t"
    "testq %r8,%r8\n\t"
    "jz 16f\n\t"
    "movq 0x28(%r8),%rax\n\t"
    "movq %rax,%gs:0x10\n\t"
    "movq 0x30(%r8),%rax\n\t"
    "movq %rax,%gs:0x8\n\t"
    "movq 0x38(%r8),%rax\n\t"
    "movq %rax,%gs:0x1478\n\t"
    "incl 0xb4(%r8)\n\t"
    "16:\n\t"
    "movdqu 0x0(%rsp),%xmm6\n\t"
    "movdqu 0x10(%rsp),%xmm7\n\t"
    "movdqu 0x20(%rsp),%xmm8\n\t"
    "movdqu 0x30(%rsp),%xmm9\n\t"
    "movdqu 0x40(%rsp),%xmm10\n\t"
    "movdqu 0x50(%rsp),%xmm11\n\t"
    "movdqu 0x60(%rsp),%xmm12\n\t"
    "movdqu 0x70(%rsp),%xmm13\n\t"
    "movdqu 0x80(%rsp),%xmm14\n\t"
    "movdqu 0x90(%rsp),%xmm15\n\t"
    "ldmxcsr 0xa0(%rsp)\n\t"
    "movq 0xa8(%rsp),%rax\n\t"
    "cmpq 0(%rax),%rsp\n\t"
    "je 6f\n\t"
    "incl 0x50(%rax)\n\t"
    "6:\n\t"
    "movq %rsp,0x110(%rax)\n\t"
    "incl 0x64(%rax)\n\t"
    "addq $0xb8,%rsp\n\t"
    "popq %r15\n\t"
    "popq %r14\n\t"
    "popq %r13\n\t"
    "popq %r12\n\t"
    "popq %rdi\n\t"
    "popq %rsi\n\t"
    "popq %rbp\n\t"
    "popq %rbx\n\t"
    "ret\n\t")


/* Canary caller tests every native Win64 nonvolatile GPR and XMM register with
 * values different from the logical continuation, plus a different MXCSR. */
void WINAPI invoke_continuation_control(struct continuation_data *, void *);
__ASM_GLOBAL_FUNC(invoke_continuation_control,
    "pushq %rbx\n\t"
    __ASM_SEH(".seh_pushreg %rbx\n\t")
    "pushq %rbp\n\t"
    __ASM_SEH(".seh_pushreg %rbp\n\t")
    "pushq %rsi\n\t"
    __ASM_SEH(".seh_pushreg %rsi\n\t")
    "pushq %rdi\n\t"
    __ASM_SEH(".seh_pushreg %rdi\n\t")
    "pushq %r12\n\t"
    __ASM_SEH(".seh_pushreg %r12\n\t")
    "pushq %r13\n\t"
    __ASM_SEH(".seh_pushreg %r13\n\t")
    "pushq %r14\n\t"
    __ASM_SEH(".seh_pushreg %r14\n\t")
    "pushq %r15\n\t"
    __ASM_SEH(".seh_pushreg %r15\n\t")
    "subq $0xd8,%rsp\n\t"
    __ASM_SEH(".seh_stackalloc 0xd8\n\t")
    "movdqu %xmm6,0x20(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm6,0x20\n\t")
    "movdqu %xmm7,0x30(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm7,0x30\n\t")
    "movdqu %xmm8,0x40(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm8,0x40\n\t")
    "movdqu %xmm9,0x50(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm9,0x50\n\t")
    "movdqu %xmm10,0x60(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm10,0x60\n\t")
    "movdqu %xmm11,0x70(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm11,0x70\n\t")
    "movdqu %xmm12,0x80(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm12,0x80\n\t")
    "movdqu %xmm13,0x90(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm13,0x90\n\t")
    "movdqu %xmm14,0xa0(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm14,0xa0\n\t")
    "movdqu %xmm15,0xb0(%rsp)\n\t"
    __ASM_SEH(".seh_savexmm %xmm15,0xb0\n\t")
    __ASM_SEH(".seh_endprologue\n\t")
    "stmxcsr 0xc0(%rsp)\n\t"
    "movq %rcx,0xc8(%rsp)\n\t"
    "movq %rdx,0xd0(%rsp)\n\t"
    "movl $0x3f80,0x11c(%rcx)\n\t"
    "ldmxcsr 0x11c(%rcx)\n\t"
    "pcmpeqd %xmm0,%xmm0\n\t"
    "movdqu 0x200(%rcx),%xmm1\n\t"
    "pxor %xmm0,%xmm1\n\t"
    "movdqa %xmm1,%xmm6\n\t"
    "movdqa %xmm1,%xmm7\n\t"
    "movdqa %xmm1,%xmm8\n\t"
    "movdqa %xmm1,%xmm9\n\t"
    "movdqa %xmm1,%xmm10\n\t"
    "movdqa %xmm1,%xmm11\n\t"
    "movdqa %xmm1,%xmm12\n\t"
    "movdqa %xmm1,%xmm13\n\t"
    "movdqa %xmm1,%xmm14\n\t"
    "movdqa %xmm1,%xmm15\n\t"
    "movabsq $0xf123000000000000,%rbx\n\t"
    "movabsq $0xf123000000000001,%rbp\n\t"
    "movabsq $0xf123000000000002,%rsi\n\t"
    "movabsq $0xf123000000000003,%rdi\n\t"
    "movabsq $0xf123000000000004,%r12\n\t"
    "movabsq $0xf123000000000005,%r13\n\t"
    "movabsq $0xf123000000000006,%r14\n\t"
    "movabsq $0xf123000000000007,%r15\n\t"
    "call " __ASM_NAME("invoke_continuation") "\n\t"
    "movq 0xc8(%rsp),%rcx\n\t"
    "movabsq $0xf123000000000000,%rax\n\t"
    "cmpq %rax,%rbx\n\t"
    "jne .Lnative_bad_0\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_0\n\t"
    ".Lnative_bad_0:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_0:\n\t"
    "movabsq $0xf123000000000001,%rax\n\t"
    "cmpq %rax,%rbp\n\t"
    "jne .Lnative_bad_1\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_1\n\t"
    ".Lnative_bad_1:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_1:\n\t"
    "movabsq $0xf123000000000002,%rax\n\t"
    "cmpq %rax,%rsi\n\t"
    "jne .Lnative_bad_2\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_2\n\t"
    ".Lnative_bad_2:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_2:\n\t"
    "movabsq $0xf123000000000003,%rax\n\t"
    "cmpq %rax,%rdi\n\t"
    "jne .Lnative_bad_3\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_3\n\t"
    ".Lnative_bad_3:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_3:\n\t"
    "movabsq $0xf123000000000004,%rax\n\t"
    "cmpq %rax,%r12\n\t"
    "jne .Lnative_bad_4\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_4\n\t"
    ".Lnative_bad_4:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_4:\n\t"
    "movabsq $0xf123000000000005,%rax\n\t"
    "cmpq %rax,%r13\n\t"
    "jne .Lnative_bad_5\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_5\n\t"
    ".Lnative_bad_5:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_5:\n\t"
    "movabsq $0xf123000000000006,%rax\n\t"
    "cmpq %rax,%r14\n\t"
    "jne .Lnative_bad_6\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_6\n\t"
    ".Lnative_bad_6:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_6:\n\t"
    "movabsq $0xf123000000000007,%rax\n\t"
    "cmpq %rax,%r15\n\t"
    "jne .Lnative_bad_7\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_end_7\n\t"
    ".Lnative_bad_7:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_end_7:\n\t"
    "pcmpeqd %xmm0,%xmm0\n\t"
    "movdqu 0x200(%rcx),%xmm1\n\t"
    "pxor %xmm0,%xmm1\n\t"
    "movdqa %xmm6,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_6\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_6\n\t"
    ".Lnative_xmm_bad_6:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_6:\n\t"
    "movdqa %xmm7,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_7\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_7\n\t"
    ".Lnative_xmm_bad_7:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_7:\n\t"
    "movdqa %xmm8,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_8\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_8\n\t"
    ".Lnative_xmm_bad_8:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_8:\n\t"
    "movdqa %xmm9,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_9\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_9\n\t"
    ".Lnative_xmm_bad_9:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_9:\n\t"
    "movdqa %xmm10,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_10\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_10\n\t"
    ".Lnative_xmm_bad_10:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_10:\n\t"
    "movdqa %xmm11,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_11\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_11\n\t"
    ".Lnative_xmm_bad_11:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_11:\n\t"
    "movdqa %xmm12,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_12\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_12\n\t"
    ".Lnative_xmm_bad_12:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_12:\n\t"
    "movdqa %xmm13,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_13\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_13\n\t"
    ".Lnative_xmm_bad_13:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_13:\n\t"
    "movdqa %xmm14,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_14\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_14\n\t"
    ".Lnative_xmm_bad_14:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_14:\n\t"
    "movdqa %xmm15,%xmm2\n\t"
    "pcmpeqb %xmm1,%xmm2\n\t"
    "pmovmskb %xmm2,%eax\n\t"
    "cmpl $0xffff,%eax\n\t"
    "jne .Lnative_xmm_bad_15\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp .Lnative_xmm_end_15\n\t"
    ".Lnative_xmm_bad_15:\n\t"
    "incl 0x50(%rcx)\n\t"
    ".Lnative_xmm_end_15:\n\t"
    "stmxcsr 0(%rsp)\n\t"
    "cmpl $0x3f80,0(%rsp)\n\t"
    "jne 7f\n\t"
    "incl 0x118(%rcx)\n\t"
    "jmp 8f\n\t"
    "7:\n\t"
    "incl 0x50(%rcx)\n\t"
    "8:\n\t"
    "movdqu 0x20(%rsp),%xmm6\n\t"
    "movdqu 0x30(%rsp),%xmm7\n\t"
    "movdqu 0x40(%rsp),%xmm8\n\t"
    "movdqu 0x50(%rsp),%xmm9\n\t"
    "movdqu 0x60(%rsp),%xmm10\n\t"
    "movdqu 0x70(%rsp),%xmm11\n\t"
    "movdqu 0x80(%rsp),%xmm12\n\t"
    "movdqu 0x90(%rsp),%xmm13\n\t"
    "movdqu 0xa0(%rsp),%xmm14\n\t"
    "movdqu 0xb0(%rsp),%xmm15\n\t"
    "ldmxcsr 0xc0(%rsp)\n\t"
    "addq $0xd8,%rsp\n\t"
    "popq %r15\n\t"
    "popq %r14\n\t"
    "popq %r13\n\t"
    "popq %r12\n\t"
    "popq %rdi\n\t"
    "popq %rsi\n\t"
    "popq %rbp\n\t"
    "popq %rbx\n\t"
    "ret\n\t")

__ASM_GLOBAL_FUNC(native_fault_control,
    __ASM_SEH(".seh_endprologue\n\t")
    __ASM_GLOBL(__ASM_NAME("native_fault_instruction")) "\n\t"
    "movzbl (%rcx),%eax\n\t"
    __ASM_GLOBL(__ASM_NAME("native_fault_return")) "\n\t"
    "ret\n\t")

struct attachment_shared
{
    ULONG_PTR common_address;
    ULONG_PTR target_address;
    DWORD error[2];
    HANDLE execution_mapping[3], run[2], done[2];
    ULONG_PTR execution_address[3];
    DWORD protection[2][3], collision_ok[2], observed_sequence[2], process_id[2];
    DWORD continuation_mode, continuation_accepted[2];
};

static BOOL map_execution_regions(struct attachment_shared *shared, void **regions, DWORD *protection)
{
    MEMORY_BASIC_INFORMATION info;
    unsigned int i;

    for (i = 0; i < 3; ++i)
    {
        DWORD access = i ? FILE_MAP_READ | FILE_MAP_WRITE : FILE_MAP_READ | FILE_MAP_EXECUTE;
        regions[i] = MapViewOfFileEx(shared->execution_mapping[i], access,
                0, 0, EXECUTION_REGION_SIZE, (void *)shared->execution_address[i]);
        if (!regions[i]) return FALSE;
        if (regions[i] != (void *)shared->execution_address[i])
        {
            SetLastError(ERROR_INVALID_ADDRESS);
            return FALSE;
        }
        if (!VirtualQuery(regions[i], &info, sizeof(info))) return FALSE;
        protection[i] = info.Protect;
        if (info.State != MEM_COMMIT || info.Type != MEM_MAPPED
                || info.Protect != (i ? PAGE_READWRITE : PAGE_EXECUTE_READ))
        {
            SetLastError(ERROR_INVALID_ACCESS);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL execution_collision_control(struct attachment_shared *shared, BYTE *sentinel)
{
    MEMORY_BASIC_INFORMATION info;
    void *collision;
    BYTE value = *sentinel;
    BOOL ret;

    collision = MapViewOfFileEx(shared->execution_mapping[0], FILE_MAP_READ | FILE_MAP_EXECUTE,
            0, 0, EXECUTION_REGION_SIZE, sentinel);
    ret = !collision && *sentinel == value
            && VirtualQuery(sentinel, &info, sizeof(info))
            && info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && info.Protect == PAGE_READWRITE;
    if (collision) UnmapViewOfFile(collision);
    return ret;
}


static ULONG_PTR continuation_address(void *code, const BYTE *label)
{
    return (ULONG_PTR)code + CONTINUATION_CODE_OFFSET + (label - continuation_code_start);
}

/* A process-local, serial dispatch scope. Static storage remains valid even if
 * handler removal fails; disarming before cleanup leaves no dangling pointer.
 * This is an exact first-chance abort catcher, not synthetic-stack unwinding. */
struct continuation_fault_scope
{
    ULONG_PTR native_rsp, native_return; /* Written only by the current bridge. */
    struct continuation_data *data;
    ULONG_PTR stack_low, stack_high, expected_rsp, fault_rip, address;
    ULONG_PTR native_low, native_high, control_rip, control_rsp, control_r15;
    DWORD pid, tid, generation, phase, armed, native_control;
};
C_ASSERT(FIELD_OFFSET(struct continuation_fault_scope, native_rsp) == 0);
C_ASSERT(FIELD_OFFSET(struct continuation_fault_scope, native_return) == 8);
static struct continuation_fault_scope fault_scope;

/* Each entry is immutable mapped RX metadata, relative to the mapped code
 * image. The table itself and every handler address are process-local. */
struct continuation_unwind_info
{
    BYTE version_flags, prolog, count, frame, code_offset, operation;
    WORD padding;
    DWORD handler, frame_id;
};
C_ASSERT(sizeof(struct continuation_unwind_info) == 16);

struct continuation_unwind_scope
{
    ULONG_PTR native_rsp, native_return;
    struct continuation_data *data;
    ULONG_PTR stack_low, stack_high, native_low, native_high, native_deallocation;
    DWORD pid, tid, generation, phase, armed, tls_index;
    EXCEPTION_DISPOSITION (WINAPI *handler)(EXCEPTION_RECORD *, void *, CONTEXT *, DISPATCHER_CONTEXT *);
    struct continuation_data *(WINAPI *landing)(struct continuation_unwind_scope *, ULONG_PTR, ULONG_PTR, ULONG64);
    TEB *teb;
    void *tls;
    ULONG_PTR code, fault_rip, address, control_rip, control_rsp, control_r15;
    DWORD native_control, registered, bounds_entered, bounds_restored;
    RUNTIME_FUNCTION table[3];
    CONTEXT context;
    UNWIND_HISTORY_TABLE history;
    ULONG_PTR compiler_fault_rsp;
    DWORD compiler_running;
};
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, stack_low) == 0x18);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, stack_high) == 0x20);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, native_low) == 0x28);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, native_high) == 0x30);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, native_deallocation) == 0x38);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, handler) == 0x58);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, landing) == 0x60);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, bounds_entered) == 0xb0);
C_ASSERT(FIELD_OFFSET(struct continuation_unwind_scope, bounds_restored) == 0xb4);
static struct continuation_unwind_scope unwind_scope;
static BOOLEAN (CDECL *pContinuationAddFunctionTable)(RUNTIME_FUNCTION *, DWORD, ULONG_PTR);
static BOOLEAN (CDECL *pContinuationDeleteFunctionTable)(RUNTIME_FUNCTION *);
static RUNTIME_FUNCTION *(WINAPI *pContinuationLookupFunctionEntry)(ULONG_PTR, ULONG_PTR *, UNWIND_HISTORY_TABLE *);
static void (WINAPI *pContinuationUnwindEx)(void *, void *, EXCEPTION_RECORD *, void *, CONTEXT *, UNWIND_HISTORY_TABLE *);

static void initialize_continuation_unwind_info(void *code)
{
    static const BYTE * const starts[] = {continuation_code_start, continuation_outer_start, continuation_inner_start};
    static const BYTE * const prologs[] = {continuation_root_prolog, continuation_outer_prolog, continuation_inner_prolog};
    struct continuation_unwind_info *info = (void *)((BYTE *)code + CONTINUATION_UNWIND_OFFSET);
    unsigned int i;

    for (i = 0; i < 3; ++i)
    {
        memset(&info[i], 0, sizeof(info[i]));
        info[i].version_flags = 1 | ((UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) << 3);
        info[i].prolog = info[i].code_offset = prologs[i] - starts[i];
        info[i].count = 1;
        info[i].operation = 0x42; /* UWOP_ALLOC_SMALL: actual subq $0x28,%rsp. */
        info[i].handler = CONTINUATION_CODE_OFFSET + (continuation_unwind_thunk - continuation_code_start);
        info[i].frame_id = i;
    }
}

static BOOL continuation_unwind_identity(struct continuation_unwind_scope *scope, BOOL shared_stack)
{
    TEB *teb = NtCurrentTeb();

    return teb == scope->teb && (ULONG_PTR)teb->ClientId.UniqueProcess == scope->pid
            && (ULONG_PTR)teb->ClientId.UniqueThread == scope->tid
            && teb->ThreadLocalStoragePointer == scope->tls && TlsGetValue(scope->tls_index) == scope
            && (ULONG_PTR)teb->Tib.StackLimit == (shared_stack ? scope->stack_low : scope->native_low)
            && (ULONG_PTR)teb->Tib.StackBase == (shared_stack ? scope->stack_high : scope->native_high)
            && (ULONG_PTR)teb->DeallocationStack == (shared_stack ? scope->stack_low : scope->native_deallocation);
}

#ifdef USE_COMPILER_EXCEPTIONS
/* These finally bodies belong to the linked PE's compiler-generated scope
 * table. No wrapper invokes their cleanup path. Volatile locals force the
 * outlined funclets to recover genuine parent-frame resources and cookies. */
static void record_compiler_finally(struct continuation_unwind_scope *scope, DWORD id, BOOL abnormal,
        volatile DWORD *resource, volatile ULONG64 *cookie)
{
    struct continuation_finally_result *result = &scope->data->finally;
    struct continuation_finally_event *event;
    ULONG_PTR local = (ULONG_PTR)&local;
    DWORD *count = abnormal ? &result->abnormal_count : &result->normal_count;
    DWORD index = *count, mask = 0;

    if (index >= 2)
    {
        result->error_mask |= 0x1000;
        ++result->errors;
        return;
    }
    event = abnormal ? &result->abnormal[index] : &result->normal[index];
    event->id = id;
    event->abnormal = abnormal;
    event->resource = *resource;
    event->cookie = *cookie;
    event->handler_rsp = local;
    event->resource_address = (ULONG_PTR)resource;
    event->cookie_address = (ULONG_PTR)cookie;
    event->identity = continuation_unwind_identity(scope, TRUE);
    if (id != 1 - index) mask |= 1;
    if (*resource != 0xf1a10001 + id) mask |= 2;
    if (*cookie != 0xa1b0f1a100000001ull + id) mask |= 4;
    if (!event->identity) mask |= 8;
    if (local < scope->stack_low + 0x1000 || local >= scope->stack_high - 0xa0) mask |= 0x10;
    if ((ULONG_PTR)resource < scope->stack_low + 0x1000
            || (ULONG_PTR)resource >= scope->stack_high - 0xa0) mask |= 0x20;
    if ((ULONG_PTR)cookie < scope->stack_low + 0x1000
            || (ULONG_PTR)cookie >= scope->stack_high - 0xa0) mask |= 0x40;
    if (!scope->armed) mask |= 0x80;
    if (!scope->registered) mask |= 0x100;
    if (scope->data->phase != 2) mask |= 0x200;
    if (abnormal && (!scope->compiler_running || result->entered != 2
            || result->normal_returned != 1 || scope->data->unwind.cleanup_count)) mask |= 0x400;
    if (!abnormal && (scope->compiler_running || result->entered != 1)) mask |= 0x800;
    event->error_mask = mask;
    result->error_mask |= mask;
    if (mask) ++result->errors;
    *resource = 0;
    ++*count;
}

static DECLSPEC_NOINLINE void continuation_compiler_finally(struct continuation_unwind_scope *scope, BOOL fault)
{
    volatile DWORD outer_resource = 0xf1a10001, inner_resource = 0;
    volatile ULONG64 outer_cookie = 0xa1b0f1a100000001ull, inner_cookie = 0;
    BYTE (WINAPI *read_fault)(void *) = (void *)scope->fault_rip;

    ++scope->data->finally.entered;
    __try
    {
        inner_resource = 0xf1a10002;
        inner_cookie = 0xa1b0f1a100000002ull;
        __try
        {
            if (fault) read_fault((void *)scope->address);
            /* Normal progress inside the protected body is observable. The
             * abnormal invocation must unwind before reaching this point. */
            ++scope->data->finally.protected_returned;
        }
        __finally
        {
            record_compiler_finally(scope, 1, AbnormalTermination(), &inner_resource, &inner_cookie);
        }
    }
    __finally
    {
        record_compiler_finally(scope, 0, AbnormalTermination(), &outer_resource, &outer_cookie);
    }
    if (outer_resource || inner_resource)
    {
        scope->data->finally.error_mask |= 0x2000;
        ++scope->data->finally.errors;
    }
    if (fault) ++scope->data->finally.abnormal_returned;
    else ++scope->data->finally.normal_returned;
}

static DECLSPEC_NOINLINE void WINAPI continuation_compiler_entry(struct continuation_unwind_scope *scope)
{
    continuation_compiler_finally(scope, FALSE);
    scope->compiler_running = 1;
    continuation_compiler_finally(scope, TRUE);
    scope->data->finally.error_mask |= 0x4000;
    ++scope->data->finally.errors; /* The abnormal invocation cannot return. */
}
#endif

static EXCEPTION_DISPOSITION WINAPI continuation_frame_handler(EXCEPTION_RECORD *record, void *frame,
        CONTEXT *context, DISPATCHER_CONTEXT *dispatch)
{
    static const ULONG64 cookies[] = {0x1122334455667788, 0x2233445566778899, 0x33445566778899aa};
    struct continuation_unwind_scope *scope = &unwind_scope;
    struct continuation_data *data = scope->data;
    struct continuation_unwind_result *result;
    struct continuation_unwind_event *event;
    ULONG_PTR local, expected_frame;
    DWORD id, index, expected_flags;
    BOOL unwinding;

    if (!scope->armed || !data || dispatch->ImageBase != scope->code || !dispatch->HandlerData)
        return ExceptionContinueSearch;
    id = *(DWORD *)dispatch->HandlerData;
    if (id >= 3 || dispatch->FunctionEntry != &scope->table[id]
            || record->ExceptionCode != STATUS_ACCESS_VIOLATION || record->NumberParameters != 2
            || record->ExceptionInformation[0] || record->ExceptionInformation[1] != scope->address
            || (ULONG_PTR)record->ExceptionAddress != scope->fault_rip)
        return ExceptionContinueSearch;
    result = &data->unwind;
    unwinding = !!(record->ExceptionFlags & EXCEPTION_UNWINDING);
    index = unwinding ? result->cleanup_count : result->search_count;
    expected_frame = scope->stack_high - 0x40 - id * 0x30;
    expected_flags = unwinding ? EXCEPTION_UNWINDING | (!id ? EXCEPTION_TARGET_UNWIND : 0) : 0;
    if (index >= 3 || id != 2 - index || (ULONG_PTR)frame != expected_frame
            || dispatch->EstablisherFrame != expected_frame || record->ExceptionFlags != expected_flags
            || dispatch->ControlPc < scope->code + scope->table[id].BeginAddress
            || dispatch->ControlPc >= scope->code + scope->table[id].EndAddress
            || *(ULONG64 *)(expected_frame + 0x20) != cookies[id]
            || data->resources[id] != 0xcafe0001 + id
            || !continuation_unwind_identity(scope, TRUE)
            || data->owner != scope->pid || data->expected_owner != scope->pid
            || data->generation != scope->generation || data->expected_generation != scope->generation
            || data->phase != 2 || data->state != 1 || data->cancelled
            || data->unwind_scope != (ULONG_PTR)scope || !scope->registered
            || scope->native_rsp != data->native_rsp || scope->native_return != data->native_return
            || scope->native_rsp < scope->native_low || scope->native_rsp + 0x100 >= scope->native_high
            || scope->native_return != (ULONG_PTR)continuation_native_return
            || *(ULONG_PTR *)(scope->native_rsp + 0xa8) != (ULONG_PTR)data
            || (!unwinding && (context->Rip != scope->fault_rip
                || context->Rsp != (data->compiler_enabled ? scope->compiler_fault_rsp : scope->stack_high - 0xa0)
                || (!data->compiler_enabled && (context->Rax != scope->address || context->R15 != (ULONG_PTR)data)))))
        ++result->errors;
    if (index >= 3) return ExceptionContinueSearch;
    local = (ULONG_PTR)&local;
    event = unwinding ? &result->cleanup[index] : &result->search[index];
    event->frame_id = id;
    event->flags = record->ExceptionFlags;
    event->resource = data->resources[id];
    event->frame = (ULONG_PTR)frame;
    event->handler_rsp = local;
    event->control_pc = dispatch->ControlPc;
    event->cookie = *(ULONG64 *)(expected_frame + 0x20);
    if (unwinding)
    {
        if (data->compiler_enabled && (data->finally.abnormal_count != 2
                || data->finally.normal_count != 2 || data->finally.normal_returned != 1
                || data->finally.abnormal_returned || data->finally.errors)) ++result->errors;
        if (data->compiler_enabled && !index && data->finally.abnormal_count == 2)
        {
            unsigned int i;

            /* Observe the retired compiler parent's zeroed volatile locals
             * before subsequent mapped cleanup/landing can reuse its stack. */
            for (i = 0; i < 2; ++i)
            {
                const struct continuation_finally_event *event = &data->finally.abnormal[i];

                if (event->resource_address > scope->compiler_fault_rsp
                        && event->resource_address < scope->stack_high - 0xa0
                        && !*(volatile DWORD *)event->resource_address)
                    ++data->finally.resources_cleared;
            }
            if (data->finally.resources_cleared != 2) ++result->errors;
        }
        /* The real unwind dispatcher invokes each cleanup. Each live logical
         * resource token is consumed here once, not by the native wrapper. */
        data->resources[id] = 0;
        ++result->cleanup_count;
        if (!id) ++result->target_count;
        return ExceptionContinueSearch;
    }
    ++result->search_count;
    if (data->compiler_enabled && (data->finally.normal_count != 2 || data->finally.normal_returned != 1
            || data->finally.abnormal_count || data->finally.errors)) ++result->errors;
    if (id) return ExceptionContinueSearch;
    result->pid = scope->pid;
    result->tid = scope->tid;
    result->code = record->ExceptionCode;
    result->flags = record->ExceptionFlags;
    result->parameters = record->NumberParameters;
    result->access = record->ExceptionInformation[0];
    result->address = record->ExceptionInformation[1];
    result->rip = context->Rip;
    result->rsp = context->Rsp;
    result->native_rsp = scope->native_rsp;
    result->native_return = scope->native_return;
    result->stack_limit = (ULONG_PTR)scope->teb->Tib.StackLimit;
    result->stack_base = (ULONG_PTR)scope->teb->Tib.StackBase;
    result->deallocation = (ULONG_PTR)scope->teb->DeallocationStack;
    result->teb = (ULONG_PTR)scope->teb;
    result->tls = (ULONG_PTR)scope->tls;
    pContinuationUnwindEx((void *)(scope->stack_high - 0x40),
            (void *)continuation_address((void *)scope->code, continuation_unwind_landing),
            record, scope, &scope->context, &scope->history);
    ++result->errors; /* RtlUnwindEx must transfer to the target, never return. */
    return ExceptionContinueSearch;
}

static struct continuation_data *WINAPI continuation_frame_landing(struct continuation_unwind_scope *scope,
        ULONG_PTR rsp, ULONG_PTR rip, ULONG64 local)
{
    struct continuation_data *data = scope->data;
    struct continuation_unwind_result *result = &data->unwind;

    ++result->landing_count;
    result->landing_rsp = rsp;
    result->landing_rip = rip;
    result->landing_local = local;
    if (scope != &unwind_scope || !scope->armed || !scope->registered
            || !continuation_unwind_identity(scope, TRUE) || result->search_count != 3
            || result->cleanup_count != 3 || result->target_count != 1 || result->landing_count != 1
            || rsp != scope->stack_high - 0x40
            || rip != continuation_address((void *)scope->code, continuation_unwind_landing)
            || *(ULONG64 *)(rsp + 0x20) != 0x1122334455667788 || local != 0x1bc
            || data->resources[0] || data->resources[1] || data->resources[2]
            || (data->compiler_enabled && (data->finally.entered != 2 || data->finally.normal_returned != 1
                || data->finally.abnormal_returned || data->finally.normal_count != 2
                || data->finally.abnormal_count != 2 || data->finally.resources_cleared != 2
                || data->finally.protected_returned != 1 || data->finally.errors)))
        ++result->errors;
    /* All three custom frame cleanup handlers have completed. Retire the
     * faulted logical continuation before returning to the current bridge. */
    data->state = 3;
    data->cancelled = 1;
    data->saved_rsp = data->saved_rip = 0;
    scope->armed = scope->compiler_running = 0;
    return data;
}

static LONG WINAPI continuation_unwind_observer(EXCEPTION_POINTERS *pointers)
{
    struct continuation_unwind_scope *scope = &unwind_scope;
    EXCEPTION_RECORD *record = pointers->ExceptionRecord;
    CONTEXT *context = pointers->ContextRecord;
    struct continuation_unwind_result *result;

    if (!scope->armed || !scope->data || record->ExceptionCode != STATUS_ACCESS_VIOLATION
            || record->ExceptionFlags || record->NumberParameters != 2
            || record->ExceptionInformation[0] || record->ExceptionInformation[1] != scope->address)
        return EXCEPTION_CONTINUE_SEARCH;
    result = &scope->data->unwind;
    if (scope->native_control && context->Rip == (ULONG_PTR)native_fault_instruction
            && context->Rsp >= scope->native_low && context->Rsp < scope->native_high)
    {
        scope->control_rip = context->Rip;
        scope->control_rsp = context->Rsp;
        scope->control_r15 = context->R15;
        ++result->rejected;
    }
    else if (!scope->native_control && context->Rip == scope->fault_rip
            && (ULONG_PTR)record->ExceptionAddress == scope->fault_rip
            && (scope->data->compiler_enabled
                ? scope->compiler_running && context->Rcx == scope->address
                    && context->Rsp > scope->stack_low + 0x1000 && context->Rsp < scope->stack_high - 0xa0
                : context->Rsp == scope->stack_high - 0xa0))
    {
        ++result->veh_search;
        if (scope->data->compiler_enabled)
        {
            scope->compiler_fault_rsp = context->Rsp;
            scope->data->finally.fault_rsp = context->Rsp;
        }
        if (!continuation_unwind_identity(scope, TRUE) || result->veh_search != 1) ++result->errors;
    }
    return EXCEPTION_CONTINUE_SEARCH; /* Never consumes the shared-stack AV. */
}

static LONG WINAPI continuation_unwind_native_control(EXCEPTION_POINTERS *pointers)
{
    struct continuation_unwind_scope *scope = &unwind_scope;
    EXCEPTION_RECORD *record = pointers->ExceptionRecord;
    CONTEXT *context = pointers->ContextRecord;
    struct continuation_unwind_result *result;

    if (!scope->armed || !scope->native_control || !continuation_unwind_identity(scope, FALSE)
            || record->ExceptionCode != STATUS_ACCESS_VIOLATION || record->ExceptionFlags
            || record->NumberParameters != 2 || record->ExceptionInformation[0]
            || record->ExceptionInformation[1] != scope->address
            || context->Rip != (ULONG_PTR)native_fault_instruction || context->Rcx != scope->address
            || context->Rsp < scope->native_low || context->Rsp >= scope->native_high)
        return EXCEPTION_CONTINUE_SEARCH;
    result = &scope->data->unwind;
    result->control_unchanged = scope->control_rip == context->Rip && scope->control_rsp == context->Rsp
            && scope->control_r15 == context->R15;
    ++result->control_caught;
    context->Rip = (ULONG_PTR)native_fault_return;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL invoke_unwind_continuation(struct continuation_data *data, void *code, void *stack)
{
    static const BYTE * const starts[] = {continuation_code_start, continuation_outer_start, continuation_inner_start};
    static const BYTE * const ends[] = {continuation_root_end, continuation_outer_end, continuation_inner_end};
    struct continuation_unwind_scope *scope = &unwind_scope;
    struct continuation_unwind_result *result = &data->unwind;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    MEMORY_BASIC_INFORMATION info;
    void *address = NULL, *observer = NULL, *control = NULL;
    ULONG_PTR image;
    unsigned int i;
    BOOL ret = FALSE, tls_set = FALSE, lookups_valid = TRUE;

    /* A failed deletion retains the static table/scope and mapped image until
     * process exit; never overwrite a still registered function table. */
    if (scope->registered) return FALSE;
    memset(scope, 0, sizeof(*scope));
    scope->tls_index = TLS_OUT_OF_INDEXES;
    pContinuationAddFunctionTable = (void *)GetProcAddress(ntdll, "RtlAddFunctionTable");
    pContinuationDeleteFunctionTable = (void *)GetProcAddress(ntdll, "RtlDeleteFunctionTable");
    pContinuationLookupFunctionEntry = (void *)GetProcAddress(ntdll, "RtlLookupFunctionEntry");
    pContinuationUnwindEx = (void *)GetProcAddress(ntdll, "RtlUnwindEx");
    ok(pContinuationAddFunctionTable && pContinuationDeleteFunctionTable
            && pContinuationLookupFunctionEntry && pContinuationUnwindEx, "A1b frame unwind APIs unavailable\n");
    if (!pContinuationAddFunctionTable || !pContinuationDeleteFunctionTable
            || !pContinuationLookupFunctionEntry || !pContinuationUnwindEx) return FALSE;
    scope->data = data;
    scope->code = (ULONG_PTR)code;
    scope->stack_low = (ULONG_PTR)stack;
    scope->stack_high = (ULONG_PTR)stack + EXECUTION_REGION_SIZE;
    scope->teb = NtCurrentTeb();
    scope->native_low = (ULONG_PTR)scope->teb->Tib.StackLimit;
    scope->native_high = (ULONG_PTR)scope->teb->Tib.StackBase;
    scope->native_deallocation = (ULONG_PTR)scope->teb->DeallocationStack;
    scope->tls = scope->teb->ThreadLocalStoragePointer;
    scope->pid = GetCurrentProcessId();
    scope->tid = GetCurrentThreadId();
    scope->generation = data->generation;
    scope->phase = data->phase;
    scope->fault_rip = continuation_address(code, data->compiler_enabled
            ? continuation_compiler_fault : continuation_fault_instruction);
#ifdef USE_COMPILER_EXCEPTIONS
    if (data->compiler_enabled)
    {
        RUNTIME_FUNCTION *entry;

        image = 0;
        entry = pContinuationLookupFunctionEntry((ULONG_PTR)continuation_compiler_finally, &image, NULL);
        data->finally.helper_address = (ULONG_PTR)continuation_compiler_finally;
        data->finally.helper_image = image;
        data->finally.metadata = entry && image == (ULONG_PTR)GetModuleHandleA(NULL)
                && entry->BeginAddress + image <= (ULONG_PTR)continuation_compiler_finally
                && entry->EndAddress + image > (ULONG_PTR)continuation_compiler_finally;
        ok(data->finally.metadata, "A1b compiler finally helper has no linked PE function entry\n");
        if (!data->finally.metadata) goto cleanup;
        data->compiler_entry = (ULONG_PTR)continuation_compiler_entry;
    }
#endif
    scope->handler = continuation_frame_handler;
    scope->landing = continuation_frame_landing;
    result->native_limit = scope->native_low;
    result->native_base = scope->native_high;
    result->native_deallocation = scope->native_deallocation;
    scope->tls_index = TlsAlloc();
    ok(scope->tls_index != TLS_OUT_OF_INDEXES, "A1b frame TLS sentinel allocation failed\n");
    if (scope->tls_index == TLS_OUT_OF_INDEXES) goto cleanup;
    tls_set = TlsSetValue(scope->tls_index, scope);
    ok(tls_set, "A1b frame TLS sentinel setup failed\n");
    if (!tls_set) goto cleanup;
    address = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    ok(address != NULL, "A1b frame fault allocation failed\n");
    if (!address) goto cleanup;
    scope->address = (ULONG_PTR)address;
    for (i = 0; i < 3; ++i)
    {
        scope->table[i].BeginAddress = CONTINUATION_CODE_OFFSET + (starts[i] - continuation_code_start);
        scope->table[i].EndAddress = CONTINUATION_CODE_OFFSET + (ends[i] - continuation_code_start);
        scope->table[i].UnwindData = CONTINUATION_UNWIND_OFFSET + i * sizeof(struct continuation_unwind_info);
        image = 0;
        if (pContinuationLookupFunctionEntry(scope->code + scope->table[i].BeginAddress, &image, NULL))
        {
            ok(0, "A1b frame %u unexpectedly had a function entry before registration\n", i);
            lookups_valid = FALSE;
        }
        else ok(1, "A1b frame %u unexpectedly had a function entry before registration\n", i);
    }
    if (!lookups_valid) goto cleanup;
    scope->registered = pContinuationAddFunctionTable(scope->table, 3, scope->code);
    result->registered = scope->registered;
    ok(scope->registered, "A1b frame function table registration failed\n");
    if (!scope->registered) goto cleanup;
    for (i = 0; i < 3; ++i)
    {
        BOOL found;

        image = 0;
        found = pContinuationLookupFunctionEntry(scope->code + scope->table[i].BeginAddress, &image, NULL)
                == &scope->table[i] && image == scope->code;
        ok(found, "A1b frame %u registered lookup identity failed\n", i);
        if (!found) lookups_valid = FALSE;
    }
    if (!lookups_valid) goto cleanup;
    observer = AddVectoredExceptionHandler(1, continuation_unwind_observer);
    control = AddVectoredExceptionHandler(0, continuation_unwind_native_control);
    ok(observer && control, "A1b frame observer/control registration failed\n");
    if (!observer || !control) goto cleanup;
    data->unwind_scope = (ULONG_PTR)scope;
    data->fault_address = scope->address;
    scope->armed = scope->native_control = 1;
    native_fault_control(address);
    scope->native_control = 0;
    ok(result->rejected == 1 && result->control_caught == 1 && result->control_unchanged
            && !result->search_count, "A1b frame unrelated native AV was changed or consumed\n");
    invoke_continuation_control(data, (BYTE *)code + CONTINUATION_CODE_OFFSET);
    result->bounds_entered = scope->bounds_entered;
    result->bounds_restored = scope->bounds_restored;
    result->native_bounds = (ULONG_PTR)scope->teb->Tib.StackLimit == scope->native_low
            && (ULONG_PTR)scope->teb->Tib.StackBase == scope->native_high
            && (ULONG_PTR)scope->teb->DeallocationStack == scope->native_deallocation;
    result->native_identity = continuation_unwind_identity(scope, FALSE);
    ok(result->native_bounds && result->native_identity, "A1b frame native stack/identity not restored\n");
    ret = TRUE;
cleanup:
    scope->armed = scope->native_control = 0;
    {
        BOOL observer_removed = !observer || RemoveVectoredExceptionHandler(observer);
        BOOL control_removed = !control || RemoveVectoredExceptionHandler(control);
        result->handlers_removed = observer_removed && control_removed;
    }
    ok(result->handlers_removed, "A1b frame observer/control removal failed\n");
    if (scope->registered)
    {
        result->removed = pContinuationDeleteFunctionTable(scope->table);
        ok(result->removed, "A1b frame function table removal failed\n");
        if (result->removed) scope->registered = 0;
    }
    if (!scope->registered)
    {
        result->lookup_absent = 1;
        for (i = 0; i < 3; ++i)
        {
            image = 0;
            if (pContinuationLookupFunctionEntry(scope->code + scope->table[i].BeginAddress, &image, NULL))
                result->lookup_absent = 0;
        }
        ok(result->lookup_absent, "A1b frame function entry persisted after deletion\n");
        data->unwind_scope = 0;
    }
    else
    {
        /* The RX thunk still resolves this valid, disarmed static scope. The
         * child retains all mapped regions until process exit on this error. */
        data->preserve_mappings = 1;
        ret = FALSE;
    }
    data->fault_address = data->compiler_entry = 0;
    scope->compiler_running = 0;
    if (address)
        result->released = VirtualFree(address, 0, MEM_RELEASE)
                && VirtualQuery(address, &info, sizeof(info)) && info.State == MEM_FREE;
    ok(!address || result->released, "A1b frame fault allocation cleanup failed\n");
    if (scope->tls_index != TLS_OUT_OF_INDEXES)
    {
        if (tls_set) TlsSetValue(scope->tls_index, NULL);
        result->tls_removed = TlsFree(scope->tls_index);
        ok(result->tls_removed, "A1b frame TLS sentinel cleanup failed\n");
    }
    return ret;
}

static LONG WINAPI continuation_fault_handler(EXCEPTION_POINTERS *pointers)
{
    struct continuation_fault_scope *scope = &fault_scope;
    EXCEPTION_RECORD *record = pointers->ExceptionRecord;
    CONTEXT *context = pointers->ContextRecord;
    struct continuation_data *data;
    struct continuation_fault_result *result;
    ULONG_PTR handler_local;
    TEB *teb = NtCurrentTeb();

    if (!scope->armed || (ULONG_PTR)teb->ClientId.UniqueProcess != scope->pid
            || (ULONG_PTR)teb->ClientId.UniqueThread != scope->tid) return EXCEPTION_CONTINUE_SEARCH;
    data = scope->data;
    result = &data->fault;
    /* A real unrelated native-stack AV must continue to the separate native
     * catcher. Record its incoming context; never modify it here. */
    if (scope->native_control && context->Rip == (ULONG_PTR)native_fault_instruction
            && record->ExceptionCode == STATUS_ACCESS_VIOLATION && !record->ExceptionFlags
            && record->NumberParameters == 2 && !record->ExceptionInformation[0]
            && record->ExceptionInformation[1] == scope->address
            && context->Rsp >= scope->native_low && context->Rsp < scope->native_high)
    {
        scope->control_rip = context->Rip;
        scope->control_rsp = context->Rsp;
        scope->control_r15 = context->R15;
        ++result->rejected;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (scope->native_control || result->caught || record->ExceptionCode != STATUS_ACCESS_VIOLATION
            || record->ExceptionFlags || record->NumberParameters != 2
            || record->ExceptionInformation[0] || record->ExceptionInformation[1] != scope->address
            || (ULONG_PTR)record->ExceptionAddress != scope->fault_rip || context->Rip != scope->fault_rip
            || context->Rax != scope->address || context->R15 != (ULONG_PTR)data
            || context->Rsp != scope->expected_rsp || context->Rsp < scope->stack_low + 0x1000
            || context->Rsp >= scope->stack_high || data->owner != scope->pid
            || data->expected_owner != scope->pid || data->generation != scope->generation
            || data->expected_generation != scope->generation || data->phase != scope->phase
            || data->state != 1 || data->cancelled || !data->fault_enabled
            || data->fault_scope != (ULONG_PTR)scope || data->fault_address != scope->address
            || !scope->native_rsp || scope->native_rsp < scope->native_low
            || scope->native_rsp + 0x100 >= scope->native_high
            || scope->native_return != (ULONG_PTR)continuation_native_return
            || data->native_rsp != scope->native_rsp || data->native_return != scope->native_return
            || *(ULONG_PTR *)(scope->native_rsp + 0xa8) != (ULONG_PTR)data)
        return EXCEPTION_CONTINUE_SEARCH;
    handler_local = (ULONG_PTR)&handler_local;
    result->caught = 1;
    result->pid = scope->pid;
    result->tid = scope->tid;
    result->code = record->ExceptionCode;
    result->flags = record->ExceptionFlags;
    result->parameters = record->NumberParameters;
    result->access = record->ExceptionInformation[0];
    result->address = record->ExceptionInformation[1];
    result->rip = context->Rip;
    result->rsp = context->Rsp;
    result->handler_rsp = handler_local;
    result->native_rsp = scope->native_rsp;
    result->native_return = scope->native_return;
    result->stack_base = (ULONG_PTR)teb->Tib.StackBase;
    result->stack_limit = (ULONG_PTR)teb->Tib.StackLimit;
    /* Abort the logical continuation. No destructor/finally/frame unwind is
     * claimed; the current host's ordinary native epilogue restores its ABI. */
    data->state = 3;
    data->cancelled = 1;
    data->saved_rsp = data->saved_rip = 0;
    scope->armed = 0;
    context->Rip = scope->native_return;
    context->Rsp = scope->native_rsp;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG WINAPI continuation_native_control_handler(EXCEPTION_POINTERS *pointers)
{
    struct continuation_fault_scope *scope = &fault_scope;
    EXCEPTION_RECORD *record = pointers->ExceptionRecord;
    CONTEXT *context = pointers->ContextRecord;
    TEB *teb = NtCurrentTeb();
    struct continuation_fault_result *result;

    if (!scope->armed || !scope->native_control
            || (ULONG_PTR)teb->ClientId.UniqueProcess != scope->pid
            || (ULONG_PTR)teb->ClientId.UniqueThread != scope->tid
            || record->ExceptionCode != STATUS_ACCESS_VIOLATION || record->ExceptionFlags
            || record->NumberParameters != 2 || record->ExceptionInformation[0]
            || record->ExceptionInformation[1] != scope->address
            || (ULONG_PTR)record->ExceptionAddress != (ULONG_PTR)native_fault_instruction
            || context->Rip != (ULONG_PTR)native_fault_instruction || context->Rcx != scope->address
            || context->Rsp < scope->native_low || context->Rsp >= scope->native_high)
        return EXCEPTION_CONTINUE_SEARCH;
    result = &scope->data->fault;
    result->native_unchanged = context->Rip == scope->control_rip
            && context->Rsp == scope->control_rsp && context->R15 == scope->control_r15;
    ++result->native_caught;
    context->Rip = (ULONG_PTR)native_fault_return;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL invoke_fault_continuation(struct continuation_data *data, void *code, void *stack)
{
    struct continuation_fault_scope *scope = &fault_scope;
    struct continuation_fault_result *result = &data->fault;
    TEB *teb = NtCurrentTeb();
    MEMORY_BASIC_INFORMATION info;
    void *handler = NULL, *control_handler = NULL;
    void *address;
    BOOL ret = FALSE;

    address = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    ok(address != NULL, "A1b fault allocation failed, error %lu\n", GetLastError());
    if (!address) return FALSE;
    memset(scope, 0, sizeof(*scope));
    scope->data = data;
    scope->stack_low = (ULONG_PTR)stack;
    scope->stack_high = (ULONG_PTR)stack + EXECUTION_REGION_SIZE;
    scope->expected_rsp = scope->stack_high - 0xa0;
    scope->fault_rip = continuation_address(code, continuation_fault_instruction);
    scope->address = (ULONG_PTR)address;
    scope->native_low = (ULONG_PTR)teb->Tib.StackLimit;
    scope->native_high = (ULONG_PTR)teb->Tib.StackBase;
    scope->pid = GetCurrentProcessId();
    scope->tid = GetCurrentThreadId();
    scope->generation = data->generation;
    scope->phase = data->phase;
    control_handler = AddVectoredExceptionHandler(0, continuation_native_control_handler);
    handler = AddVectoredExceptionHandler(1, continuation_fault_handler);
    ok(handler && control_handler, "A1b fault handlers registration failed\n");
    if (!handler || !control_handler) goto cleanup;
    data->fault_scope = (ULONG_PTR)scope;
    data->fault_address = (ULONG_PTR)address;
    scope->armed = scope->native_control = 1;
    native_fault_control(address);
    scope->native_control = 0;
    ok(result->rejected == 1 && result->native_caught == 1 && result->native_unchanged
            && !result->caught, "A1b unrelated native AV was swallowed or changed\n");
    invoke_continuation_control(data, (BYTE *)code + CONTINUATION_CODE_OFFSET);
    ret = TRUE;
cleanup:
    scope->armed = scope->native_control = 0;
    data->fault_scope = data->fault_address = 0;
    {
        BOOL removed = !handler || RemoveVectoredExceptionHandler(handler);
        BOOL control_removed = !control_handler || RemoveVectoredExceptionHandler(control_handler);
        result->removed = removed && control_removed;
    }
    ok(result->removed, "A1b fault handlers removal failed\n");
    result->teb_unchanged = scope->native_low == (ULONG_PTR)teb->Tib.StackLimit
            && scope->native_high == (ULONG_PTR)teb->Tib.StackBase;
    result->released = VirtualFree(address, 0, MEM_RELEASE)
            && VirtualQuery(address, &info, sizeof(info)) && info.State == MEM_FREE;
    ok(result->released, "A1b fault allocation cleanup failed\n");
    return ret;
}

/* Admission runs exclusively on the current host's native stack. The serial
 * parent owns phase/owner/generation publication and never executes an internal
 * probe entry. A suspended continuation can only resume its actual CALL return. */
static BOOL dispatch_continuation(struct continuation_data *data, void *code, void *stack, DWORD owner)
{
    static const BYTE * const resumes[] = {NULL, continuation_after_a, continuation_after_b,
            continuation_after_restore_a, continuation_after_caller};
    static const unsigned int depths[] = {0, 0x1f8, 0x228, 0x228, 0x1f8};
    ULONG_PTR top = (ULONG_PTR)stack + EXECUTION_REGION_SIZE - 0x10;
    const struct continuation_frame *frame;

    if (data->cancelled || data->generation != CONTINUATION_GENERATION
            || data->expected_generation != data->generation || owner != GetCurrentProcessId()
            || owner != data->expected_owner
            || data->owner != owner || data->state > 1) return FALSE;
    if (!data->state)
    {
        if (data->phase || data->starts || data->completed || data->saved_rsp || data->saved_rip
                || data->initial_rsp != top - 8
                || *(ULONG_PTR *)(top - 8) != continuation_address(code, continuation_finish)) return FALSE;
    }
    else
    {
        if (data->phase < 1 || data->phase > 4 || data->starts != 1 || data->completed
                || data->saved_rip != continuation_address(code, resumes[data->phase])
                || data->saved_rsp != top - depths[data->phase] || (data->saved_rsp & 15) != 8
                || data->saved_rsp < (ULONG_PTR)stack + 0x100
                || data->saved_rsp > top - sizeof(*frame)) return FALSE;
        frame = (const struct continuation_frame *)data->saved_rsp;
        if (frame->rip != data->saved_rip || frame->gpr[0] != (ULONG_PTR)data
                || frame->mxcsr != 0x1f80 || frame->flags != 0x247
                || *(ULONG_PTR *)(top - 8) != continuation_address(code, continuation_finish)
                || *(ULONG64 *)(top - 0x10) != 0x1122334455667788
                || *(ULONG64 *)(top - 0x40) != 0x2233445566778899
                || *(ULONG_PTR *)(top - 0x38) != continuation_address(code, continuation_root_return))
            return FALSE;
        if ((data->phase == 2 || data->phase == 3)
                && (*(ULONG64 *)(top - 0x70) != 0x33445566778899aa
                || *(ULONG_PTR *)(top - 0x68) != continuation_address(code, continuation_outer_return)))
            return FALSE;
    }
    if (data->unwind_enabled && data->phase == 2)
        return invoke_unwind_continuation(data, code, stack);
    if (data->fault_enabled && data->phase == 2)
        return invoke_fault_continuation(data, code, stack);
    invoke_continuation_control(data, (BYTE *)code + CONTINUATION_CODE_OFFSET);
    return TRUE;
}

static void attachment_child(char **argv)
{
    HANDLE mapping = (HANDLE)(ULONG_PTR)_strtoui64(argv[3], NULL, 16);
    HANDLE ready = (HANDLE)(ULONG_PTR)_strtoui64(argv[4], NULL, 16);
    HANDLE stop = (HANDLE)(ULONG_PTR)_strtoui64(argv[5], NULL, 16);
    unsigned int index = atoi(argv[6]), i;
    struct attachment_shared *shared;
    void *regions[3] = {NULL};
    BYTE *common = NULL, *target = NULL;
    HANDLE events[2];
    DWORD wait;

    shared = MapViewOfFile(mapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, sizeof(*shared));
    if (shared && index < 2)
    {
        shared->process_id[index] = GetCurrentProcessId();
        common = VirtualAlloc((void *)shared->common_address, 0x1000,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (common) target = VirtualAlloc((void *)shared->target_address, 0x1000,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        shared->error[index] = !common || !target ? GetLastError() : 0;
        if (common && target)
        {
            *common = index ? 0xb2 : 0xa1;
            *target = index ? 0xd4 : 0xc3;
            shared->collision_ok[index] = execution_collision_control(shared, common);
            if (!map_execution_regions(shared, regions, shared->protection[index]))
                shared->error[index] = GetLastError();
        }
    }
    SetEvent(ready);
    /* IPC and admission occur on the native stack. The bounded table-SEH mode
     * makes real exception/unwind calls on its truthfully described shared
     * stack. The parent grants it to only one serial owner at a time. */
    if (common && target && !shared->error[index])
    {
        events[0] = stop;
        events[1] = shared->run[index];
        for (;;)
        {
            wait = WaitForMultipleObjects(2, events, FALSE, 60000);
            if (wait != WAIT_OBJECT_0 + 1) break;
            if (shared->continuation_mode)
            {
                struct continuation_data *data = (void *)((BYTE *)regions[1] + CONTINUATION_DATA_OFFSET);
                shared->continuation_accepted[index] = dispatch_continuation(data, regions[0],
                        regions[2], GetCurrentProcessId());
            }
            else
            {
                ((struct execution_data *)regions[1])->owner = GetCurrentProcessId();
                invoke_execution(regions[1], regions[0], common,
                        (BYTE *)regions[2] + EXECUTION_REGION_SIZE - 0x10, target);
                shared->observed_sequence[index] = ((struct execution_data *)regions[1])->sequence;
            }
            SetEvent(shared->done[index]);
        }
    }
    /* If dynamic-table deletion failed, its static records and mapped image
     * remain valid through process exit. Do not unmap a referenced image. */
    if (!regions[1] || !((struct continuation_data *)((BYTE *)regions[1]
            + CONTINUATION_DATA_OFFSET))->preserve_mappings)
        for (i = 0; i < 3; ++i) if (regions[i]) UnmapViewOfFile(regions[i]);
    if (target) VirtualFree(target, 0, MEM_RELEASE);
    if (common) VirtualFree(common, 0, MEM_RELEASE);
    if (shared) UnmapViewOfFile(shared);
    CloseHandle(mapping);
    CloseHandle(ready);
    CloseHandle(stop);
}

static BOOL test_execution_regions(struct attachment_shared *shared, void **regions,
        BYTE *common, PROCESS_INFORMATION *children)
{
    static const char * const phases[] = {"caller", "A", "B", "A again", "caller again"};
    static const int owners[] = {-1, 0, 1, 0, -1};
    static const BYTE common_values[] = {0x59, 0xa1, 0xb2, 0xa1, 0x59};
    static const BYTE target_values[] = {0, 0xc3, 0xd4, 0xc3, 0};
    struct execution_data *data = regions[1];
    BYTE *stack = regions[2], *top = stack + EXECUTION_REGION_SIZE - 0x10;
    HANDLE events[2];
    unsigned int i, j;
    DWORD wait, owner;

    ok(execution_collision_control(shared, common), "A1b caller collision clobbered private mapping\n");
    for (i = 0; i < 2; ++i)
    {
        ok(shared->collision_ok[i], "A1b child %u collision clobbered private mapping\n", i);
        ok(shared->process_id[i] == children[i].dwProcessId, "A1b child %u process identity %lu/%lu\n",
                i, shared->process_id[i], children[i].dwProcessId);
        for (j = 0; j < 3; ++j)
            ok(shared->protection[i][j] == (j ? PAGE_READWRITE : PAGE_EXECUTE_READ),
                    "A1b child %u region %u protection %#lx\n", i, j, shared->protection[i][j]);
    }
    for (i = 0; i < 3; ++i)
    {
        MEMORY_BASIC_INFORMATION info;
        BOOL ret = VirtualQuery(regions[i], &info, sizeof(info));
        ok(ret && info.BaseAddress == (void *)shared->execution_address[i] && info.State == MEM_COMMIT
                && info.Type == MEM_MAPPED && info.Protect == (i ? PAGE_READWRITE : PAGE_EXECUTE_READ),
                "A1b caller region %u address/protection mismatch\n", i);
    }
    ok(!memcmp(regions[0], execution_code, sizeof(execution_code)), "A1b shared executable bytes changed\n");
    trace("A1b shared regions: RX code %p (%Iu bytes), RW data/control %p, RW stack %p size %#x\n",
            regions[0], sizeof(execution_code), regions[1], regions[2], EXECUTION_REGION_SIZE);
    for (i = 0; i < ARRAY_SIZE(owners); ++i)
    {
        for (j = 0; j < 2; ++j)
        {
            wait = WaitForSingleObject(children[j].hProcess, 0);
            ok(wait == WAIT_TIMEOUT, "A1b child %u liveness wait %#lx\n", j, wait);
            if (wait != WAIT_TIMEOUT) return FALSE;
        }
        if (owners[i] < 0)
        {
            data->owner = owner = GetCurrentProcessId();
            invoke_execution(data, regions[0], common, top, NULL);
        }
        else
        {
            j = owners[i];
            owner = children[j].dwProcessId;
            events[0] = shared->done[j];
            events[1] = children[j].hProcess;
            if (!SetEvent(shared->run[j]))
            {
                ok(0, "A1b child %u dispatch failed, error %lu\n", j, GetLastError());
                return FALSE;
            }
            wait = WaitForMultipleObjects(2, events, FALSE, 10000);
            ok(wait == WAIT_OBJECT_0, "A1b child %u completion/liveness wait %#lx\n", j, wait);
            if (wait != WAIT_OBJECT_0) return FALSE;
            ok(shared->observed_sequence[j] == i + 1, "A1b child %u observed sequence %lu\n",
                    j, shared->observed_sequence[j]);
        }
        trace("A1b %s: owner %lu sequence %lu previous stack %lu, RIP %#Ix RSP %#Ix, private bytes %#lx/%#lx, native stack %#Ix/%#Ix registers %#lx\n",
                phases[i], data->owner, data->sequence, data->previous_stack, data->rip, data->rsp,
                data->common_value, data->target_value, data->native_before, data->native_after, data->registers);
        ok(data->owner == owner, "A1b %s owner %lu/%lu\n", phases[i], data->owner, owner);
        ok(data->sequence == i + 1, "A1b %s coherent data sequence %lu/%u\n", phases[i], data->sequence, i + 1);
        ok(data->previous_stack == i && data->stack_value == i + 1 && *(DWORD *)(top - 8) == i + 1,
                "A1b %s coherent stack %lu/%lu/%lu\n", phases[i],
                data->previous_stack, data->stack_value, *(DWORD *)(top - 8));
        ok(data->rip == (ULONG_PTR)regions[0] + 0x11, "A1b %s actual code RIP %#Ix\n", phases[i], data->rip);
        ok(data->rsp == (ULONG_PTR)top - 0x28 && (data->rsp & 15) == 8,
                "A1b %s actual aligned stack RSP %#Ix\n", phases[i], data->rsp);
        ok(data->native_before == data->native_after && data->native_before
                && (data->native_before < (ULONG_PTR)stack || data->native_before >= (ULONG_PTR)stack + EXECUTION_REGION_SIZE),
                "A1b %s native-stack restoration %#Ix/%#Ix\n", phases[i], data->native_before, data->native_after);
        ok(data->registers == 3, "A1b %s RBX/RBP preservation mask %#lx\n", phases[i], data->registers);
        ok(data->common_value == common_values[i] && data->target_value == target_values[i],
                "A1b %s direct private loads %#lx/%#lx expected %#x/%#x\n", phases[i],
                data->common_value, data->target_value, common_values[i], target_values[i]);
        ok(*(DWORD *)stack == 0x31415926 && *(DWORD *)(stack + EXECUTION_REGION_SIZE - 4) == 0x27182818,
                "A1b %s shared stack boundary canaries changed\n", phases[i]);
    }
    return TRUE;
}


static void initialize_continuation(struct attachment_shared *shared, void **regions)
{
    struct continuation_data *data = (void *)((BYTE *)regions[1] + CONTINUATION_DATA_OFFSET);
    ULONG_PTR top = (ULONG_PTR)regions[2] + EXECUTION_REGION_SIZE - 0x10;
    unsigned int i, j;

    memset(data, 0, sizeof(*data));
    data->initial_rsp = top - 8;
    *(ULONG_PTR *)data->initial_rsp = continuation_address(regions[0], continuation_finish);
    data->common = shared->common_address;
    data->target = shared->target_address;
    data->generation = data->expected_generation = CONTINUATION_GENERATION;
    data->expected.mxcsr = 0x1f80;
    data->expected.flags = 0x247;
    for (i = 0; i < 16; ++i)
        for (j = 0; j < 16; ++j) data->expected.xmm[i][j] = 0x20 + i * 7 + j;
    for (i = 0; i < 15; ++i) data->expected.gpr[i] = 0x123456789abc0000ull + i * 0x101;
    data->expected.gpr[0] = (ULONG_PTR)data;
}

static BOOL test_continuation(struct attachment_shared *shared, void **regions,
        PROCESS_INFORMATION *children)
{
    static const int owners[] = {-1, 0, 1, 0, -1};
    static const DWORD common_values[] = {0x59, 0xa1, 0xb2, 0xa1, 0x59};
    static const DWORD target_values[] = {0, 0xc3, 0xd4, 0xc3, 0};
    static const BYTE * const resumes[] = {continuation_after_a, continuation_after_b,
            continuation_after_restore_a, continuation_after_caller, continuation_terminal};
    struct continuation_data *data = (void *)((BYTE *)regions[1] + CONTINUATION_DATA_OFFSET);
    ULONG_PTR top = (ULONG_PTR)regions[2] + EXECUTION_REGION_SIZE - 0x10;
    struct continuation_frame *frame;
    HANDLE events[2];
    ULONG_PTR saved_rsp, saved_rip;
    DWORD i, j, wait, owner, control_owner, dispatches, saved_state;
    BOOL accepted;

    initialize_continuation(shared, regions);
    shared->continuation_mode = 1;
    trace("A1b continuation code %p size %Iu, shared context %p, initial RSP %#Ix\n",
            (BYTE *)regions[0] + CONTINUATION_CODE_OFFSET,
            continuation_code_end - continuation_code_start, data, data->initial_rsp);
    ok(!memcmp((BYTE *)regions[0] + CONTINUATION_CODE_OFFSET, continuation_code_start,
            continuation_code_end - continuation_code_start), "A1b continuation code bytes changed\n");
    data->owner = data->expected_owner = GetCurrentProcessId();
    data->cancelled = 1;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && !data->dispatches && !data->starts, "A1b cancelled new continuation executed\n");
    data->cancelled = 0;
    --data->generation;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && !data->dispatches && !data->starts, "A1b wrong generation executed\n");
    ++data->generation;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner + 1)
            && !data->dispatches && !data->starts, "A1b wrong owner executed\n");

    for (i = 0; i < ARRAY_SIZE(owners); ++i)
    {
        for (j = 0; j < 2; ++j)
        {
            wait = WaitForSingleObject(children[j].hProcess, 0);
            ok(wait == WAIT_TIMEOUT, "A1b continuation child %lu lifetime wait %#lx\n", j, wait);
            if (wait != WAIT_TIMEOUT) return FALSE;
        }
        owner = owners[i] < 0 ? GetCurrentProcessId() : children[owners[i]].dwProcessId;
        data->owner = data->expected_owner = owner;
        if (owners[i] < 0) accepted = dispatch_continuation(data, regions[0], regions[2], owner);
        else
        {
            j = owners[i];
            shared->continuation_accepted[j] = 0;
            events[0] = shared->done[j];
            events[1] = children[j].hProcess;
            if (!SetEvent(shared->run[j]))
            {
                ok(0, "A1b continuation child %lu dispatch error %lu\n", j, GetLastError());
                return FALSE;
            }
            wait = WaitForMultipleObjects(2, events, FALSE, 10000);
            ok(wait == WAIT_OBJECT_0, "A1b continuation child %lu completion/lifetime wait %#lx\n", j, wait);
            if (wait != WAIT_OBJECT_0) return FALSE;
            accepted = shared->continuation_accepted[j];
        }
        ok(accepted, "A1b continuation phase %lu was rejected\n", i);
        if (!accepted) return FALSE;
        trace("A1b continuation phase %lu host %lu: starts %lu completed %lu next %lu state %lu, saved RIP %#Ix RSP %#Ix, live checks %lu native checks %lu errors %lu accumulator %#I64x\n",
                i, owner, data->starts, data->completed, data->phase, data->state,
                data->saved_rip, data->saved_rsp, data->checks, data->native_checks, data->errors, data->accumulator);
        ok(data->starts == 1, "A1b continuation root entered %lu times\n", data->starts);
        ok(data->completed == (i == 4), "A1b continuation completion %lu at phase %lu\n", data->completed, i);
        ok(data->phase == i + 1 && data->state == (i == 4 ? 2 : 1),
                "A1b continuation phase/state %lu/%lu expected %lu\n", data->phase, data->state, i + 1);
        ok(data->checks == i && !data->errors, "A1b live preservation %lu errors %lu at phase %lu\n",
                data->checks, data->errors, i);
        ok(data->native_checks == (i + 1) * 19 && data->dispatches == i + 1,
                "A1b native ABI checks %lu dispatches %lu at phase %lu\n", data->native_checks, data->dispatches, i);
        ok(data->native_rsp == data->native_after && data->native_rsp
                && (data->native_rsp < (ULONG_PTR)regions[2] || data->native_rsp >= top),
                "A1b continuation native RSP %#Ix/%#Ix\n", data->native_rsp, data->native_after);
        ok(data->saved_rip == continuation_address(regions[0], resumes[i]),
                "A1b actual saved post-yield RIP %#Ix at phase %lu\n", data->saved_rip, i);
        frame = (void *)data->saved_rsp;
        ok(frame->rip == data->saved_rip && frame->gpr[0] == (ULONG_PTR)data,
                "A1b saved CALL return/R15 mismatch at phase %lu\n", i);
        ok(*(DWORD *)regions[2] == 0x31415926
                && *(DWORD *)((BYTE *)regions[2] + EXECUTION_REGION_SIZE - 4) == 0x27182818,
                "A1b continuation stack boundaries changed at phase %lu\n", i);
        if (i == 4) break;
        /* Admission controls alter one field and require zero executions. The
         * saved genuine continuation is restored before its next owner runs. */
        control_owner = GetCurrentProcessId();
        data->owner = data->expected_owner = control_owner;
        dispatches = data->dispatches;
        saved_rsp = data->saved_rsp;
        saved_rip = data->saved_rip;
        ++data->saved_rip;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b malformed RIP executed\n");
        data->saved_rip = saved_rip;
        data->saved_rsp = (ULONG_PTR)regions[2] - 8;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b out-of-bounds RSP executed\n");
        data->saved_rsp = saved_rsp + 8;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b misaligned RSP executed\n");
        data->saved_rsp = saved_rsp;
        ++frame->rip;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b corrupted CALL return executed\n");
        --frame->rip;
        frame->flags |= 0x100;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b trap flags executed\n");
        frame->flags &= ~0x100;
        ++frame->gpr[0];
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b invalid control pointer executed\n");
        --frame->gpr[0];
        ++*(ULONG_PTR *)(top - 0x38);
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b corrupted outer return executed\n");
        --*(ULONG_PTR *)(top - 0x38);
        data->cancelled = 1;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b cancelled suspended continuation executed\n");
        data->cancelled = 0;
        saved_state = data->state;
        data->state = 3;
        ok(!dispatch_continuation(data, regions[0], regions[2], control_owner)
                && data->dispatches == dispatches, "A1b invalid state executed\n");
        data->state = saved_state;
        data->owner = data->expected_owner = owner;
    }
    for (i = 0; i < 5; ++i)
    {
        struct continuation_observation *observation = &data->observations[i];
        owner = owners[i] < 0 ? GetCurrentProcessId() : children[owners[i]].dwProcessId;
        trace("A1b migrated sample %lu: host %lu direct private %#lx/%#lx, shared RSP %#Ix, real CALL return %#Ix\n",
                i, observation->owner, observation->common, observation->target,
                observation->rsp, observation->return_rip);
        ok(observation->owner == owner && observation->phase == i,
                "A1b continuation sample %lu host/phase %lu/%lu\n", i, observation->owner, observation->phase);
        ok(observation->common == common_values[i] && observation->target == target_values[i],
                "A1b continuation sample %lu direct bytes %#lx/%#lx expected %#lx/%#lx\n",
                i, observation->common, observation->target, common_values[i], target_values[i]);
        ok(observation->rsp > (ULONG_PTR)regions[2] && observation->rsp < top
                && (observation->rsp & 15) == 8
                && observation->return_rip >= (ULONG_PTR)regions[0] + CONTINUATION_CODE_OFFSET
                && observation->return_rip < (ULONG_PTR)regions[0] + CONTINUATION_CODE_OFFSET
                    + (continuation_code_end - continuation_code_start),
                "A1b continuation sample %lu stack/return outside mapped code/stack\n", i);
    }
    ok(data->accumulator == 0x2a6 && *(ULONG64 *)(data->initial_rsp - 0x10) == 0x2b6,
            "A1b accumulated private reads %#I64x, live stack local %#I64x\n",
            data->accumulator, *(ULONG64 *)(data->initial_rsp - 0x10));
    dispatches = data->dispatches;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && data->dispatches == dispatches && data->starts == 1 && data->completed == 1,
            "A1b terminal continuation restarted\n");
    shared->continuation_mode = 0;
    return TRUE;
}

static BOOL test_fault_continuation(struct attachment_shared *shared, void **regions,
        PROCESS_INFORMATION *children)
{
    struct continuation_data *data = (void *)((BYTE *)regions[1] + CONTINUATION_DATA_OFFSET);
    struct continuation_fault_result *fault = &data->fault;
    ULONG_PTR low = (ULONG_PTR)regions[2], high = low + EXECUTION_REGION_SIZE;
    HANDLE events[2];
    DWORD i, j, owner, wait, dispatches;
    BOOL accepted;

    initialize_continuation(shared, regions);
    data->fault_enabled = 1;
    shared->continuation_mode = 1;
    for (i = 0; i < 3; ++i)
    {
        for (j = 0; j < 2; ++j)
        {
            wait = WaitForSingleObject(children[j].hProcess, 0);
            ok(wait == WAIT_TIMEOUT, "A1b fault child %lu not live, wait %#lx\n", j, wait);
            if (wait != WAIT_TIMEOUT) return FALSE;
        }
        owner = !i ? GetCurrentProcessId() : children[i - 1].dwProcessId;
        data->owner = data->expected_owner = owner;
        if (!i) accepted = dispatch_continuation(data, regions[0], regions[2], owner);
        else
        {
            j = i - 1;
            shared->continuation_accepted[j] = 0;
            events[0] = shared->done[j];
            events[1] = children[j].hProcess;
            if (!SetEvent(shared->run[j])) return FALSE;
            wait = WaitForMultipleObjects(2, events, FALSE, 10000);
            ok(wait == WAIT_OBJECT_0, "A1b fault host %lu completion wait %#lx\n", owner, wait);
            if (wait != WAIT_OBJECT_0) return FALSE;
            accepted = shared->continuation_accepted[j];
        }
        ok(accepted, "A1b fault phase %lu rejected\n", i);
        if (!accepted) return FALSE;
        ok(data->starts == 1 && !data->completed && data->checks == i && !data->errors,
                "A1b fault logical starts/completed/checks/errors %lu/%lu/%lu/%lu\n",
                data->starts, data->completed, data->checks, data->errors);
        ok(data->dispatches == i + 1 && data->native_checks == (i + 1) * 19,
                "A1b fault native returns/checks %lu/%lu at %lu\n", data->dispatches, data->native_checks, i);
        ok(data->native_rsp == data->native_after && data->native_rsp
                && (data->native_rsp < low || data->native_rsp >= high),
                "A1b fault native stack not restored %#Ix/%#Ix\n", data->native_rsp, data->native_after);
        if (i < 2)
            ok(data->phase == i + 1 && data->state == 1 && !fault->caught,
                    "A1b pre-fault checkpoint phase/state/caught %lu/%lu/%lu\n", data->phase, data->state, fault->caught);
    }
    trace("A1b real migrated AV: owner %lu thread %lu code %#lx flags %#lx parameters %lu read %lu address %#Ix, RIP %#Ix RSP %#Ix handler local %#Ix; current native RIP %#Ix RSP %#Ix, native ABI %lu dispatches %lu, removed/released/TEB %lu/%lu/%lu\n",
            fault->pid, fault->tid, fault->code, fault->flags, fault->parameters, fault->access,
            fault->address, fault->rip, fault->rsp, fault->handler_rsp,
            fault->native_return, fault->native_rsp, data->native_checks, data->dispatches,
            fault->removed, fault->released, fault->teb_unchanged);
    ok(fault->caught == 1 && fault->pid == children[1].dwProcessId && fault->tid,
            "A1b exact fault count/owner/thread %lu/%lu/%lu\n", fault->caught, fault->pid, fault->tid);
    ok(fault->code == STATUS_ACCESS_VIOLATION && !fault->flags && fault->parameters == 2
            && !fault->access && fault->address && fault->rip == continuation_address(regions[0], continuation_fault_instruction),
            "A1b genuine AV record did not match injected ordinary read\n");
    ok(fault->rsp == high - 0xa0 && fault->handler_rsp > low + 0x1000 && fault->handler_rsp < fault->rsp,
            "A1b fault/handler stack outside shared region %#Ix/%#Ix\n", fault->rsp, fault->handler_rsp);
    ok(fault->native_rsp == data->native_rsp && fault->native_return == data->native_return
            && fault->native_rsp >= fault->stack_limit && fault->native_rsp < fault->stack_base,
            "A1b recovery did not use current B native bridge\n");
    ok(data->phase == 2 && data->state == 3 && data->cancelled && !data->saved_rsp && !data->saved_rip,
            "A1b fault continuation remained resumable\n");
    ok(fault->rejected == 1 && fault->native_caught == 1 && fault->native_unchanged,
            "A1b unrelated armed native AV did not pass through unchanged\n");
    ok(fault->removed && fault->released && fault->teb_unchanged && !data->fault_scope && !data->fault_address,
            "A1b fault cleanup/TEB restoration incomplete\n");
    ok(data->observations[2].owner == children[1].dwProcessId
            && data->observations[2].common == 0xb2 && data->observations[2].target == 0xd4
            && data->accumulator == 0x1ac && *(ULONG64 *)(data->initial_rsp - 0x10) == 0x1bc,
            "A1b fault samples owner/private %lu/%#lx/%#lx accumulator/local %#I64x/%#I64x\n",
            data->observations[2].owner, data->observations[2].common, data->observations[2].target,
            data->accumulator, *(ULONG64 *)(data->initial_rsp - 0x10));
    ok(*(DWORD *)regions[2] == 0x31415926 && *(DWORD *)((BYTE *)regions[2] + EXECUTION_REGION_SIZE - 4) == 0x27182818,
            "A1b fault stack boundary sentinel changed\n");
    dispatches = data->dispatches;
    /* Test terminal admission under a valid current owner, then with the
     * cancellation flag removed so the terminal state alone must reject it. */
    data->owner = data->expected_owner = GetCurrentProcessId();
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && data->dispatches == dispatches, "A1b cancelled fault continuation restarted\n");
    data->cancelled = 0;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && data->dispatches == dispatches, "A1b terminal fault state restarted\n");
    data->cancelled = 1;
    shared->continuation_mode = 0;
    return TRUE;
}

static BOOL test_unwind_continuation(struct attachment_shared *shared, void **regions,
        PROCESS_INFORMATION *children, BOOL compiler)
{
    static const ULONG64 cookies[] = {0x1122334455667788, 0x2233445566778899, 0x33445566778899aa};
    struct continuation_data *data = (void *)((BYTE *)regions[1] + CONTINUATION_DATA_OFFSET);
    struct continuation_unwind_result *result = &data->unwind;
    ULONG_PTR low = (ULONG_PTR)regions[2], high = low + EXECUTION_REGION_SIZE;
    HANDLE events[2];
    DWORD i, j, owner, wait, dispatches;
    BOOL accepted;

    initialize_continuation(shared, regions);
    data->fault_enabled = data->unwind_enabled = 1;
    data->compiler_enabled = compiler;
    shared->continuation_mode = 1;
    for (i = 0; i < 3; ++i)
    {
        for (j = 0; j < 2; ++j)
        {
            wait = WaitForSingleObject(children[j].hProcess, 0);
            ok(wait == WAIT_TIMEOUT, "A1b unwind child %lu not live, wait %#lx\n", j, wait);
            if (wait != WAIT_TIMEOUT) return FALSE;
        }
        owner = !i ? GetCurrentProcessId() : children[i - 1].dwProcessId;
        data->owner = data->expected_owner = owner;
        if (!i) accepted = dispatch_continuation(data, regions[0], regions[2], owner);
        else
        {
            j = i - 1;
            shared->continuation_accepted[j] = 0;
            events[0] = shared->done[j];
            events[1] = children[j].hProcess;
            if (!SetEvent(shared->run[j])) return FALSE;
            wait = WaitForMultipleObjects(2, events, FALSE, 10000);
            ok(wait == WAIT_OBJECT_0, "A1b unwind host %lu completion wait %#lx\n", owner, wait);
            if (wait != WAIT_OBJECT_0) return FALSE;
            accepted = shared->continuation_accepted[j];
        }
        ok(accepted, "A1b unwind phase %lu rejected\n", i);
        if (!accepted) return FALSE;
        ok(data->starts == 1 && !data->completed && data->checks == i && !data->errors,
                "A1b unwind starts/completed/checks/errors %lu/%lu/%lu/%lu\n",
                data->starts, data->completed, data->checks, data->errors);
        ok(data->dispatches == i + 1 && data->native_checks == (i + 1) * 19,
                "A1b unwind native returns/checks %lu/%lu at %lu\n", data->dispatches, data->native_checks, i);
        ok(data->native_rsp == data->native_after && data->native_rsp
                && (data->native_rsp < low || data->native_rsp >= high),
                "A1b unwind current native RSP not restored %#Ix/%#Ix\n", data->native_rsp, data->native_after);
        if (i < 2)
        {
            ok(data->phase == i + 1 && data->state == 1 && !result->search_count && !result->cleanup_count,
                    "A1b unwind checkpoint phase/state/search/cleanup %lu/%lu/%lu/%lu\n",
                    data->phase, data->state, result->search_count, result->cleanup_count);
            ok(data->resources[0] == 0xcafe0001 && data->resources[1] == 0xcafe0002
                    && data->resources[2] == (i ? 0xcafe0003 : 0),
                    "A1b unwind frame entries did not create live resources %#lx/%#lx/%#lx\n",
                    data->resources[0], data->resources[1], data->resources[2]);
        }
    }
    trace("A1b real %s unwind: owner %lu thread %lu code %#lx flags %#lx parameters %lu read %lu address %#Ix, fault RIP %#Ix RSP %#Ix; active TEB stack %#Ix-%#Ix allocation %#Ix; search/cleanup/target/landing %lu/%lu/%lu/%lu errors %lu, landing RIP %#Ix RSP %#Ix captured local %#I64x; current native RIP %#Ix RSP %#Ix ABI %lu dispatches %lu, bound switches/restores %lu/%lu identity %lu; registered/deleted/absent/VEH/page/TLS %lu/%lu/%lu/%lu/%lu/%lu\n",
            compiler ? "compiler-finally" : "frame", result->pid, result->tid, result->code, result->flags, result->parameters, result->access,
            result->address, result->rip, result->rsp, result->stack_limit, result->stack_base, result->deallocation,
            result->search_count, result->cleanup_count, result->target_count, result->landing_count, result->errors,
            result->landing_rip, result->landing_rsp, result->landing_local, result->native_return, result->native_rsp,
            data->native_checks, data->dispatches, result->bounds_entered, result->bounds_restored, result->native_identity,
            result->registered, result->removed, result->lookup_absent, result->handlers_removed, result->released, result->tls_removed);
    ok(result->search_count == 3 && result->cleanup_count == 3 && result->target_count == 1
            && result->landing_count == 1 && !result->errors,
            "A1b real frame search/cleanup/target/landing/errors %lu/%lu/%lu/%lu/%lu\n",
            result->search_count, result->cleanup_count, result->target_count, result->landing_count, result->errors);
    ok(result->pid == children[1].dwProcessId && result->tid && result->code == STATUS_ACCESS_VIOLATION
            && !result->flags && result->parameters == 2 && !result->access && result->address
            && result->rip == continuation_address(regions[0], compiler ? continuation_compiler_fault : continuation_fault_instruction)
            && (compiler ? result->rsp == data->finally.fault_rsp && result->rsp > low + 0x1000
                    && result->rsp < high - 0xa0 : result->rsp == high - 0xa0),
            "A1b frame unwinding did not originate from exact B ordinary-read AV\n");
    ok(result->stack_limit == low && result->stack_base == high && result->deallocation == low,
            "A1b real dispatch did not observe truthful active shared-stack bounds\n");
    ok(result->bounds_entered == 1 && result->bounds_restored == 1
            && result->native_bounds && result->native_identity && result->teb,
            "A1b active/native stack description or actual host identity not restored\n");
    ok(result->native_rsp == data->native_rsp && result->native_return == data->native_return
            && result->native_rsp >= result->native_limit && result->native_rsp < result->native_base,
            "A1b frame unwind did not return through current B native bridge\n");
    ok(result->landing_rsp == high - 0x40
            && result->landing_rip == continuation_address(regions[0], continuation_unwind_landing)
            && result->landing_local == 0x1bc,
            "A1b RtlUnwindEx target landing RSP/RIP/captured local mismatch\n");
    for (i = 0; i < 3; ++i)
    {
        DWORD id = 2 - i;
        const struct continuation_unwind_event *search = &result->search[i], *cleanup = &result->cleanup[i];

        trace("A1b frame %lu: search id %lu flags %#lx frame %#Ix handler %#Ix PC %#Ix cookie %#Ix resource %#lx; cleanup id %lu flags %#lx frame %#Ix handler %#Ix PC %#Ix cookie %#Ix resource %#lx\n",
                i, search->frame_id, search->flags, search->frame, search->handler_rsp, search->control_pc,
                search->cookie, search->resource, cleanup->frame_id, cleanup->flags, cleanup->frame,
                cleanup->handler_rsp, cleanup->control_pc, cleanup->cookie, cleanup->resource);
        ok(search->frame_id == id && !search->flags && search->frame == high - 0x40 - id * 0x30
                && search->cookie == cookies[id] && search->resource == 0xcafe0001 + id,
                "A1b actual search order/frame/cookie/resource mismatch at %lu\n", i);
        ok(cleanup->frame_id == id && cleanup->flags == (EXCEPTION_UNWINDING | (!id ? EXCEPTION_TARGET_UNWIND : 0))
                && cleanup->frame == search->frame && cleanup->cookie == cookies[id]
                && cleanup->resource == 0xcafe0001 + id && !data->resources[id],
                "A1b actual cleanup order/flags/one-time consumption mismatch at %lu\n", i);
        ok(search->handler_rsp > low + 0x1000 && search->handler_rsp < high - 0xa0
                && cleanup->handler_rsp > low + 0x1000 && cleanup->handler_rsp < high - 0xa0,
                "A1b search/unwind handlers escaped the actual shared stack at %lu\n", i);
    }
    ok(result->veh_search == 1 && result->rejected == 1 && result->control_caught == 1 && result->control_unchanged,
            "A1b frame AV did not pass observing VEH or unrelated native AV changed\n");
    ok(result->registered && result->removed && result->lookup_absent && result->handlers_removed
            && result->released && result->tls_removed && !data->unwind_scope && !data->fault_address
            && !data->preserve_mappings, "A1b frame table/handler/allocation/TLS cleanup incomplete\n");
    ok(data->phase == 2 && data->state == 3 && data->cancelled && !data->saved_rsp && !data->saved_rip,
            "A1b unwound logical continuation remained resumable\n");
    ok(data->observations[2].owner == children[1].dwProcessId && data->observations[2].common == 0xb2
            && data->observations[2].target == 0xd4 && data->accumulator == 0x1ac,
            "A1b frame fixture did not preserve actual B private-memory observations\n");
    ok(*(DWORD *)regions[2] == 0x31415926 && *(DWORD *)((BYTE *)regions[2] + EXECUTION_REGION_SIZE - 4) == 0x27182818,
            "A1b unwind stack boundary sentinels changed\n");
    if (compiler)
    {
        struct continuation_finally_result *finally = &data->finally;

        trace("A1b compiler finally: linked helper %#Ix image %#Ix metadata %lu; entries %lu protected progress %lu normal/abnormal returns %lu/%lu cleanup %lu/%lu zeroed locals %lu errors %lu mask %#lx exact fault RSP %#Ix\n",
                finally->helper_address, finally->helper_image, finally->metadata, finally->entered, finally->protected_returned,
                finally->normal_returned, finally->abnormal_returned, finally->normal_count,
                finally->abnormal_count, finally->resources_cleared, finally->errors, finally->error_mask, finally->fault_rsp);
        ok(finally->metadata && finally->helper_address && finally->helper_image,
                "A1b compiler finally did not use the current host's linked PE metadata\n");
        ok(finally->entered == 2 && finally->normal_returned == 1 && !finally->abnormal_returned
                && finally->normal_count == 2 && finally->abnormal_count == 2 && finally->resources_cleared == 2
                && finally->protected_returned == 1 && !finally->errors,
                "A1b compiler finally entries/returns/cleanup/errors %lu/%lu/%lu/%lu/%lu/%lu\n",
                finally->entered, finally->normal_returned, finally->abnormal_returned,
                finally->normal_count, finally->abnormal_count, finally->errors);
        for (i = 0; i < 2; ++i)
        {
            const struct continuation_finally_event *normal = &finally->normal[i], *abnormal = &finally->abnormal[i];
            DWORD id = 1 - i;

            trace("A1b compiler finally %lu: normal id/abnormal/resource %lu/%lu/%#lx cookie %#I64x parent resource/cookie %#Ix/%#Ix local %#Ix identity %lu errors %#lx; unwind id/abnormal/resource %lu/%lu/%#lx cookie %#I64x parent resource/cookie %#Ix/%#Ix local %#Ix identity %lu errors %#lx\n",
                    i, normal->id, normal->abnormal, normal->resource, normal->cookie,
                    normal->resource_address, normal->cookie_address, normal->handler_rsp, normal->identity, normal->error_mask,
                    abnormal->id, abnormal->abnormal, abnormal->resource, abnormal->cookie,
                    abnormal->resource_address, abnormal->cookie_address, abnormal->handler_rsp, abnormal->identity, abnormal->error_mask);
            ok(normal->id == id && !normal->abnormal && normal->resource == 0xf1a10001 + id
                    && normal->cookie == 0xa1b0f1a100000001ull + id && normal->identity,
                    "A1b normal compiler finally order/abnormal/local resource/cookie/identity mismatch at %lu\n", i);
            ok(abnormal->id == id && abnormal->abnormal == 1 && abnormal->resource == 0xf1a10001 + id
                    && abnormal->cookie == 0xa1b0f1a100000001ull + id && abnormal->identity,
                    "A1b unwind compiler finally order/abnormal/local resource/cookie/identity mismatch at %lu\n", i);
            ok(normal->resource_address == abnormal->resource_address
                    && normal->cookie_address == abnormal->cookie_address
                    && abnormal->resource_address > finally->fault_rsp && abnormal->resource_address < high - 0xa0
                    && abnormal->cookie_address > finally->fault_rsp && abnormal->cookie_address < high - 0xa0,
                    "A1b compiler finally did not recover its genuine parent-frame locals at %lu\n", i);
            ok(normal->handler_rsp > low + 0x1000 && normal->handler_rsp < high - 0xa0
                    && abnormal->handler_rsp > low + 0x1000 && abnormal->handler_rsp < high - 0xa0,
                    "A1b compiler finally escaped the shared stack at %lu\n", i);
        }
        ok(!data->compiler_entry, "A1b compiler helper authority persisted after cleanup\n");
    }
    dispatches = data->dispatches;
    data->owner = data->expected_owner = GetCurrentProcessId();
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && data->dispatches == dispatches, "A1b cancelled unwound continuation restarted\n");
    data->cancelled = 0;
    ok(!dispatch_continuation(data, regions[0], regions[2], data->owner)
            && data->dispatches == dispatches, "A1b terminal unwind state restarted\n");
    data->cancelled = 1;
    shared->continuation_mode = 0;
    return TRUE;
}

static BOOL stop_attachment_children(PROCESS_INFORMATION *children, HANDLE stop)
{
    unsigned int i;
    DWORD wait;
    BOOL reaped = TRUE;

    if (stop) SetEvent(stop);
    for (i = 0; i < 2; ++i)
    {
        if (!children[i].hProcess) continue;
        wait = WaitForSingleObject(children[i].hProcess, 10000);
        ok(wait == WAIT_OBJECT_0, "attachment child %u exit wait %#lx\n", i, wait);
        if (wait != WAIT_OBJECT_0)
        {
            ok(TerminateProcess(children[i].hProcess, 1),
                    "failed to terminate attachment child %u, error %lu\n", i, GetLastError());
            wait = WaitForSingleObject(children[i].hProcess, 10000);
            ok(wait == WAIT_OBJECT_0, "terminated attachment child %u wait %#lx\n", i, wait);
        }
        if (wait != WAIT_OBJECT_0) reaped = FALSE;
        if (wait == WAIT_OBJECT_0)
        {
            DWORD exit_code = STILL_ACTIVE;
            ok(GetExitCodeProcess(children[i].hProcess, &exit_code) && !exit_code,
                    "attachment child %u abnormal exit %lu\n", i, exit_code);
        }
        CloseHandle(children[i].hThread);
        CloseHandle(children[i].hProcess);
        memset(&children[i], 0, sizeof(children[i]));
    }
    return reaped;
}
#endif

static void test_process_attachment(void)
{
#ifdef __x86_64__
    static const char * const phases[] = {"caller", "A", "nested B", "restored A", "restored caller"};
    static const BYTE common_values[] = {0x59, 0xa1, 0xb2, 0xa1, 0x59};
    static const BYTE target_values[] = {0, 0xc3, 0xd4, 0xc3, 0};
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    PROCESS_INFORMATION children[2] = {{0}};
    STARTUPINFOA startup = {sizeof(startup)};
    struct attachment_shared *shared = NULL;
    struct attachment_output output;
    struct attachment_input input;
    MEMORY_BASIC_INFORMATION info;
    HANDLE mapping = NULL, ready[2] = {NULL, NULL}, stop = NULL;
    HANDLE execution_mapping[3] = {NULL}, run[2] = {NULL}, done[2] = {NULL};
    void *regions[3] = {NULL}, *code_init = NULL;
    DWORD protection[3];
    char executable[MAX_PATH], command[MAX_PATH + 128];
    BYTE *common = NULL;
    DWORD size, wait;
    unsigned int attempt, i;
    BOOL ret, fixture_ready = FALSE;

    if (!GetModuleFileNameA(NULL, executable, sizeof(executable)))
    {
        ok(0, "attachment executable path failed, error %lu\n", GetLastError());
        return;
    }
    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
            0, sizeof(*shared), NULL);
    if (mapping) shared = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(*shared));
    stop = CreateEventA(&sa, TRUE, FALSE, NULL);
    for (i = 0; i < 2; ++i) ready[i] = CreateEventA(&sa, TRUE, FALSE, NULL);
    ok(shared && stop && ready[0] && ready[1], "attachment IPC setup failed, error %lu\n", GetLastError());
    if (!shared || !stop || !ready[0] || !ready[1]) goto cleanup;
    for (i = 0; i < 3; ++i)
    {
        execution_mapping[i] = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa,
                i ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE, 0, EXECUTION_REGION_SIZE, NULL);
        shared->execution_mapping[i] = execution_mapping[i];
        ok(!!execution_mapping[i], "A1b region %u section failed, error %lu\n", i, GetLastError());
        if (!execution_mapping[i]) goto cleanup;
    }
    /* Only this temporary initialization view is writable; all executing
     * views have RX code and separate nonexecutable RW data and stack. */
    code_init = MapViewOfFile(execution_mapping[0], FILE_MAP_WRITE, 0, 0, EXECUTION_REGION_SIZE);
    ok(!!code_init, "A1b code initialization map failed, error %lu\n", GetLastError());
    if (!code_init) goto cleanup;
    ok(continuation_code_end - continuation_code_start < EXECUTION_REGION_SIZE - CONTINUATION_CODE_OFFSET,
            "A1b continuation exceeds shared code region\n");
    if (continuation_code_end - continuation_code_start >= EXECUTION_REGION_SIZE - CONTINUATION_CODE_OFFSET)
        goto cleanup;
    ok(continuation_code_end - continuation_code_start < CONTINUATION_UNWIND_OFFSET - CONTINUATION_CODE_OFFSET,
            "A1b continuation overlaps immutable unwind metadata\n");
    if (continuation_code_end - continuation_code_start >= CONTINUATION_UNWIND_OFFSET - CONTINUATION_CODE_OFFSET)
        goto cleanup;
    memcpy(code_init, execution_code, sizeof(execution_code));
    memcpy((BYTE *)code_init + CONTINUATION_CODE_OFFSET, continuation_code_start,
            continuation_code_end - continuation_code_start);
    initialize_continuation_unwind_info(code_init);
    FlushInstructionCache(GetCurrentProcess(), code_init, EXECUTION_REGION_SIZE);
    UnmapViewOfFile(code_init);
    code_init = NULL;
    for (i = 0; i < 2; ++i)
    {
        shared->run[i] = run[i] = CreateEventA(&sa, FALSE, FALSE, NULL);
        shared->done[i] = done[i] = CreateEventA(&sa, FALSE, FALSE, NULL);
        ok(run[i] && done[i], "A1b child %u handoff events failed, error %lu\n", i, GetLastError());
        if (!run[i] || !done[i]) goto cleanup;
    }

    /* Low, allocation-granularity-aligned candidates work on native x64 too.
     * Retry address collisions; the children remain live throughout the IOCTL. */
    for (attempt = 0; attempt < 6; ++attempt)
    {
        shared->common_address = 0x18000000 + attempt * 0x10000000;
        shared->target_address = shared->common_address + 0x10000;
        if (!VirtualQuery((void *)shared->target_address, &info, sizeof(info)) || info.State != MEM_FREE)
            continue;
        common = VirtualAlloc((void *)shared->common_address, 0x1000,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!common) continue;
        *common = common_values[0];
        for (i = 0; i < 3; ++i) shared->execution_address[i] = shared->common_address + 0x20000 + i * 0x10000;
        if (!map_execution_regions(shared, regions, protection))
        {
            trace("A1b caller mapping candidate unavailable, error %lu\n", GetLastError());
            for (i = 0; i < 3; ++i)
            {
                if (regions[i]) UnmapViewOfFile(regions[i]);
                regions[i] = NULL;
            }
            VirtualFree(common, 0, MEM_RELEASE);
            common = NULL;
            continue;
        }
        memset(regions[1], 0, sizeof(struct execution_data));
        memset(regions[2], 0, EXECUTION_REGION_SIZE);
        *(DWORD *)regions[2] = 0x31415926;
        *(DWORD *)((BYTE *)regions[2] + EXECUTION_REGION_SIZE - 4) = 0x27182818;
        ResetEvent(stop);
        fixture_ready = TRUE;
        for (i = 0; i < 2; ++i)
        {
            ResetEvent(ready[i]);
            shared->error[i] = ERROR_GEN_FAILURE;
            shared->collision_ok[i] = shared->observed_sequence[i] = shared->process_id[i] = 0;
            memset(shared->protection[i], 0, sizeof(shared->protection[i]));
            ResetEvent(run[i]);
            ResetEvent(done[i]);
            snprintf(command, sizeof(command), "\"%s\" ntoskrnl attachment_child %I64x %I64x %I64x %u",
                    executable, (ULONG64)(ULONG_PTR)mapping, (ULONG64)(ULONG_PTR)ready[i],
                    (ULONG64)(ULONG_PTR)stop, i);
            ret = CreateProcessA(executable, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &children[i]);
            ok(ret, "attachment child %u creation failed, error %lu\n", i, GetLastError());
            if (!ret) { fixture_ready = FALSE; break; }
            wait = WaitForSingleObject(ready[i], 10000);
            ok(wait == WAIT_OBJECT_0, "attachment child %u readiness wait %#lx\n", i, wait);
            if (wait != WAIT_OBJECT_0 || shared->error[i]) { fixture_ready = FALSE; break; }
        }
        if (fixture_ready) break;
        trace("attachment candidate %p unavailable, child errors %lu/%lu\n",
                common, shared->error[0], shared->error[1]);
        /* Never reset the stop event or reuse shared configuration after a
         * child failed bounded reaping. Its own expiry is the final fallback. */
        if (!stop_attachment_children(children, stop)) goto cleanup;
        for (i = 0; i < 3; ++i)
        {
            if (regions[i]) UnmapViewOfFile(regions[i]);
            regions[i] = NULL;
        }
        VirtualFree(common, 0, MEM_RELEASE);
        common = NULL;
    }
    if (!fixture_ready)
    {
        skip("Could not establish two live processes at the same virtual address.\n");
        goto cleanup;
    }
    ret = VirtualQuery((void *)shared->target_address, &info, sizeof(info));
    ok(ret && info.State == MEM_FREE, "target-only address %#Ix is not absent from caller\n", shared->target_address);
    if (!ret || info.State != MEM_FREE) goto cleanup;
    input.process_id[0] = children[0].dwProcessId;
    input.process_id[1] = children[1].dwProcessId;
    input.common_address = shared->common_address;
    input.target_address = shared->target_address;
    for (i = 0; i < 2; ++i)
    {
        wait = WaitForSingleObject(children[i].hProcess, 0);
        ok(wait == WAIT_TIMEOUT, "attachment child %u is no longer live, wait %#lx\n", i, wait);
        if (wait != WAIT_TIMEOUT) goto cleanup;
    }
    if (!test_execution_regions(shared, regions, common, children)) goto cleanup;
    if (!test_continuation(shared, regions, children)) goto cleanup;
    if (!test_fault_continuation(shared, regions, children)) goto cleanup;
    if (!test_unwind_continuation(shared, regions, children, FALSE)) goto cleanup;
#ifdef USE_COMPILER_EXCEPTIONS
    if (!test_unwind_continuation(shared, regions, children, TRUE)) goto cleanup;
#else
    skip("A1b compiler finally requires native compiler __try/__finally support\n");
#endif
    /* A newly initialized full continuation after all fault cleanups must still
     * complete all five phases before the unchanged E05 driver fixture. */
    if (!test_continuation(shared, regions, children)) goto cleanup;
    /* Keep the original E05 IOCTL and its eight todos independent of the
     * successful cooperative gate: real KeStackAttachProcess is unchanged. */
    memset(&output, 0xcc, sizeof(output));
    size = 0;
    ret = DeviceIoControl(device, IOCTL_WINETEST_PROCESS_ATTACHMENT, &input, sizeof(input),
            &output, sizeof(output), &size, NULL);
    ok(ret, "attachment DeviceIoControl failed, error %lu\n", GetLastError());
    ok(size == sizeof(output), "attachment output size %lu\n", size);
    if (!ret || size != sizeof(output)) goto cleanup;
    trace("attachment common %#Ix, target-only %#Ix, processes %lu/%lu, valid %#lx/%#x, fault %#lx, lookups %#lx/%#lx\n",
            input.common_address, input.target_address, input.process_id[0], input.process_id[1],
            output.valid_status, output.valid_value, output.fault_status, output.lookup_status[0], output.lookup_status[1]);
    ok(!output.valid_status && output.valid_value == 0x7e,
            "guarded valid stack read status %#lx byte %#x\n", output.valid_status, output.valid_value);
    ok(output.fault_status == STATUS_ACCESS_VIOLATION, "guarded NULL read status %#lx\n", output.fault_status);
    for (i = 0; i < 2; ++i)
        ok(!output.lookup_status[i], "attachment process %u lookup status %#lx\n", i, output.lookup_status[i]);
    if (output.valid_status || output.valid_value != 0x7e || output.fault_status != STATUS_ACCESS_VIOLATION
            || output.lookup_status[0] || output.lookup_status[1])
        goto cleanup;
    for (i = 0; i < ATTACHMENT_OBSERVATIONS; ++i)
    {
        const struct attachment_observation *observation = &output.observations[i];
        NTSTATUS target_status = i && i != 4 ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
        trace("attachment %s: common status %#lx byte %#x; target status %#lx byte %#x\n", phases[i],
                observation->common_status, observation->common_value, observation->target_status, observation->target_value);
        /* Wine's driver host is separate from the caller, and attachment is
         * currently a no-op. Keep every ordinary read visible as a todo. */
        todo_wine ok(!observation->common_status && observation->common_value == common_values[i],
                "attachment %s common: status %#lx byte %#x, expected %#x\n", phases[i],
                observation->common_status, observation->common_value, common_values[i]);
        if (target_status == STATUS_SUCCESS)
            todo_wine ok(!observation->target_status && observation->target_value == target_values[i],
                    "attachment %s target: status %#lx byte %#x, expected %#x\n", phases[i],
                    observation->target_status, observation->target_value, target_values[i]);
        else
            ok(observation->target_status == target_status, "attachment %s target status %#lx\n",
                    phases[i], observation->target_status);
    }
    ret = VirtualQuery((void *)shared->target_address, &info, sizeof(info));
    ok(ret && info.State == MEM_FREE, "target-only address no longer absent from caller\n");
    for (i = 0; i < 2; ++i)
        ok(WaitForSingleObject(children[i].hProcess, 0) == WAIT_TIMEOUT,
                "attachment child %u exited before fixture completion\n", i);

cleanup:
    stop_attachment_children(children, stop);
    if (code_init) UnmapViewOfFile(code_init);
    for (i = 0; i < 3; ++i)
    {
        if (regions[i])
        {
            ret = UnmapViewOfFile(regions[i]);
            ok(ret && VirtualQuery(regions[i], &info, sizeof(info)) && info.State == MEM_FREE,
                    "A1b parent region %u was not released\n", i);
        }
        if (execution_mapping[i]) CloseHandle(execution_mapping[i]);
    }
    for (i = 0; i < 2; ++i)
    {
        if (run[i]) CloseHandle(run[i]);
        if (done[i]) CloseHandle(done[i]);
    }
    if (common) VirtualFree(common, 0, MEM_RELEASE);
    if (shared) UnmapViewOfFile(shared);
    if (mapping) CloseHandle(mapping);
    if (stop) CloseHandle(stop);
    for (i = 0; i < 2; ++i) if (ready[i]) CloseHandle(ready[i]);
#else
    skip("Direct process-attachment fixture requires native x64 SEH; i386 and other architectures are pending.\n");
#endif
}

static void main_test(void)
{
    struct main_test_input test_input;
    DWORD size;
    BOOL res;

    test_input.process_id = GetCurrentProcessId();
    test_input.teststr_offset = (SIZE_T)((BYTE *)&teststr - (BYTE *)NtCurrentTeb()->Peb->ImageBaseAddress);
    test_input.modified_value = &modified_value;
    modified_value = 0;

    res = DeviceIoControl(device, IOCTL_WINETEST_MAIN_TEST, &test_input, sizeof(test_input), NULL, 0, &size, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(!size, "got size %lu\n", size);
}

static void test_shared_kernel_memory(void)
{
    const char *opt_in = getenv("WINE_SHARED_KERNEL_MEMORY");
    BYTE request = 1;
    DWORD size;
    BOOL ret;

    if (!winetest_platform_is_wine || !opt_in || strcmp(opt_in, "1")) return;

    ret = DeviceIoControl(device, IOCTL_WINETEST_SHARED_KERNEL_MEMORY, &request, sizeof(request),
            NULL, 0, &size, NULL);
    ok(ret, "Shared-kernel-memory IOCTL failed: %lu\n", GetLastError());
    ok(!size, "got output size %lu\n", size);
}

static void test_basic_ioctl(void)
{
    char inbuf[64], buf[32];
    DWORD written;
    BOOL res;

    res = DeviceIoControl(device, IOCTL_WINETEST_BASIC_IOCTL, NULL, 0, buf,
                          sizeof(buf), &written, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(written == sizeof(teststr), "got size %ld\n", written);
    ok(!strcmp(buf, teststr), "got '%s'\n", buf);

    memset(buf, 0, sizeof(buf));
    res = DeviceIoControl(device, IOCTL_WINETEST_BASIC_IOCTL, inbuf,
            sizeof(inbuf), buf, 10, &written, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(written == 10, "got size %ld\n", written);
    ok(!strcmp(buf, "Wine is no"), "got '%s'\n", buf);
}

static BOOL cancelioex_returned;

enum cancel_test
{
    cancel,
    cancelex,
    cancelex_cancel,
    cancel_cancelex,
    cancelsync,
};

struct cancel_thread_ctx
{
    HANDLE file;
    enum cancel_test test;
};

static DWORD WINAPI test_cancel_thread(void *param)
{
    struct cancel_thread_ctx *ctx = param;
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK cancel_sb;
    DWORD cancel_cnt, size;
    OVERLAPPED o, o2, o3;
    BOOL res;

    res = DeviceIoControl(ctx->file, IOCTL_WINETEST_RESET_CANCEL, NULL, 0, NULL, 0, NULL, &o);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());

    if (ctx->test != cancelsync)
    {
        res = DeviceIoControl(ctx->file, IOCTL_WINETEST_QUEUE_ASYNC, NULL, 0, NULL, 0, NULL, &o);
        ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());

        res = DeviceIoControl(ctx->file, IOCTL_WINETEST_QUEUE_ASYNC, NULL, 0, NULL, 0, NULL, &o2);
        ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());
    }

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(ctx->file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &o3);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    if (ctx->test == cancelsync)
    {
        /* This hangs */
        if (0)
        {
            res = DeviceIoControl(ctx->file, IOCTL_WINETEST_QUEUE_ASYNC, NULL, 0, NULL, 0, &size, NULL);
            ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
        }
        /* This hangs if the cancel routine doesn't call IoCompleteRequest()
         * (regardless of Status / Information values) */
        res = DeviceIoControl(ctx->file, IOCTL_WINETEST_TEST_CANCEL, NULL, 0, NULL, 0, &size, NULL);
        ok(!res && GetLastError() == ERROR_OPERATION_ABORTED, "DeviceIoControl failed: %lu\n", GetLastError());
    }

    if (ctx->test == cancel || ctx->test == cancel_cancelex)
    {
        status = NtCancelIoFile(ctx->file, &cancel_sb);
        ok(!status, "Unexpected status %lu\n", status);
        ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
        ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
    }
    else if (ctx->test == cancelex || ctx->test == cancelex_cancel)
    {
        status = NtCancelIoFileEx(ctx->file, NULL, &cancel_sb);
        ok(!status, "Unexpected status %lu\n", status);
        ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
        ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
        status = NtCancelIoFileEx(ctx->file, NULL, &cancel_sb);
        ok(!status, "Unexpected status %lu\n", status);
        ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
        ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
        cancelioex_returned = TRUE;
    }
    if (ctx->test == cancelex_cancel)
    {
        status = NtCancelIoFile(ctx->file, &cancel_sb);
        ok(!status, "Unexpected status %lu\n", status);
        ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
        ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
    }
    else if (ctx->test == cancel_cancelex)
    {
        status = NtCancelIoFileEx(ctx->file, NULL, &cancel_sb);
        ok(status, "Unexpected status %lu\n", status);
        ok(cancel_sb.Status == STATUS_NOT_FOUND, "Unexpected Status %lx\n", cancel_sb.Status);
        ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
    }
    return status;
}

static void test_overlapped(void)
{
    OVERLAPPED overlapped, overlapped2, *o;
    struct cancel_thread_ctx ctx;
    HANDLE file, port, thread;
    IO_STATUS_BLOCK cancel_sb;
    DWORD cancel_cnt, size;
    NTSTATUS status;
    ULONG_PTR key;
    DWORD ret;
    BOOL res;

    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    overlapped2.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    file = CreateFileA("\\\\.\\WineTestDriver", FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                       0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    /* test cancelling all device requests */
    res = DeviceIoControl(file, IOCTL_WINETEST_RESET_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());

    res = DeviceIoControl(file, IOCTL_WINETEST_TEST_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());

    res = DeviceIoControl(file, IOCTL_WINETEST_TEST_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped2);
    ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    CancelIo(file);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 2, "cancel_cnt = %lu\n", cancel_cnt);

    /* test cancelling selected overlapped event */
    if (pCancelIoEx)
    {
        res = DeviceIoControl(file, IOCTL_WINETEST_RESET_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
        ok(res, "DeviceIoControl failed: %lu\n", GetLastError());

        res = DeviceIoControl(file, IOCTL_WINETEST_TEST_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
        ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());

        res = DeviceIoControl(file, IOCTL_WINETEST_TEST_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped2);
        ok(!res && GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed: %lu\n", GetLastError());

        pCancelIoEx(file, &overlapped);

        cancel_cnt = 0xdeadbeef;
        res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped);
        ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
        ok(cancel_cnt == 1, "cancel_cnt = %lu\n", cancel_cnt);

        pCancelIoEx(file, &overlapped2);

        cancel_cnt = 0xdeadbeef;
        res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped);
        ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
        ok(cancel_cnt == 2, "cancel_cnt = %lu\n", cancel_cnt);
    }

    /* test cancelling uncancellable requests - CancelIo */
    ctx.file = file;
    ctx.test = cancel;
    thread = CreateThread(NULL, 0, test_cancel_thread, &ctx, 0, NULL);
    ret = WaitForSingleObject(thread, 100);
    ok(ret == WAIT_TIMEOUT, "CancelIo didn't block\n");
    res = DeviceIoControl(file, IOCTL_WINETEST_COMPLETE_ASYNC, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped2);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    /* test cancelling uncancellable requests - CancelIoEx */
    ctx.file = file;
    ctx.test = cancelex;
    cancelioex_returned = FALSE;
    thread = CreateThread(NULL, 0, test_cancel_thread, &ctx, 0, NULL);
    /* CancelIoEx() doesn't block, but the thread doesn't terminate either
     * until the pending IOCTL is completed */
    ret = WaitForSingleObject(thread, 100);
    todo_wine ok(ret == WAIT_TIMEOUT, "Thread already terminated\n");
    ok(cancelioex_returned, "CancelIoEx did block\n");
    res = DeviceIoControl(file, IOCTL_WINETEST_COMPLETE_ASYNC, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped2);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    /* test cancelling uncancellable requests - CancelIoEx + CancelIo */
    ctx.file = file;
    ctx.test = cancelex_cancel;
    cancelioex_returned = FALSE;
    thread = CreateThread(NULL, 0, test_cancel_thread, &ctx, 0, NULL);
    ret = WaitForSingleObject(thread, 100);
    ok(ret == WAIT_TIMEOUT, "Thread already terminated\n");
    ok(cancelioex_returned, "CancelIoEx did block\n");
    res = DeviceIoControl(file, IOCTL_WINETEST_COMPLETE_ASYNC, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped2);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    /* test cancelling uncancellable requests - CancelIo + CancelIoEx */
    ctx.file = file;
    ctx.test = cancel_cancelex;
    thread = CreateThread(NULL, 0, test_cancel_thread, &ctx, 0, NULL);
    ret = WaitForSingleObject(thread, 100);
    ok(ret == WAIT_TIMEOUT, "CancelIo didn't block\n");
    status = NtCancelIoFileEx(file, NULL, &cancel_sb);
    ok(!status, "Unexpected status %lu\n", status);
    ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
    ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
    ret = WaitForSingleObject(thread, 100);
    ok(ret == WAIT_TIMEOUT, "CancelIo didn't block\n");
    res = DeviceIoControl(file, IOCTL_WINETEST_COMPLETE_ASYNC, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(file, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), NULL, &overlapped2);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 0, "cancel_cnt = %lu\n", cancel_cnt);

    /* test cancelling uncancellable requests - CancelSynchronousIo */
    ctx.file = device;
    ctx.test = cancelsync;
    thread = CreateThread(NULL, 0, test_cancel_thread, &ctx, 0, NULL);
    WaitForSingleObject(thread, 100);
    ok(ret == WAIT_TIMEOUT, "Synchronous DeviceIoControl() already returned\n");
    status = NtCancelSynchronousIoFile(thread, NULL, &cancel_sb);
    ok(!status, "Unexpected status %lu\n", status);
    ok(!cancel_sb.Status, "Unexpected Status %lx\n", cancel_sb.Status);
    ok(!cancel_sb.Information, "Unexpected Information %Iu\n", cancel_sb.Information);
    ret = WaitForSingleObject(thread, INFINITE);
    ok(ret == WAIT_OBJECT_0, "CancelIoEx did block\n");
    CloseHandle(thread);

    cancel_cnt = 0xdeadbeef;
    res = DeviceIoControl(device, IOCTL_WINETEST_GET_CANCEL_COUNT, NULL, 0, &cancel_cnt, sizeof(cancel_cnt), &size, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    ok(cancel_cnt == 1, "cancel_cnt = %lu\n", cancel_cnt);

    /* test completion port */
    port = CreateIoCompletionPort(file, NULL, 0xdeadbeef, 0);
    ok(port != NULL, "CreateIoCompletionPort failed, error %lu\n", GetLastError());
    res = GetQueuedCompletionStatus(port, &size, &key, &o, 0);
    ok(!res && GetLastError() == WAIT_TIMEOUT, "GetQueuedCompletionStatus returned %x(%lu)\n", res, GetLastError());

    res = DeviceIoControl(file, IOCTL_WINETEST_RESET_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
    res = GetQueuedCompletionStatus(port, &size, &key, &o, 0);
    ok(res, "GetQueuedCompletionStatus failed: %lu\n", GetLastError());
    ok(o == &overlapped, "o != overlapped\n");

    if (pSetFileCompletionNotificationModes)
    {
        res = pSetFileCompletionNotificationModes(file, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
        ok(res, "SetFileCompletionNotificationModes failed: %lu\n", GetLastError());

        res = DeviceIoControl(file, IOCTL_WINETEST_RESET_CANCEL, NULL, 0, NULL, 0, NULL, &overlapped);
        ok(res, "DeviceIoControl failed: %lu\n", GetLastError());
        res = GetQueuedCompletionStatus(port, &size, &key, &o, 0);
        ok(!res && GetLastError() == WAIT_TIMEOUT, "GetQueuedCompletionStatus returned %x(%lu)\n", res, GetLastError());
    }

    CloseHandle(port);
    CloseHandle(overlapped.hEvent);
    CloseHandle(overlapped2.hEvent);
    CloseHandle(file);
}

static void test_load_driver(SC_HANDLE service)
{
    SERVICE_STATUS status;
    BOOL load, res;
    DWORD sz;

    res = QueryServiceStatus(service, &status);
    ok(res, "QueryServiceStatusEx failed: %lu\n", GetLastError());
    ok(status.dwCurrentState == SERVICE_STOPPED, "got state %#lx\n", status.dwCurrentState);

    load = TRUE;
    res = DeviceIoControl(device, IOCTL_WINETEST_LOAD_DRIVER, &load, sizeof(load), NULL, 0, &sz, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());

    res = QueryServiceStatus(service, &status);
    ok(res, "QueryServiceStatusEx failed: %lu\n", GetLastError());
    ok(status.dwCurrentState == SERVICE_RUNNING, "got state %#lx\n", status.dwCurrentState);

    load = FALSE;
    res = DeviceIoControl(device, IOCTL_WINETEST_LOAD_DRIVER, &load, sizeof(load), NULL, 0, &sz, NULL);
    ok(res, "DeviceIoControl failed: %lu\n", GetLastError());

    res = QueryServiceStatus(service, &status);
    ok(res, "QueryServiceStatusEx failed: %lu\n", GetLastError());
    ok(status.dwCurrentState == SERVICE_STOPPED, "got state %#lx\n", status.dwCurrentState);
}

static void test_file_handles(void)
{
    DWORD count, ret_size;
    HANDLE file, dup, file2;
    BOOL ret;

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CREATE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 2, "got %lu\n", count);

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CLOSE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 1, "got %lu\n", count);

    file = CreateFileA("\\\\.\\WineTestDriver", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CREATE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 3, "got %lu\n", count);

    file2 = CreateFileA("\\\\.\\WineTestDriver", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file2 != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CREATE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 4, "got %lu\n", count);

    ret = DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    ok(ret, "failed to duplicate handle: %lu\n", GetLastError());

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CREATE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 4, "got %lu\n", count);

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_FSCONTEXT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 1, "got %lu\n", count);

    ret = DeviceIoControl(file, IOCTL_WINETEST_GET_FSCONTEXT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 3, "got %lu\n", count);

    ret = DeviceIoControl(file2, IOCTL_WINETEST_GET_FSCONTEXT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 4, "got %lu\n", count);

    ret = DeviceIoControl(dup, IOCTL_WINETEST_GET_FSCONTEXT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 3, "got %lu\n", count);

    CloseHandle(dup);

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CLOSE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 1, "got %lu\n", count);

    CloseHandle(file2);

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CLOSE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 2, "got %lu\n", count);

    CloseHandle(file);

    ret = DeviceIoControl(device, IOCTL_WINETEST_GET_CLOSE_COUNT, NULL, 0, &count, sizeof(count), &ret_size, NULL);
    ok(ret, "ioctl failed: %lu\n", GetLastError());
    ok(count == 3, "got %lu\n", count);
}

static unsigned int got_return_status_apc;

static void WINAPI return_status_apc(void *apc_user, IO_STATUS_BLOCK *io, ULONG reserved)
{
    ++got_return_status_apc;
    ok(apc_user == (void *)456, "got %p\n", apc_user);
    ok(!reserved, "got reserved %#lx\n", reserved);
}

static void do_return_status(ULONG ioctl, struct return_status_params *params)
{
    const char *expect_buffer;
    LARGE_INTEGER zero = {{0}};
    HANDLE file, port, event;
    NTSTATUS expect_status;
    ULONG_PTR key, value;
    IO_STATUS_BLOCK io;
    char buffer[7];
    DWORD size;
    BOOL ret;

    if (params->ret_status == STATUS_PENDING && !params->pending)
    {
        /* this causes kernel hangs under certain conditions */
        return;
    }

    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (ioctl != IOCTL_WINETEST_RETURN_STATUS_BUFFERED)
        expect_buffer = "ghijkl";
    else if (NT_ERROR(params->iosb_status))
        expect_buffer = "abcdef";
    else
        expect_buffer = "ghidef";

    /* Test the non-overlapped case. */

    expect_status = (params->ret_status == STATUS_PENDING ? params->iosb_status : params->ret_status);

    strcpy(buffer, "abcdef");
    size = 0xdeadf00d;
    SetLastError(0xdeadf00d);
    ret = DeviceIoControl(device, ioctl, params, sizeof(*params), buffer, sizeof(buffer), &size, NULL);
    todo_wine_if (params->ret_status == STATUS_PENDING && params->iosb_status == STATUS_PENDING)
        ok(ret == NT_SUCCESS(expect_status), "got %d\n", ret);
    if (NT_SUCCESS(expect_status))
    {
        todo_wine_if (params->ret_status == STATUS_PENDING && params->iosb_status == STATUS_PENDING)
            ok(GetLastError() == 0xdeadf00d, "got error %lu\n", GetLastError());
    }
    else
    {
        ok(GetLastError() == RtlNtStatusToDosErrorNoTeb(expect_status), "got error %lu\n", GetLastError());
    }
    if (NT_ERROR(expect_status))
        ok(size == 0xdeadf00d, "got size %lu\n", size);
    else if (!NT_ERROR(params->iosb_status))
        ok(size == 3, "got size %lu\n", size);
    /* size is garbage if !NT_ERROR(expect_status) && NT_ERROR(iosb_status) */
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    strcpy(buffer, "abcdef");
    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    ret = NtDeviceIoControlFile(device, NULL, NULL, NULL, &io,
            ioctl, params, sizeof(*params), buffer, sizeof(buffer));
    ok(ret == expect_status, "got %#x\n", ret);
    if (NT_ERROR(params->iosb_status) && !params->pending)
    {
        ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
        ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
    }
    else
    {
        todo_wine_if (NT_ERROR(params->iosb_status) && params->pending)
            ok(io.Status == params->iosb_status /* newer win10/11 */
                    || broken(NT_ERROR(params->iosb_status) && params->pending && io.Status == 0xdeadf00d), /* older win10 */
                    "got %#lx\n", io.Status);
        todo_wine_if (NT_ERROR(params->iosb_status) && params->pending)
            ok(io.Information == 3 /* newer win10/11 */
                    || broken(NT_ERROR(params->iosb_status) && params->pending && io.Information == 0xdeadf00d), /* older win10 */
                    "got size %Iu\n", io.Information);
    }
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    /* Test the overlapped case. */

    file = CreateFileA("\\\\.\\WineTestDriver", FILE_ALL_ACCESS,
            0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device, error %lu\n", GetLastError());
    port = CreateIoCompletionPort(file, NULL, 123, 0);
    ok(port != NULL, "failed to create port, error %lu\n", GetLastError());

    ret = WaitForSingleObject(file, 0);
    ok(!ret, "got %d\n", ret);

    ResetEvent(event);
    strcpy(buffer, "abcdef");
    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    ret = NtDeviceIoControlFile(file, event, NULL, (void *)456, &io,
            ioctl, params, sizeof(*params), buffer, sizeof(buffer));
    ok(ret == params->ret_status
            || (NT_WARNING(params->ret_status) && ret == STATUS_PENDING), /* newer win10/11 */
            "got %#x\n", ret);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
        ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(event, 0);
        ok(ret == WAIT_TIMEOUT, "got %d\n", ret);
    }
    else
    {
        ok(io.Status == params->iosb_status, "got %#lx\n", io.Status);
        ok(io.Information == 3, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(event, 0);
        ok(!ret, "got %d\n", ret);
    }
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    ret = WaitForSingleObject(file, 0);
    ok(ret == WAIT_TIMEOUT, "got %d\n", ret);

    key = 0xdeadf00d;
    value = 0xdeadf00d;
    memset(&io, 0xcc, sizeof(io));
    ret = NtRemoveIoCompletion(port, &key, &value, &io, &zero);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(ret == STATUS_TIMEOUT, "got %#x\n", ret);
    }
    else
    {
        ok(!ret, "got %#x\n", ret);
        ok(key == 123, "got key %Iu\n", key);
        ok(value == 456, "got value %Iu\n", value);
        ok(io.Status == params->iosb_status, "got iosb status %#lx\n", io.Status);
        ok(io.Information == 3, "got information %Iu\n", io.Information);
    }

    /* As above, but set the event first, to show that the event is always
     * reset. */
    ResetEvent(event);
    strcpy(buffer, "abcdef");
    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    ret = NtDeviceIoControlFile(file, event, NULL, NULL, &io,
            ioctl, params, sizeof(*params), buffer, sizeof(buffer));
    ok(ret == params->ret_status
            || (NT_WARNING(params->ret_status) && ret == STATUS_PENDING), /* newer win10/11 */
            "got %#x\n", ret);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
        ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(event, 0);
        ok(ret == WAIT_TIMEOUT, "got %d\n", ret);
    }
    else
    {
        ok(io.Status == params->iosb_status, "got %#lx\n", io.Status);
        ok(io.Information == 3, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(event, 0);
        ok(!ret, "got %d\n", ret);
    }
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    /* As above, but use the file handle instead of an event. */
    ret = WaitForSingleObject(file, 0);
    ok(ret == WAIT_TIMEOUT, "got %d\n", ret);

    strcpy(buffer, "abcdef");
    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    ret = NtDeviceIoControlFile(file, NULL, NULL, NULL, &io,
            ioctl, params, sizeof(*params), buffer, sizeof(buffer));
    ok(ret == params->ret_status
            || (NT_WARNING(params->ret_status) && ret == STATUS_PENDING), /* newer win10/11 */
            "got %#x\n", ret);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
        ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(file, 0);
        ok(ret == WAIT_TIMEOUT, "got %d\n", ret);
    }
    else
    {
        ok(io.Status == params->iosb_status, "got %#lx\n", io.Status);
        ok(io.Information == 3, "got size %Iu\n", io.Information);
        ret = WaitForSingleObject(file, 0);
        ok(!ret, "got %d\n", ret);
    }
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    /* Test FILE_SKIP_COMPLETION_PORT_ON_SUCCESS. */

    if (pSetFileCompletionNotificationModes)
    {
        ret = pSetFileCompletionNotificationModes(file, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
        ok(ret, "got error %lu\n", GetLastError());

        SetEvent(event);
        strcpy(buffer, "abcdef");
        io.Status = 0xdeadf00d;
        io.Information = 0xdeadf00d;
        ret = NtDeviceIoControlFile(file, event, NULL, (void *)456, &io,
                ioctl, params, sizeof(*params), buffer, sizeof(buffer));
        ok(ret == params->ret_status
                || (NT_WARNING(params->ret_status) && ret == STATUS_PENDING), /* newer win10/11 */
                "got %#x\n", ret);
        if (!params->pending && NT_ERROR(params->iosb_status))
        {
            ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
            ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
            ret = WaitForSingleObject(event, 0);
            ok(ret == WAIT_TIMEOUT, "got %d\n", ret);
        }
        else
        {
            ok(io.Status == params->iosb_status, "got %#lx\n", io.Status);
            ok(io.Information == 3, "got size %Iu\n", io.Information);
            ret = WaitForSingleObject(event, 0);
            ok(!ret, "got %d\n", ret);
        }
        ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

        key = 0xdeadf00d;
        value = 0xdeadf00d;
        memset(&io, 0xcc, sizeof(io));
        ret = NtRemoveIoCompletion(port, &key, &value, &io, &zero);
        if (!params->pending)
        {
            /* Completion is skipped on non-pending NT_ERROR regardless of file
             * options. Windows < 8 interprets
             * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS to mean that !NT_ERROR
             * should also be skipped. Windows >= 8 restricts this to
             * NT_SUCCESS, which has the weird effect that non-pending
             * NT_WARNING does *not* skip completion. It's not clear whether
             * this is a bug or not—it looks like one, but on the other hand it
             * arguably follows the letter of the documentation more closely. */
            ok(ret == STATUS_TIMEOUT || (NT_WARNING(params->iosb_status) && !ret), "got %#x\n", ret);
        }
        else
        {
            ok(!ret, "got %#x\n", ret);
        }
        if (!ret)
        {
            ok(key == 123, "got key %Iu\n", key);
            ok(value == 456, "got value %Iu\n", value);
            ok(io.Status == params->iosb_status, "got iosb status %#lx\n", io.Status);
            ok(io.Information == 3, "got information %Iu\n", io.Information);
        }
    }

    ret = CloseHandle(file);
    ok(ret, "failed to close file, error %lu\n", GetLastError());
    ret = CloseHandle(port);
    ok(ret, "failed to close port, error %lu\n", GetLastError());

    /* Test with an APC. */

    got_return_status_apc = 0;

    file = CreateFileA("\\\\.\\WineTestDriver", FILE_ALL_ACCESS,
            0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device, error %lu\n", GetLastError());

    strcpy(buffer, "abcdef");
    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    ret = NtDeviceIoControlFile(file, NULL, return_status_apc, (void *)456, &io,
            ioctl, params, sizeof(*params), buffer, sizeof(buffer));
    ok(ret == params->ret_status, "got %#x\n", ret);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(io.Status == 0xdeadf00d, "got %#lx\n", io.Status);
        ok(io.Information == 0xdeadf00d, "got size %Iu\n", io.Information);
    }
    else
    {
        ok(io.Status == params->iosb_status, "got %#lx\n", io.Status);
        ok(io.Information == 3, "got size %Iu\n", io.Information);
    }
    ok(!strcmp(buffer, expect_buffer), "got buffer %s\n", buffer);

    ret = SleepEx(0, TRUE);
    if (!params->pending && NT_ERROR(params->iosb_status))
    {
        ok(!ret, "got %d\n", ret);
        ok(!got_return_status_apc, "got %u APC calls\n", got_return_status_apc);
    }
    else
    {
        ok(ret == WAIT_IO_COMPLETION, "got %d\n", ret);
        ok(got_return_status_apc == 1, "got %u APC calls\n", got_return_status_apc);
    }

    ret = CloseHandle(file);
    ok(ret, "failed to close file, error %lu\n", GetLastError());

    CloseHandle(event);
}

static void test_return_status(void)
{
    struct return_status_params params;
    unsigned int i, j, k;

    static const ULONG method_tests[] =
    {
        IOCTL_WINETEST_RETURN_STATUS_BUFFERED,
        IOCTL_WINETEST_RETURN_STATUS_DIRECT,
        IOCTL_WINETEST_RETURN_STATUS_NEITHER,
    };

    static const NTSTATUS status_tests[] =
    {
        STATUS_SUCCESS,
        STATUS_PENDING,
        STATUS_TIMEOUT,
        0x0eadbeef,
        0x4eadbeef,
        STATUS_BUFFER_OVERFLOW,
        0x8eadbeef,
        STATUS_NOT_IMPLEMENTED,
        0xceadbeef,
    };

    for (i = 0; i < ARRAY_SIZE(status_tests); ++i)
    {
        for (j = 0; j < ARRAY_SIZE(status_tests); ++j)
        {
            for (params.pending = 0; params.pending <= 1; ++params.pending)
            {
                for (k = 0; k < ARRAY_SIZE(method_tests); ++k)
                {
                    params.ret_status = status_tests[i];
                    params.iosb_status = status_tests[j];

                    winetest_push_context("return 0x%08lx, iosb 0x%08lx, pending %d, method %lu",
                            params.ret_status, params.iosb_status, params.pending, method_tests[k] & 3);

                    do_return_status(method_tests[k], &params);

                    winetest_pop_context();
                }
            }
        }
    }
}

static BOOL compare_unicode_string(const WCHAR *buffer, ULONG len, const WCHAR *expect)
{
    return len == wcslen(expect) * sizeof(WCHAR) && !memcmp(buffer, expect, len);
}

static void test_object_info(void)
{
    char buffer[200];
    OBJECT_NAME_INFORMATION *name_info = (OBJECT_NAME_INFORMATION *)buffer;
    OBJECT_TYPE_INFORMATION *type_info = (OBJECT_TYPE_INFORMATION *)buffer;
    FILE_FS_VOLUME_INFORMATION *volume_info = (FILE_FS_VOLUME_INFORMATION *)buffer;
    FILE_NAME_INFORMATION *file_info = (FILE_NAME_INFORMATION *)buffer;
    HANDLE file;
    NTSTATUS status;
    IO_STATUS_BLOCK io;
    ULONG size;

    status = NtQueryObject(device, ObjectNameInformation, buffer, sizeof(buffer), NULL);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(name_info->Name.Buffer, name_info->Name.Length, L"\\Device\\WineTestDriver"),
            "wrong name %s\n", debugstr_w(name_info->Name.Buffer));

    status = NtQueryObject(device, ObjectTypeInformation, buffer, sizeof(buffer), NULL);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(type_info->TypeName.Buffer, type_info->TypeName.Length, L"File"),
            "wrong name %s\n", debugstr_wn(type_info->TypeName.Buffer, type_info->TypeName.Length / sizeof(WCHAR)));

    status = NtQueryInformationFile(device, &io, buffer, sizeof(buffer), FileNameInformation);
    todo_wine ok(status == STATUS_INVALID_DEVICE_REQUEST, "got %#lx\n", status);

    status = NtQueryVolumeInformationFile(device, &io, buffer, sizeof(buffer), FileFsVolumeInformation);
    todo_wine ok(status == STATUS_INVALID_DEVICE_REQUEST, "got %#lx\n", status);

    file = CreateFileA("\\\\.\\WineTestDriver\\subfile", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    todo_wine ok(file != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());
    if (file == INVALID_HANDLE_VALUE) return;

    memset(buffer, 0xcc, sizeof(buffer));
    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(buffer), &size);
    ok(!status, "got %#lx\n", status);
    ok(size == sizeof(*name_info) + sizeof(L"\\Device\\WineTestDriver\\subfile"), "wrong size %lu\n", size);
    ok(compare_unicode_string(name_info->Name.Buffer, name_info->Name.Length, L"\\Device\\WineTestDriver\\subfile"),
            "wrong name %s\n", debugstr_w(name_info->Name.Buffer));

    memset(buffer, 0xcc, sizeof(buffer));
    status = NtQueryObject(file, ObjectNameInformation, buffer, size - 2, &size);
    ok(status == STATUS_BUFFER_OVERFLOW, "got %#lx\n", status);
    ok(size == sizeof(*name_info) + sizeof(L"\\Device\\WineTestDriver\\subfile"), "wrong size %lu\n", size);
    ok(compare_unicode_string(name_info->Name.Buffer, name_info->Name.Length, L"\\Device\\WineTestDriver\\subfil"),
            "wrong name %s\n", debugstr_w(name_info->Name.Buffer));

    memset(buffer, 0xcc, sizeof(buffer));
    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(*name_info), &size);
    ok(status == STATUS_BUFFER_OVERFLOW, "got %#lx\n", status);
    ok(size == sizeof(*name_info) + sizeof(L"\\Device\\WineTestDriver\\subfile"), "wrong size %lu\n", size);

    status = NtQueryObject(file, ObjectTypeInformation, buffer, sizeof(buffer), NULL);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(type_info->TypeName.Buffer, type_info->TypeName.Length, L"File"),
            "wrong name %s\n", debugstr_wn(type_info->TypeName.Buffer, type_info->TypeName.Length / sizeof(WCHAR)));

    status = NtQueryInformationFile(file, &io, buffer, sizeof(buffer), FileNameInformation);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(file_info->FileName, file_info->FileNameLength, L"\\subfile"),
            "wrong name %s\n", debugstr_wn(file_info->FileName, file_info->FileNameLength / sizeof(WCHAR)));

    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsVolumeInformation);
    ok(!status, "got %#lx\n", status);
    ok(!io.Status, "got status %#lx\n", io.Status);
    size = offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + volume_info->VolumeLabelLength;
    ok(io.Information == size, "expected information %lu, got %Iu\n", size, io.Information);
    ok(volume_info->VolumeSerialNumber == 0xdeadbeef,
            "wrong serial number 0x%08lx\n", volume_info->VolumeSerialNumber);
    ok(compare_unicode_string(volume_info->VolumeLabel, volume_info->VolumeLabelLength, L"WineTestDriver"),
            "wrong name %s\n", debugstr_wn(volume_info->VolumeLabel, volume_info->VolumeLabelLength / sizeof(WCHAR)));

    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsAttributeInformation);
    ok(status == STATUS_NOT_IMPLEMENTED, "got %#lx\n", status);
    ok(io.Status == 0xdeadf00d, "got status %#lx\n", io.Status);
    ok(io.Information == 0xdeadf00d, "got information %Iu\n", io.Information);

    CloseHandle(file);

    file = CreateFileA("\\\\.\\WineTestDriver\\notimpl", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());

    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(buffer), NULL);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(name_info->Name.Buffer, name_info->Name.Length, L"\\Device\\WineTestDriver"),
            "wrong name %s\n", debugstr_w(name_info->Name.Buffer));

    status = NtQueryInformationFile(file, &io, buffer, sizeof(buffer), FileNameInformation);
    ok(status == STATUS_NOT_IMPLEMENTED, "got %#lx\n", status);

    CloseHandle(file);

    file = CreateFileA("\\\\.\\WineTestDriver\\badparam", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());

    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(buffer), NULL);
    ok(!status, "got %#lx\n", status);
    ok(compare_unicode_string(name_info->Name.Buffer, name_info->Name.Length, L"\\Device\\WineTestDriver"),
            "wrong name %s\n", debugstr_w(name_info->Name.Buffer));

    status = NtQueryInformationFile(file, &io, buffer, sizeof(buffer), FileNameInformation);
    ok(status == STATUS_INVALID_PARAMETER, "got %#lx\n", status);

    CloseHandle(file);

    file = CreateFileA("\\\\.\\WineTestDriver\\genfail", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());

    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(buffer), NULL);
    ok(status == STATUS_UNSUCCESSFUL, "got %#lx\n", status);

    status = NtQueryInformationFile(file, &io, buffer, sizeof(buffer), FileNameInformation);
    ok(status == STATUS_UNSUCCESSFUL, "got %#lx\n", status);

    CloseHandle(file);

    file = CreateFileA("\\\\.\\WineTestDriver\\badtype", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());

    status = NtQueryObject(file, ObjectNameInformation, buffer, sizeof(buffer), NULL);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "got %#lx\n", status);

    status = NtQueryInformationFile(file, &io, buffer, sizeof(buffer), FileNameInformation);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "got %#lx\n", status);

    CloseHandle(file);
}

static void test_blocking_irp(void)
{
    char buffer[40];
    IO_STATUS_BLOCK io;
    NTSTATUS status;
    HANDLE file;

    file = CreateFileA("\\\\.\\WineTestDriver\\", FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    memset(&io, 0xcc, sizeof(io));
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsSizeInformation);
    ok(!status, "got %#lx\n", status);
    ok(!io.Status, "got iosb status %#lx\n", io.Status);
    ok(!io.Information, "got information %#Ix\n", io.Information);

    io.Status = 0xdeadf00d;
    io.Information = 0xdeadf00d;
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsFullSizeInformation);
    ok(status == STATUS_DEVICE_NOT_READY, "got %#lx\n", status);
    todo_wine ok(io.Status == STATUS_DEVICE_NOT_READY || broken(io.Status == 0xdeadf00d), /* older win10 */
            "got iosb status %#lx\n", io.Status);
    todo_wine ok(io.Information == 0 || broken(io.Information == 0xdeadf00d), /* older win10 */
            "got information %#Ix\n", io.Information);

    CloseHandle(file);

    file = CreateFileA("\\\\.\\WineTestDriver\\", FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    memset(&io, 0xcc, sizeof(io));
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsSizeInformation);
    ok(!status, "got %#lx\n", status);
    ok(!io.Status, "got iosb status %#lx\n", io.Status);
    ok(!io.Information, "got information %#Ix\n", io.Information);

    memset(&io, 0xcc, sizeof(io));
    status = NtQueryVolumeInformationFile(file, &io, buffer, sizeof(buffer), FileFsFullSizeInformation);
    ok(status == STATUS_DEVICE_NOT_READY, "got %#lx\n", status);
    ok(io.Status == STATUS_DEVICE_NOT_READY, "got iosb status %#lx\n", io.Status);
    ok(!io.Information, "got information %#Ix\n", io.Information);

    CloseHandle(file);
}

static void test_driver3(struct testsign_context *ctx)
{
    WCHAR filename[MAX_PATH];
    SC_HANDLE service;
    BOOL ret;

    service = load_driver(ctx, filename, L"driver3.dll", L"WineTestDriver3");
    ok(service != NULL, "driver3 failed to load\n");

    ret = StartServiceA(service, 0, NULL);
    ok(!ret, "driver3 should fail to start\n");
    ok(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED ||
       GetLastError() == ERROR_INVALID_FUNCTION ||
       GetLastError() == ERROR_PROC_NOT_FOUND /* XP */ ||
       GetLastError() == ERROR_FILE_NOT_FOUND /* Win7 */, "got %lu\n", GetLastError());

    DeleteService(service);
    CloseServiceHandle(service);
    DeleteFileW(filename);
}

static DWORD WINAPI wsk_test_thread(void *parameter)
{
    static const char test_send_string[] = "Client test string 1.";
    static const WORD version = MAKEWORD(2, 2);
    SOCKET s_listen, s_accept, s_connect;
    struct sockaddr_in addr;
    char buffer[256];
    int ret, err;
    WSADATA data;
    int opt_val;

    ret = WSAStartup(version, &data);
    ok(!ret, "WSAStartup() failed, ret %u.\n", ret);

    s_connect = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s_connect != INVALID_SOCKET, "Error creating socket, WSAGetLastError() %u.\n", WSAGetLastError());

    s_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s_listen != INVALID_SOCKET, "Error creating socket, WSAGetLastError() %u.\n", WSAGetLastError());

    opt_val = 1;
    setsockopt(s_listen, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt_val, sizeof(opt_val));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CLIENT_LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(0x7f000001);
    ret = bind(s_listen, (struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "Got unexpected ret %d, WSAGetLastError() %u.\n", ret, WSAGetLastError());

    ret = listen(s_listen, SOMAXCONN);
    ok(!ret, "Got unexpected ret %d, WSAGetLastError() %u.\n", ret, WSAGetLastError());

    addr.sin_port = htons(SERVER_LISTEN_PORT);

    ret = connect(s_connect, (struct sockaddr *)&addr, sizeof(addr));
    while (ret && ((err = WSAGetLastError()) == WSAECONNREFUSED || err == WSAECONNABORTED))
    {
        SwitchToThread();
        ret = connect(s_connect, (struct sockaddr *)&addr, sizeof(addr));
    }
    ok(!ret, "Error connecting, WSAGetLastError() %u.\n", WSAGetLastError());

    ret = send(s_connect, test_send_string, sizeof(test_send_string), 0);
    ok(ret == sizeof(test_send_string), "Got unexpected ret %d.\n", ret);

    ret = recv(s_connect, buffer, sizeof(buffer), 0);
    ok(ret == sizeof(buffer), "Got unexpected ret %d.\n", ret);
    ok(!strcmp(buffer, "Server test string 1."), "Received unexpected data.\n");

    s_accept = accept(s_listen, NULL, NULL);
    ok(s_accept != INVALID_SOCKET, "Error creating socket, WSAGetLastError() %u.\n", WSAGetLastError());

    closesocket(s_accept);
    closesocket(s_connect);
    closesocket(s_listen);
    return TRUE;
}

static void test_driver_netio(struct testsign_context *ctx)
{
    WCHAR filename[MAX_PATH];
    SC_HANDLE service;
    HANDLE hthread;
    BOOL ret;

    if (!(service = load_driver(ctx, filename, L"driver_netio.dll", L"winetest_netio")))
        return;

    if (!start_driver(service, TRUE))
    {
        DeleteFileW(filename);
        return;
    }

    device = CreateFileA("\\\\.\\winetest_netio", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(device != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    hthread = CreateThread(NULL, 0, wsk_test_thread, NULL, 0, NULL);
    main_test();
    WaitForSingleObject(hthread, INFINITE);
    CloseHandle(hthread);

    CloseHandle(device);

    unload_driver(service);
    ret = DeleteFileW(filename);
    ok(ret, "DeleteFile failed: %lu\n", GetLastError());

    cat_okfile();
}

#ifdef __i386__
#define EXT "x86"
#elif defined(__x86_64__)
#define EXT "amd64"
#elif defined(__arm__)
#define EXT "arm"
#elif defined(__aarch64__)
#define EXT "arm64"
#else
#define EXT
#endif

static const char inf_text[] =
    "[Version]\n"
    "Signature=$Chicago$\n"
    "ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\n"
    "CatalogFile=winetest.cat\n"
    "DriverVer=09/21/2006,6.0.5736.1\n"

    "[Manufacturer]\n"
    "Wine=mfg_section,NT" EXT "\n"

    "[mfg_section.NT" EXT "]\n"
    "Wine test root driver=device_section,test_hardware_id\n"

    "[device_section.NT" EXT "]\n"
    "CopyFiles=file_section\n"

    "[device_section.NT" EXT ".Services]\n"
    "AddService=winetest,0x2,svc_section\n"

    "[file_section]\n"
    "winetest.sys\n"

    "[SourceDisksFiles]\n"
    "winetest.sys=1\n"

    "[SourceDisksNames]\n"
    "1=,winetest.sys\n"

    "[DestinationDirs]\n"
    "DefaultDestDir=12\n"

    "[svc_section]\n"
    "ServiceBinary=%12%\\winetest.sys\n"
    "ServiceType=1\n"
    "StartType=3\n"
    "ErrorControl=1\n"
    "LoadOrderGroup=Extended Base\n"
    "DisplayName=\"winetest bus driver\"\n"
    "; they don't sleep anymore, on the beach\n";

static void add_file_to_catalog(HANDLE catalog, const WCHAR *file)
{
    SIP_SUBJECTINFO subject_info = {sizeof(SIP_SUBJECTINFO)};
    SIP_INDIRECT_DATA *indirect_data;
    CRYPTCATMEMBER *member;
    WCHAR hash_buffer[100];
    GUID subject_guid;
    unsigned int i;
    DWORD size;
    BOOL ret;

    ret = CryptSIPRetrieveSubjectGuidForCatalogFile(file, NULL, &subject_guid);
    todo_wine ok(ret, "Failed to get subject guid, error %lu\n", GetLastError());

    size = 0;
    subject_info.pgSubjectType = &subject_guid;
    subject_info.pwsFileName = file;
    subject_info.DigestAlgorithm.pszObjId = (char *)szOID_OIWSEC_sha1;
    ret = CryptSIPCreateIndirectData(&subject_info, &size, NULL);
    todo_wine ok(ret, "Failed to get indirect data size, error %lu\n", GetLastError());

    indirect_data = malloc(size);
    ret = CryptSIPCreateIndirectData(&subject_info, &size, indirect_data);
    todo_wine ok(ret, "Failed to get indirect data, error %lu\n", GetLastError());
    if (ret)
    {
        memset(hash_buffer, 0, sizeof(hash_buffer));
        for (i = 0; i < indirect_data->Digest.cbData; ++i)
            swprintf(&hash_buffer[i * 2], 2, L"%02X", indirect_data->Digest.pbData[i]);

        member = CryptCATPutMemberInfo(catalog, (WCHAR *)file,
                hash_buffer, &subject_guid, 0, size, (BYTE *)indirect_data);
        ok(!!member, "Failed to write member, error %lu\n", GetLastError());
    }

    free(indirect_data);
}

static const GUID bus_class     = {0xdeadbeef, 0x29ef, 0x4538, {0xa5, 0xfd, 0xb6, 0x95, 0x73, 0xa3, 0x62, 0xc1}};
static const GUID child_class   = {0xdeadbeef, 0x29ef, 0x4538, {0xa5, 0xfd, 0xb6, 0x95, 0x73, 0xa3, 0x62, 0xc2}};

static unsigned int got_bus_arrival, got_bus_removal, got_child_arrival, got_child_removal;

static LRESULT WINAPI device_notify_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message != WM_DEVICECHANGE)
        return DefWindowProcA(window, message, wparam, lparam);

    switch (wparam)
    {
        case DBT_DEVNODES_CHANGED:
            if (winetest_debug > 1) trace("device nodes changed\n");

            ok(InSendMessageEx(NULL) == ISMEX_NOTIFY, "got message flags %#lx\n", InSendMessageEx(NULL));
            ok(!lparam, "got lparam %#Ix\n", lparam);
            break;

        case DBT_DEVICEARRIVAL:
        {
            const DEV_BROADCAST_DEVICEINTERFACE_A *iface = (const DEV_BROADCAST_DEVICEINTERFACE_A *)lparam;
            DWORD expect_size = offsetof(DEV_BROADCAST_DEVICEINTERFACE_A, dbcc_name[strlen(iface->dbcc_name)]);

            if (winetest_debug > 1) trace("device arrival %s\n", iface->dbcc_name);

            ok(InSendMessageEx(NULL) == ISMEX_SEND, "got message flags %#lx\n", InSendMessageEx(NULL));

            ok(iface->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE,
                    "got unexpected notification type %#lx\n", iface->dbcc_devicetype);
            ok(iface->dbcc_size >= expect_size, "expected size at least %lu, got %lu\n", expect_size, iface->dbcc_size);
            ok(!iface->dbcc_reserved, "got reserved %#lx\n", iface->dbcc_reserved);
            if (IsEqualGUID(&iface->dbcc_classguid, &bus_class))
            {
                ++got_bus_arrival;
                ok(!strcmp(iface->dbcc_name, "\\\\?\\ROOT#WINETEST#0#{deadbeef-29ef-4538-a5fd-b69573a362c1}"),
                        "got name %s\n", debugstr_a(iface->dbcc_name));
            }
            else if (IsEqualGUID(&iface->dbcc_classguid, &child_class))
            {
                ++got_child_arrival;
                ok(!strcmp(iface->dbcc_name, "\\\\?\\Wine#Test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"),
                        "got name %s\n", debugstr_a(iface->dbcc_name));
            }
            break;
        }

        case DBT_DEVICEREMOVECOMPLETE:
        {
            const DEV_BROADCAST_DEVICEINTERFACE_A *iface = (const DEV_BROADCAST_DEVICEINTERFACE_A *)lparam;
            DWORD expect_size = offsetof(DEV_BROADCAST_DEVICEINTERFACE_A, dbcc_name[strlen(iface->dbcc_name)]);

            if (winetest_debug > 1) trace("device removal %s\n", iface->dbcc_name);

            ok(InSendMessageEx(NULL) == ISMEX_SEND, "got message flags %#lx\n", InSendMessageEx(NULL));

            ok(iface->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE,
                    "got unexpected notification type %#lx\n", iface->dbcc_devicetype);
            ok(iface->dbcc_size >= expect_size, "expected size at least %lu, got %lu\n", expect_size, iface->dbcc_size);
            ok(!iface->dbcc_reserved, "got reserved %#lx\n", iface->dbcc_reserved);
            if (IsEqualGUID(&iface->dbcc_classguid, &bus_class))
            {
                ++got_bus_removal;
                ok(!strcmp(iface->dbcc_name, "\\\\?\\ROOT#WINETEST#0#{deadbeef-29ef-4538-a5fd-b69573a362c1}"),
                        "got name %s\n", debugstr_a(iface->dbcc_name));
            }
            else if (IsEqualGUID(&iface->dbcc_classguid, &child_class))
            {
                ++got_child_removal;
                ok(!strcmp(iface->dbcc_name, "\\\\?\\Wine#Test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"),
                        "got name %s\n", debugstr_a(iface->dbcc_name));
            }
            break;
        }
    }
    return DefWindowProcA(window, message, wparam, lparam);
}

static void pump_messages(void)
{
    MSG msg;

    if (!MsgWaitForMultipleObjects(0, NULL, FALSE, 200, QS_ALLINPUT))
    {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}

struct devquery_callback_data
{
    HANDLE enum_completed_evt;
    BOOL initial_enum_completed;

    HANDLE device_added_sem;
    DWORD bus_dev_added;
    DWORD child_dev_added;

    HANDLE device_removed_sem;
    DWORD bus_dev_removed;
    DWORD child_dev_removed;
};

static const char *debugstr_DEV_OBJECT_TYPE(DEV_OBJECT_TYPE type)
{
    static const char *str[] = {
        "DevObjectTypeUnknown",
        "DevObjectTypeDeviceInterface",
        "DevObjectTypeDeviceContainer",
        "DevObjectTypeDevice",
        "DevObjectTypeDeviceInterfaceClass",
        "DevObjectTypeAEP",
        "DevObjectTypeAEPContainer",
        "DevObjectTypeDeviceInstallerClass",
        "DevObjectTypeDeviceInterfaceDisplay",
        "DevObjectTypeDeviceContainerDisplay",
        "DevObjectTypeAEPService",
        "DevObjectTypeDevicePanel",
        "DevObjectTypeAEPProtocol",
    };
    if (type >= ARRAY_SIZE(str))
        return wine_dbg_sprintf("(unknown %d)", type);
    return wine_dbg_sprintf("%s", str[type]);
}

static const char *debugstr_DEV_QUERY_RESULT_ACTION_DATA(const DEV_QUERY_RESULT_ACTION_DATA *action_data)
{
    if (!action_data) return wine_dbg_sprintf("(null)");
    switch (action_data->Action)
    {
    case DevQueryResultStateChange:
    {
        static const char *str[] = {
            "DevQueryStateInitialized",
            "DevQueryStateEnumCompleted",
            "DevQueryStateAborted",
            "DevQueryStateClosed"
        };

        if (action_data->Data.State >= ARRAY_SIZE(str))
            return wine_dbg_sprintf("{ DevQueryResultStateChange { (unknown %d) } }", action_data->Data.State);
        return wine_dbg_sprintf("{ DevQueryResultStateChange { %s } }", str[action_data->Data.State]);
    }
    case DevQueryResultAdd:
    case DevQueryResultUpdate:
    case DevQueryResultRemove:
    {
        const DEV_OBJECT *obj = &action_data->Data.DeviceObject;
        static const char *str[] = {
            "DevQueryResultAdd",
            "DevQueryResultUpdate",
            "DevQueryResultRemove",
        };

        return wine_dbg_sprintf("{ %s { %s %s %lu %p } }", str[action_data->Action - 1],
                                debugstr_DEV_OBJECT_TYPE(obj->ObjectType), debugstr_w(obj->pszObjectId),
                                obj->cPropertyCount, obj->pProperties);
    }
    default:
        return wine_dbg_sprintf("{ (unknown %d) }", action_data->Action);
    }
}

static void CALLBACK devquery_notify_callback(HDEVQUERY devquery, void *user_data,
                                              const DEV_QUERY_RESULT_ACTION_DATA *action_data)
{
    struct devquery_callback_data *data = user_data;

    switch (action_data->Action)
    {
    case DevQueryResultStateChange:
        if (winetest_debug > 1)
            trace("%s\n", debugstr_DEV_QUERY_RESULT_ACTION_DATA(action_data));

        if (action_data->Data.State == DevQueryStateEnumCompleted)
        {
            data->initial_enum_completed = TRUE;
            SetEvent(data->enum_completed_evt);
        }
        break;
    case DevQueryResultAdd:
    {
        const DEV_OBJECT *obj = &action_data->Data.DeviceObject;
        DEVPROP_BOOLEAN state = DEVPROP_FALSE;
        GUID iface_guid = {0};
        ULONG i;

        if (!data->initial_enum_completed)
            break;
        if (winetest_debug > 1)
            trace("%s\n", debugstr_DEV_QUERY_RESULT_ACTION_DATA(action_data));
        if (obj->ObjectType != DevObjectTypeDeviceInterfaceDisplay)
            break;
        ok(obj->cPropertyCount == 2, "got cPropertyCount %lu\n", obj->cPropertyCount);
        ok(!!obj->pProperties, "got pProperties %p\n", obj->pProperties);
        if (!obj->pProperties)
            return;
        for (i = 0; i < obj->cPropertyCount; i++)
        {
            const DEVPROPERTY *prop = &obj->pProperties[i];
            if (IsEqualDevPropKey(prop->CompKey.Key, DEVPKEY_DeviceInterface_ClassGuid))
            {
                ok(prop->Type == DEVPROP_TYPE_GUID, "got Type %#lx != %#x\n", prop->Type, DEVPROP_TYPE_GUID);
                ok(prop->BufferSize == sizeof(GUID), "got BufferSize %lu != %Iu\n", prop->BufferSize, sizeof(GUID));
                if (prop->BufferSize == sizeof(GUID) && prop->Type == DEVPROP_TYPE_GUID)
                    iface_guid = *(GUID *)prop->Buffer;
            }
            else if (IsEqualDevPropKey(prop->CompKey.Key, DEVPKEY_DeviceInterface_Enabled))
            {
                ok(prop->Type == DEVPROP_TYPE_BOOLEAN, "got Type %#lx != %#x\n", prop->Type, DEVPROP_TYPE_BOOLEAN);
                ok(prop->BufferSize == sizeof(DEVPROP_BOOLEAN), "got BufferSize %lu != %Iu\n", prop->BufferSize,
                   sizeof(DEVPROP_BOOLEAN));
                if (prop->BufferSize == sizeof(DEVPROP_BOOLEAN) && prop->Type == DEVPROP_TYPE_BOOLEAN)
                    state = *(DEVPROP_BOOLEAN *)prop->Buffer;
            }
        }

        ok(IsEqualGUID(&iface_guid, &bus_class) || IsEqualGUID(&iface_guid, &child_class), "got iface_guid %s\n",
           debugstr_guid(&iface_guid));
        if (IsEqualGUID(&iface_guid, &bus_class) && state)
        {
            data->bus_dev_added++;
            ok(!wcsicmp(obj->pszObjectId, L"\\\\?\\ROOT#WINETEST#0#{deadbeef-29ef-4538-a5fd-b69573a362c1}"),
                "got pszObjectId %s\n", debugstr_w(obj->pszObjectId));
            ReleaseSemaphore(data->device_added_sem, 1, NULL);
        }
        else if (IsEqualGUID(&iface_guid, &child_class) && state)
        {
            data->child_dev_added++;
            ok(!wcsicmp(obj->pszObjectId, L"\\\\?\\Wine#Test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"),
                "got pszObjectId %s\n", debugstr_w(obj->pszObjectId));
            ReleaseSemaphore(data->device_added_sem, 1, NULL);
        }
        break;
    }
    case DevQueryResultUpdate:
    {
        const DEV_OBJECT *obj = &action_data->Data.DeviceObject;
        const DEVPROPERTY *prop = &obj->pProperties[0];

        if (!data->initial_enum_completed)
            break;
        if (winetest_debug > 1)
            trace("%s\n", debugstr_DEV_QUERY_RESULT_ACTION_DATA(action_data));
        if (obj->ObjectType != DevObjectTypeDeviceInterfaceDisplay)
            break;
        ok(!wcsicmp(obj->pszObjectId, L"\\\\?\\ROOT#WINETEST#0#{deadbeef-29ef-4538-a5fd-b69573a362c1}") ||
                !wcsicmp(obj->pszObjectId, L"\\\\?\\Wine#Test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"),
            "got pszObjectId %s\n", debugstr_w(obj->pszObjectId));
        ok(obj->cPropertyCount == 1, "got cPropertyCount %lu\n", obj->cPropertyCount);
        ok(!!obj->pProperties, "got pProperties %p\n", obj->pProperties);
        if (!obj->pProperties)
            return;
        ok(IsEqualDevPropKey(prop->CompKey.Key, DEVPKEY_DeviceInterface_Enabled), "got CompKey.Key {%s,%#lx}\n",
            debugstr_guid(&prop->CompKey.Key.fmtid), prop->CompKey.Key.pid);
        ok(prop->Type == DEVPROP_TYPE_BOOLEAN, "got Type %#lx != %#x\n", prop->Type, DEVPROP_TYPE_BOOLEAN);
        ok(prop->BufferSize == sizeof(DEVPROP_BOOLEAN), "got BufferSize %lu != %Iu\n", prop->BufferSize,
           sizeof(DEVPROP_BOOLEAN));
        if (prop->BufferSize == sizeof(DEVPROP_BOOLEAN) && prop->Type == DEVPROP_TYPE_BOOLEAN &&
            !*(DEVPROP_BOOLEAN *)prop->Buffer)
        {
            if (!wcsicmp(obj->pszObjectId, L"\\\\?\\ROOT#WINETEST#0#{deadbeef-29ef-4538-a5fd-b69573a362c1}"))
                data->bus_dev_removed++;
            else if (!wcsicmp(obj->pszObjectId, L"\\\\?\\Wine#Test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"))
                data->child_dev_removed++;
            ReleaseSemaphore(data->device_removed_sem, 1, NULL);
        }
        break;
    }
    default:
        break;
    }
}

static void test_pnp_devices(void)
{
    static const GUID expect_container_id_guid = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x91, 0x23}};
    static const char expect_hardware_id[] = "winetest_hardware\0winetest_hardware_1\0";
    static const WCHAR expect_hardware_id_w[] = L"winetest_hardware\0winetest_hardware_1\0";
    static const char expect_compat_id[] = "winetest_compat\0winetest_compat_1\0";
    static const char expect_device_location[] = "WineTestDeviceLocation";
    static const WCHAR expect_device_location_w[] = L"WineTestDeviceLocation";
    static const WCHAR expect_device_bus_desc_w[] = L"WineTestDevice";
    static const WCHAR expect_compat_id_w[] = L"winetest_compat\0winetest_compat_1\0";
    static const WCHAR expect_container_id_w[] = L"{12345678-1234-1234-1234-123456789123}";
    static const char foobar[] = "foobar";
    static const char foo[] = "foo";
    static const char bar[] = "bar";

    char buffer[200];
    WCHAR buffer_w[200];
    GUID buffer_guid = {0};
    SP_DEVICE_INTERFACE_DETAIL_DATA_A *iface_detail = (void *)buffer;
    SP_DEVICE_INTERFACE_DATA iface = {sizeof(iface)};
    SP_DEVINFO_DATA device = {sizeof(device)};
    DEVPROP_BOOLEAN enabled = DEVPROP_FALSE;
    DEVPROPTYPE prop_type = DEVPROP_TYPE_EMPTY;
    DEV_BROADCAST_DEVICEINTERFACE_A filter =
    {
        .dbcc_size = sizeof(filter),
        .dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE,
    };
    static const WNDCLASSA class =
    {
        .lpszClassName = "ntoskrnl_test_wc",
        .lpfnWndProc = device_notify_proc,
    };
    struct devquery_callback_data devquery_data = {0};
    DEVPROPCOMPKEY iface_prop_keys[2] =
    {
        { DEVPKEY_DeviceInterface_ClassGuid, DEVPROP_STORE_SYSTEM, 0 },
        { DEVPKEY_DeviceInterface_Enabled, DEVPROP_STORE_SYSTEM, 0 }
    };
    HDEVNOTIFY notify_handle;
    DWORD size = 0, type, dword;
    HANDLE bus, child, tmp;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING string;
    OVERLAPPED ovl = {0};
    IO_STATUS_BLOCK io;
    HDEVQUERY query;
    HDEVINFO set;
    HWND window;
    LSTATUS status;
    HRESULT hr;
    HKEY key;
    BOOL ret, have_devquery = pDevCreateObjectQuery && pDevCloseObjectQuery;
    int id;

    ret = RegisterClassA(&class);
    ok(ret, "failed to register class\n");
    window = CreateWindowA("ntoskrnl_test_wc", NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    ok(!!window, "failed to create window\n");
    notify_handle = RegisterDeviceNotificationA(window, &filter, DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    ok(!!notify_handle, "failed to register window, error %lu\n", GetLastError());

    if (!have_devquery)
        win_skip("DevCreateObjectQuery, DevCloseObjectQuery unavailable.\n");

    if (have_devquery)
    {
        devquery_data.enum_completed_evt = CreateEventW(NULL, FALSE, FALSE, NULL);
        devquery_data.device_added_sem = CreateSemaphoreW(NULL, 0, 1, NULL);
        devquery_data.device_removed_sem = CreateSemaphoreW(NULL, 0, 1, NULL);
        hr = pDevCreateObjectQuery(DevObjectTypeDeviceInterfaceDisplay, DevQueryFlagUpdateResults, 2, iface_prop_keys, 0,
                                   NULL, devquery_notify_callback, &devquery_data, &query);
        ok(hr == S_OK, "Failed to create device query, hr %#lx\n", hr);
        status = WaitForSingleObject(devquery_data.enum_completed_evt, 5000);
        ok(!status, "WaitforSingleObject failed, error %lu\n", status);
    }

    set = SetupDiGetClassDevsA(&control_class, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());

    ret = SetupDiEnumDeviceInfo(set, 0, &device);
    ok(ret, "failed to get device, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&device.ClassGuid, &GUID_DEVCLASS_SYSTEM), "wrong class %s\n", debugstr_guid(&device.ClassGuid));

    ret = SetupDiGetDeviceInstanceIdA(set, &device, buffer, sizeof(buffer), NULL);
    ok(ret, "failed to get device ID, error %#lx\n", GetLastError());
    ok(!strcmp(buffer, "ROOT\\WINETEST\\0"), "got ID %s\n", debugstr_a(buffer));

    ret = SetupDiEnumDeviceInterfaces(set, NULL, &control_class, 0, &iface);
    ok(ret, "failed to get interface, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&iface.InterfaceClassGuid, &control_class),
            "wrong class %s\n", debugstr_guid(&iface.InterfaceClassGuid));
    ok(iface.Flags == SPINT_ACTIVE, "got flags %#lx\n", iface.Flags);

    iface_detail->cbSize = sizeof(*iface_detail);
    ret = SetupDiGetDeviceInterfaceDetailA(set, &iface, iface_detail, sizeof(buffer), NULL, NULL);
    ok(ret, "failed to get interface path, error %#lx\n", GetLastError());
    ok(!strcmp(iface_detail->DevicePath, "\\\\?\\root#winetest#0#{deadbeef-29ef-4538-a5fd-b69573a362c0}"),
            "wrong path %s\n", debugstr_a(iface_detail->DevicePath));

    ret = SetupDiGetDeviceInterfacePropertyW(set, &iface, &DEVPKEY_DeviceInterface_Enabled, &prop_type,
                                             (BYTE *)&enabled, sizeof(enabled), &size, 0);
    ok(ret, "failed to get device interface property, got error %lu\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_BOOLEAN, "got prop_type %#lx\n", prop_type);
    ok(size == sizeof(enabled), "got size %lu\n", size);
    ok(enabled == DEVPROP_TRUE, "got enabled %d\n", enabled);

    /* Create a device parameter for testing IoOpenDeviceRegistryKey */
    key = SetupDiCreateDevRegKeyA(set, &device, DICS_FLAG_GLOBAL, 0, DIREG_DEV, NULL, NULL);
    ok(key != INVALID_HANDLE_VALUE, "failed to create a hardware parameters key, got error %#lx\n", GetLastError());
    status = RegSetValueExA(key, foobar, 0, REG_SZ, (const BYTE *)foo, sizeof(foo));
    ok(status == ERROR_SUCCESS, "failed to save a device parameter, got error %lu\n", status);
    RegCloseKey(key);

    SetupDiDestroyDeviceInfoList(set);

    bus = CreateFileA(iface_detail->DevicePath, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(bus != INVALID_HANDLE_VALUE, "got error %lu\n", GetLastError());

    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_MAIN, NULL, 0, NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    /* Test IoRegisterDeviceInterface() and IoSetDeviceInterfaceState(). */

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got error %#lx\n", GetLastError());
    SetupDiDestroyDeviceInfoList(set);

    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_REGISTER_IFACE, NULL, 0, NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(ret, "failed to get interface, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&iface.InterfaceClassGuid, &bus_class),
            "wrong class %s\n", debugstr_guid(&iface.InterfaceClassGuid));
    ok(!iface.Flags, "got flags %#lx\n", iface.Flags);
    SetupDiDestroyDeviceInfoList(set);

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got error %#lx\n", GetLastError());
    SetupDiDestroyDeviceInfoList(set);

    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_ENABLE_IFACE, NULL, 0, NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    pump_messages();
    ok(got_bus_arrival == 1, "got %u bus arrival messages\n", got_bus_arrival);
    ok(!got_bus_removal, "got %u bus removal messages\n", got_bus_removal);
    if (have_devquery)
    {
        status = WaitForSingleObject(devquery_data.device_added_sem, 1000);
        ok(!status, "WaitForSingleObject failed, error %lu\n", status);
        ok(devquery_data.bus_dev_added == 1, "got %lu new bus device objects\n", devquery_data.bus_dev_added);
        ok(!devquery_data.bus_dev_removed, "got %lu bus device object removals\n", devquery_data.bus_dev_removed);
    }

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(ret, "failed to get interface, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&iface.InterfaceClassGuid, &bus_class),
            "wrong class %s\n", debugstr_guid(&iface.InterfaceClassGuid));
    ok(iface.Flags == SPINT_ACTIVE, "got flags %#lx\n", iface.Flags);
    SetupDiDestroyDeviceInfoList(set);

    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_DISABLE_IFACE, NULL, 0, NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    pump_messages();
    ok(got_bus_arrival == 1, "got %u bus arrival messages\n", got_bus_arrival);
    ok(got_bus_removal == 1, "got %u bus removal messages\n", got_bus_removal);
    if (have_devquery)
    {
        status = WaitForSingleObject(devquery_data.device_removed_sem, 1000);
        ok(!status, "WaitForSingleObject failed, error %lu\n", status);
        ok(devquery_data.bus_dev_added == 1, "got %lu new bus device objects\n", devquery_data.bus_dev_added);
        ok(devquery_data.bus_dev_removed == 1, "got %lu bus device object removals\n", devquery_data.bus_dev_removed);
    }

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(ret, "failed to get interface, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&iface.InterfaceClassGuid, &bus_class),
            "wrong class %s\n", debugstr_guid(&iface.InterfaceClassGuid));
    ok(!iface.Flags, "got flags %#lx\n", iface.Flags);
    SetupDiDestroyDeviceInfoList(set);

    set = SetupDiGetClassDevsA(&bus_class, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());
    ret = SetupDiEnumDeviceInterfaces(set, NULL, &bus_class, 0, &iface);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got error %#lx\n", GetLastError());
    SetupDiDestroyDeviceInfoList(set);

    /* Test exposing a child device. */

    id = 1;
    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_ADD_CHILD, &id, sizeof(id), NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    pump_messages();
    ok(got_child_arrival == 1, "got %u child arrival messages\n", got_child_arrival);
    ok(!got_child_removal, "got %u child removal messages\n", got_child_removal);
    if (have_devquery)
    {
        status = WaitForSingleObject(devquery_data.device_added_sem, 1000);
        ok(!status, "WaitForSingleObject failed, error %lu\n", status);
        ok(devquery_data.child_dev_added == 1, "got %lu new bus device objects\n", devquery_data.child_dev_added);
        ok(!devquery_data.child_dev_removed, "got %lu bus device object removals\n", devquery_data.child_dev_removed);
    }

    set = SetupDiGetClassDevsA(&child_class, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());

    ret = SetupDiEnumDeviceInfo(set, 0, &device);
    ok(ret, "failed to get device, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&device.ClassGuid, &GUID_NULL), "wrong class %s\n", debugstr_guid(&device.ClassGuid));

    ret = SetupDiGetDeviceInstanceIdA(set, &device, buffer, sizeof(buffer), NULL);
    ok(ret, "failed to get device ID, error %#lx\n", GetLastError());
    ok(!strcmp(buffer, "WINE\\TEST\\1"), "got ID %s\n", debugstr_a(buffer));

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_CAPABILITIES,
            &type, (BYTE *)&dword, sizeof(dword), NULL);
    todo_wine ok(ret, "got error %#lx\n", GetLastError());
    if (ret)
    {
        ok(dword == (CM_DEVCAP_EJECTSUPPORTED | CM_DEVCAP_UNIQUEID
                | CM_DEVCAP_RAWDEVICEOK | CM_DEVCAP_SURPRISEREMOVALOK), "got flags %#lx\n", dword);
        ok(type == REG_DWORD, "got type %lu\n", type);
    }

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_CLASSGUID,
            &type, (BYTE *)buffer, sizeof(buffer), NULL);
    todo_wine ok(!ret, "expected failure\n");
    if (ret)
        ok(GetLastError() == ERROR_INVALID_DATA, "got error %#lx\n", GetLastError());

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_CONFIGFLAGS,
            &type, (BYTE *)&dword, sizeof(dword), NULL);
    ok(ret, "got error %#lx\n", GetLastError());
    /* windows 7 sets CONFIGFLAG_FINISH_INSTALL; it's not clear what this means */
    ok(!(dword & ~CONFIGFLAG_FINISH_INSTALL), "got flags %#lx\n", dword);
    ok(type == REG_DWORD, "got type %lu\n", type);

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_DEVTYPE,
            &type, (BYTE *)&dword, sizeof(dword), NULL);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_INVALID_DATA, "got error %#lx\n", GetLastError());

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_DRIVER,
            &type, (BYTE *)buffer, sizeof(buffer), NULL);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_INVALID_DATA, "got error %#lx\n", GetLastError());

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_HARDWAREID,
            &type, (BYTE *)buffer, sizeof(buffer), &size);
    ok(ret, "got error %#lx\n", GetLastError());
    ok(type == REG_MULTI_SZ, "got type %lu\n", type);
    ok(size == sizeof(expect_hardware_id), "got size %lu\n", size);
    ok(!memcmp(buffer, expect_hardware_id, size), "got hardware IDs %s\n", debugstr_an(buffer, size));

    /* Using the WCHAR variant because Windows returns a WCHAR for this property even when using SetupDiGetDeviceRegistryPropertyA */
    ret = SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_BASE_CONTAINERID,
            &type, (BYTE *)buffer_w, sizeof(buffer_w), &size);
    ok(ret, "got error %#lx\n", GetLastError());
    ok(type == REG_SZ, "got type %lu\n", type);
    ok(size == sizeof(expect_container_id_w), "got size %lu\n", size);
    ok(!memcmp(buffer_w, expect_container_id_w, size), "got container ID %s\n", debugstr_w(buffer_w));

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_COMPATIBLEIDS,
            &type, (BYTE *)buffer, sizeof(buffer), &size);
    ok(ret, "got error %#lx\n", GetLastError());
    ok(type == REG_MULTI_SZ, "got type %lu\n", type);
    ok(size == sizeof(expect_compat_id), "got size %lu\n", size);
    ok(!memcmp(buffer, expect_compat_id, size), "got compatible IDs %s\n", debugstr_an(buffer, size));

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
            &type, (BYTE *)buffer, sizeof(buffer), NULL);
    todo_wine ok(ret, "got error %#lx\n", GetLastError());
    if (ret)
    {
        ok(type == REG_SZ, "got type %lu\n", type);
        ok(!strcmp(buffer, "\\Device\\winetest_pnp_1"), "got PDO name %s\n", debugstr_a(buffer));
    }

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_LOCATION_INFORMATION, &type, (BYTE *)buffer,
            sizeof(buffer), &size);
    todo_wine ok(ret, "Got error %#lx.\n", GetLastError());
    if (ret)
    {
        ok(type == REG_SZ, "Got type %lu.\n", type);
        ok(size == sizeof(expect_device_location), "Got size %lu.\n", size);
        ok(!strcmp(buffer, expect_device_location), "Got location information %s.\n", debugstr_a(buffer));
    }

    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    memset(buffer_w, 0, sizeof(buffer_w));
    ret = SetupDiGetDevicePropertyW(set, &device, &DEVPKEY_Device_HardwareIds, &prop_type, (BYTE *)buffer_w,
                                    sizeof(buffer_w), &size, 0);
    ok(ret, "failed to get device property, error %#lx\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_STRING_LIST, "got type %#lx\n", prop_type);
    ok(size == sizeof(expect_hardware_id_w), "got size %lu\n", size);
    ok(!memcmp(buffer_w, expect_hardware_id_w, size), "got hardware IDs %s\n", debugstr_wn(buffer_w, size));

    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    memset(buffer_w, 0, sizeof(buffer_w));
    ret = SetupDiGetDevicePropertyW(set, &device, &DEVPKEY_Device_CompatibleIds, &prop_type, (BYTE *)buffer_w,
                                    sizeof(buffer_w), &size, 0);
    ok(ret, "failed to get device property, error %#lx\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_STRING_LIST, "got type %#lx\n", prop_type);
    ok(size == sizeof(expect_compat_id_w), "got size %lu\n", size);
    ok(!memcmp(buffer_w, expect_compat_id_w, size), "got compatible IDs %s\n", debugstr_wn(buffer_w, size));

    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    ret = SetupDiGetDevicePropertyW(set, &device, &DEVPKEY_Device_ContainerId, &prop_type, (BYTE *)&buffer_guid,
                                    sizeof(buffer_guid), &size, 0);
    ok(ret, "failed to get device property, error %#lx\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_GUID, "got type %#lx\n", prop_type);
    ok(size == sizeof(expect_container_id_guid), "got size %lu\n", size);
    ok(IsEqualGUID(&buffer_guid, &expect_container_id_guid), "got container ID %s != %s\n",
       debugstr_guid(&buffer_guid), debugstr_guid(&expect_container_id_guid));

    /* DEVPKEY_Device_BusReportedDeviceDesc. */
    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    memset(buffer_w, 0, sizeof(buffer_w));
    ret = SetupDiGetDevicePropertyW(set, &device, &DEVPKEY_Device_BusReportedDeviceDesc, &prop_type, (BYTE *)buffer_w,
                                    sizeof(buffer_w), &size, 0);
    ok(ret, "Got error %#lx.\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_STRING, "got type %#lx\n", prop_type);
    ok(size == sizeof(expect_device_bus_desc_w), "Got size %lu.\n", size);
    ok(!wcscmp(buffer_w, expect_device_bus_desc_w), "Got device bus desc %s.\n", debugstr_w(buffer_w));

    /* DEVPKEY_Device_LocationInfo. */
    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    memset(buffer_w, 0, sizeof(buffer_w));
    ret = SetupDiGetDevicePropertyW(set, &device, &DEVPKEY_Device_LocationInfo, &prop_type, (BYTE *)buffer_w,
                                    sizeof(buffer_w), &size, 0);
    todo_wine ok(ret, "Got error %#lx.\n", GetLastError());
    if (ret)
    {
        ok(prop_type == DEVPROP_TYPE_STRING, "got type %#lx\n", prop_type);
        ok(size == sizeof(expect_device_location_w), "Got size %lu.\n", size);
        ok(!wcscmp(buffer_w, expect_device_location_w), "Got device location info %s.\n", debugstr_w(buffer_w));
    }

    ret = SetupDiEnumDeviceInterfaces(set, NULL, &child_class, 0, &iface);
    ok(ret, "failed to get interface, error %#lx\n", GetLastError());
    ok(IsEqualGUID(&iface.InterfaceClassGuid, &child_class),
            "wrong class %s\n", debugstr_guid(&iface.InterfaceClassGuid));
    ok(iface.Flags == SPINT_ACTIVE, "got flags %#lx\n", iface.Flags);

    iface_detail->cbSize = sizeof(*iface_detail);
    ret = SetupDiGetDeviceInterfaceDetailA(set, &iface, iface_detail, sizeof(buffer), NULL, NULL);
    ok(ret, "failed to get interface path, error %#lx\n", GetLastError());
    ok(!strcmp(iface_detail->DevicePath, "\\\\?\\wine#test#1#{deadbeef-29ef-4538-a5fd-b69573a362c2}"),
            "wrong path %s\n", debugstr_a(iface_detail->DevicePath));

    prop_type = DEVPROP_TYPE_EMPTY;
    size = 0;
    enabled = DEVPROP_FALSE;
    ret = SetupDiGetDeviceInterfacePropertyW(set, &iface, &DEVPKEY_DeviceInterface_Enabled, &prop_type,
                                             (BYTE *)&enabled, sizeof(enabled), &size, 0);
    ok(ret, "failed to get device interface property, got error %lu\n", GetLastError());
    ok(prop_type == DEVPROP_TYPE_BOOLEAN, "got prop_type %#lx\n", prop_type);
    ok(size == sizeof(enabled), "got size %lu\n", size);
    ok(enabled == DEVPROP_TRUE, "got enabled %d\n", enabled);

    /* Create a device parameter for testing IoOpenDeviceRegistryKey */
    key = SetupDiCreateDevRegKeyA(set, &device, DICS_FLAG_GLOBAL, 0, DIREG_DEV, NULL, NULL);
    ok(key != INVALID_HANDLE_VALUE, "failed to create a hardware parameters key, got error %#lx\n", GetLastError());
    status = RegSetValueExA(key, foobar, 0, REG_SZ, (const BYTE *)bar, sizeof(bar));
    ok(status == ERROR_SUCCESS, "failed to save a device parameter, got error %lu\n", status);
    RegCloseKey(key);

    SetupDiDestroyDeviceInfoList(set);

    RtlInitUnicodeString(&string, L"\\Device\\winetest_pnp_1");
    InitializeObjectAttributes(&attr, &string, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ret = NtOpenFile(&child, SYNCHRONIZE, &attr, &io, 0, FILE_SYNCHRONOUS_IO_NONALERT);
    ok(!ret, "failed to open child: %#x\n", ret);

    id = 0xdeadbeef;
    ret = DeviceIoControl(child, IOCTL_WINETEST_CHILD_GET_ID, NULL, 0, &id, sizeof(id), &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());
    ok(id == 1, "got id %d\n", id);
    ok(size == sizeof(id), "got size %lu\n", size);

    ret = DeviceIoControl(child, IOCTL_WINETEST_CHILD_MAIN, NULL, 0, NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    CloseHandle(child);

    ret = NtOpenFile(&child, SYNCHRONIZE, &attr, &io, 0, 0);
    ok(!ret, "failed to open child: %#x\n", ret);

    ret = DeviceIoControl(child, IOCTL_WINETEST_CHILD_MARK_PENDING, NULL, 0, NULL, 0, &size, &ovl);
    ok(!ret, "DeviceIoControl succeeded\n");
    ok(GetLastError() == ERROR_IO_PENDING, "got error %lu\n", GetLastError());
    ok(size == 0, "got size %lu\n", size);

    id = 1;
    ret = DeviceIoControl(bus, IOCTL_WINETEST_BUS_REMOVE_CHILD, &id, sizeof(id), NULL, 0, &size, NULL);
    ok(ret, "got error %lu\n", GetLastError());

    pump_messages();
    ok(got_child_arrival == 1, "got %u child arrival messages\n", got_child_arrival);
    ok(got_child_removal == 1, "got %u child removal messages\n", got_child_removal);
    if (have_devquery)
    {
        status = WaitForSingleObject(devquery_data.device_removed_sem, 1000);
        ok(!status, "WaitForSingleObject failed, error %lu\n", status);
        ok(devquery_data.child_dev_added == 1, "got %lu new bus device objects\n", devquery_data.child_dev_added);
        ok(devquery_data.child_dev_removed == 1, "got %lu bus device object removals\n", devquery_data.child_dev_removed);
    }

    ret = DeviceIoControl(child, IOCTL_WINETEST_CHILD_CHECK_REMOVED, NULL, 0, NULL, 0, &size, NULL);
    todo_wine ok(ret, "got error %lu\n", GetLastError());

    ret = NtOpenFile(&tmp, SYNCHRONIZE, &attr, &io, 0, FILE_SYNCHRONOUS_IO_NONALERT);
    todo_wine ok(ret == STATUS_NO_SUCH_DEVICE, "got %#x\n", ret);

    ret = GetOverlappedResult(child, &ovl, &size, TRUE);
    ok(!ret, "unexpected success.\n");
    ok(GetLastError() == ERROR_ACCESS_DENIED, "got error %lu\n", GetLastError());
    ok(size == 0, "got size %lu\n", size);

    CloseHandle(child);

    pump_messages();
    ok(got_child_arrival == 1, "got %u child arrival messages\n", got_child_arrival);
    ok(got_child_removal == 1, "got %u child removal messages\n", got_child_removal);
    if (have_devquery)
    {
        status = WaitForSingleObject(devquery_data.device_added_sem, 1000);
        ok(status == WAIT_TIMEOUT, "got status %#lx\n", status);
        status = WaitForSingleObject(devquery_data.device_removed_sem, 1000);
        ok(status == WAIT_TIMEOUT, "got status %#lx\n", status);
        ok(devquery_data.child_dev_added == 1, "got %lu new bus device objects\n", devquery_data.child_dev_added);
        ok(devquery_data.child_dev_removed == 1, "got %lu bus device object removals\n", devquery_data.child_dev_removed);
    }

    ret = NtOpenFile(&tmp, SYNCHRONIZE, &attr, &io, 0, FILE_SYNCHRONOUS_IO_NONALERT);
    ok(ret == STATUS_OBJECT_NAME_NOT_FOUND, "got %#x\n", ret);

    CloseHandle(bus);

    UnregisterDeviceNotification(notify_handle);
    if (have_devquery)
    {
        pDevCloseObjectQuery(query);
        CloseHandle(devquery_data.device_added_sem);
        CloseHandle(devquery_data.device_removed_sem);
        CloseHandle(devquery_data.enum_completed_evt);
    }
    DestroyWindow(window);
    UnregisterClassA("ntoskrnl_test_wc", GetModuleHandleA(NULL));
}

static void test_pnp_driver(struct testsign_context *ctx)
{
    static const char hardware_id[] = "test_hardware_id\0";
    char path[MAX_PATH], dest[MAX_PATH], *filepart;
    SP_DEVINFO_DATA device = {sizeof(device)};
    char cwd[MAX_PATH], tempdir[MAX_PATH];
    WCHAR driver_filename[MAX_PATH];
    SC_HANDLE manager, service;
    BOOL ret, need_reboot;
    HANDLE catalog, file;
    DWORD dword, type;
    unsigned int i;
    HDEVINFO set;
    FILE *f;

    GetCurrentDirectoryA(ARRAY_SIZE(cwd), cwd);
    GetTempPathA(ARRAY_SIZE(tempdir), tempdir);
    SetCurrentDirectoryA(tempdir);

    load_resource(L"driver_pnp.dll", driver_filename);
    ret = MoveFileExW(driver_filename, L"winetest.sys", MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
    ok(ret, "failed to move file, error %lu\n", GetLastError());

    f = fopen("winetest.inf", "w");
    ok(!!f, "failed to open winetest.inf: %s\n", strerror(errno));
    fputs(inf_text, f);
    fclose(f);

    /* Create the catalog file. */

    catalog = CryptCATOpen((WCHAR *)L"winetest.cat", CRYPTCAT_OPEN_CREATENEW, 0, CRYPTCAT_VERSION_1, 0);
    ok(catalog != INVALID_HANDLE_VALUE, "Failed to create catalog, error %#lx\n", GetLastError());

    ret = !!CryptCATPutCatAttrInfo(catalog, (WCHAR *)L"HWID1",
            CRYPTCAT_ATTR_NAMEASCII | CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_AUTHENTICATED,
            sizeof(L"test_hardware_id"), (BYTE *)L"test_hardware_id");
    todo_wine ok(ret, "failed to add attribute, error %#lx\n", GetLastError());

    ret = !!CryptCATPutCatAttrInfo(catalog, (WCHAR *)L"OS",
            CRYPTCAT_ATTR_NAMEASCII | CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_AUTHENTICATED,
            sizeof(L"VistaX64"), (BYTE *)L"VistaX64");
    todo_wine ok(ret, "failed to add attribute, error %#lx\n", GetLastError());

    add_file_to_catalog(catalog, L"winetest.sys");
    add_file_to_catalog(catalog, L"winetest.inf");

    ret = CryptCATPersistStore(catalog);
    todo_wine ok(ret, "Failed to write catalog, error %lu\n", GetLastError());

    ret = CryptCATClose(catalog);
    ok(ret, "Failed to close catalog, error %lu\n", GetLastError());

    testsign_sign(ctx, L"winetest.cat");

    /* Install the driver. */

    set = SetupDiCreateDeviceInfoList(NULL, NULL);
    ok(set != INVALID_HANDLE_VALUE, "failed to create device list, error %#lx\n", GetLastError());

    ret = SetupDiCreateDeviceInfoA(set, "root\\winetest\\0", &GUID_NULL, NULL, NULL, 0, &device);
    ok(ret, "failed to create device, error %#lx\n", GetLastError());

    ret = SetupDiSetDeviceRegistryPropertyA( set, &device, SPDRP_HARDWAREID,
            (const BYTE *)hardware_id, sizeof(hardware_id) );
    ok(ret, "failed to create set hardware ID, error %#lx\n", GetLastError());

    ret = SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, &device);
    ok(ret, "failed to register device, error %#lx\n", GetLastError());

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_CONFIGFLAGS,
            &type, (BYTE *)&dword, sizeof(dword), NULL);
    ok(!ret, "expected failure\n");
    ok(GetLastError() == ERROR_INVALID_DATA, "got error %#lx\n", GetLastError());

    GetFullPathNameA("winetest.inf", sizeof(path), path, NULL);
    ret = UpdateDriverForPlugAndPlayDevicesA(NULL, hardware_id, path, INSTALLFLAG_FORCE, &need_reboot);
    ok(ret, "failed to install device, error %#lx\n", GetLastError());
    ok(!need_reboot, "expected no reboot necessary\n");

    ret = SetupDiGetDeviceRegistryPropertyA(set, &device, SPDRP_CONFIGFLAGS,
            &type, (BYTE *)&dword, sizeof(dword), NULL);
    ok(ret, "got error %#lx\n", GetLastError());
    ok(!dword, "got flags %#lx\n", dword);
    ok(type == REG_DWORD, "got type %lu\n", type);

    /* Tests. */

    test_pnp_devices();

    /* Clean up. */

    ret = SetupDiCallClassInstaller(DIF_REMOVE, set, &device);
    ok(ret, "failed to remove device, error %#lx\n", GetLastError());

    file = CreateFileA("\\\\?\\root#winetest#0#{deadbeef-29ef-4538-a5fd-b69573a362c0}", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(file == INVALID_HANDLE_VALUE, "expected failure\n");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "got error %lu\n", GetLastError());

    ret = SetupDiDestroyDeviceInfoList(set);
    ok(ret, "failed to destroy set, error %#lx\n", GetLastError());

    set = SetupDiGetClassDevsA(NULL, "wine", NULL, DIGCF_ALLCLASSES);
    ok(set != INVALID_HANDLE_VALUE, "failed to get device list, error %#lx\n", GetLastError());

    for (i = 0; SetupDiEnumDeviceInfo(set, i, &device); ++i)
    {
        ret = SetupDiCallClassInstaller(DIF_REMOVE, set, &device);
        ok(ret, "failed to remove device, error %#lx\n", GetLastError());
    }

    SetupDiDestroyDeviceInfoList(set);

    /* Windows stops the service but does not delete it. */
    manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    ok(!!manager, "failed to open service manager, error %lu\n", GetLastError());
    service = OpenServiceA(manager, "winetest", SERVICE_STOP | DELETE);
    ok(!!service, "failed to open service, error %lu\n", GetLastError());
    unload_driver(service);
    CloseServiceHandle(manager);

    cat_okfile();

    GetFullPathNameA("winetest.inf", sizeof(path), path, NULL);
    ret = SetupCopyOEMInfA(path, NULL, 0, 0, dest, sizeof(dest), NULL, &filepart);
    ok(ret, "Failed to copy INF, error %#lx\n", GetLastError());
    ret = SetupUninstallOEMInfA(filepart, SUOI_FORCEDELETE, NULL);
    ok(ret, "Failed to uninstall INF, error %lu\n", GetLastError());

    ret = DeleteFileA("winetest.cat");
    ok(ret, "Failed to delete file, error %lu\n", GetLastError());
    ret = DeleteFileA("winetest.inf");
    ok(ret, "Failed to delete file, error %lu\n", GetLastError());
    ret = DeleteFileA("winetest.sys");
    ok(ret, "Failed to delete file, error %lu\n", GetLastError());
    /* Windows 10 apparently deletes the image in SetupUninstallOEMInf(). */
    ret = DeleteFileA("C:/windows/system32/drivers/winetest.sys");
    ok(ret || GetLastError() == ERROR_FILE_NOT_FOUND, "Failed to delete file, error %lu\n", GetLastError());

    SetCurrentDirectoryA(cwd);
}

START_TEST(ntoskrnl)
{
    WCHAR filename[MAX_PATH], filename2[MAX_PATH];
    struct testsign_context ctx;
    SC_HANDLE service, service2;
    BOOL ret, is_wow64;
    HANDLE mapping;
    DWORD written;
    HMODULE cfgmgr32;
#ifdef __x86_64__
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc == 7 && !strcmp(argv[2], "attachment_child"))
    {
        attachment_child(argv);
        return;
    }
#endif
    cfgmgr32 = LoadLibraryA("cfgmgr32.dll");

    pCancelIoEx = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CancelIoEx");
    pSetFileCompletionNotificationModes = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                                                 "SetFileCompletionNotificationModes");
    pDevCreateObjectQuery = (void *)GetProcAddress(cfgmgr32, "DevCreateObjectQuery");
    pDevCloseObjectQuery = (void *)GetProcAddress(cfgmgr32, "DevCloseObjectQuery");

    if (IsWow64Process(GetCurrentProcess(), &is_wow64) && is_wow64)
    {
        skip("Running in WoW64.\n");
        return;
    }

    if (!testsign_create_cert(&ctx))
        return;

    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
            0, sizeof(*test_data), "Global\\winetest_ntoskrnl_section");
    ok(!!mapping, "got error %lu\n", GetLastError());
    test_data = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 1024);
    test_data->running_under_wine = !strcmp(winetest_platform, "wine");
    test_data->winetest_report_success = winetest_report_success;
    test_data->winetest_debug = winetest_debug;

    okfile = CreateFileA("C:\\windows\\winetest_ntoskrnl_okfile", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(okfile != INVALID_HANDLE_VALUE, "failed to create file, error %lu\n", GetLastError());

    subtest("driver");
    if (!(service = load_driver(&ctx, filename, L"driver.dll", L"WineTestDriver")))
        goto out;

    if (!start_driver(service, FALSE))
    {
        DeleteFileW(filename);
        goto out;
    }
    service2 = load_driver(&ctx, filename2, L"driver2.dll", L"WineTestDriver2");

    device = CreateFileA("\\\\.\\WineTestDriver", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(device != INVALID_HANDLE_VALUE, "failed to open device: %lu\n", GetLastError());

    test_basic_ioctl();

    main_test();
    todo_wine ok(modified_value == 0xdeadbeeffeedcafe, "Got unexpected value %#I64x.\n", modified_value);
    test_shared_kernel_memory();
    test_process_attachment();

    test_overlapped();
    test_load_driver(service2);
    test_file_handles();
    test_return_status();
    test_object_info();
    test_blocking_irp();

    /* We need a separate ioctl to call IoDetachDevice(); calling it in the
     * driver unload routine causes a live-lock. */
    ret = DeviceIoControl(device, IOCTL_WINETEST_DETACH, NULL, 0, NULL, 0, &written, NULL);
    ok(ret, "DeviceIoControl failed: %lu\n", GetLastError());

    CloseHandle(device);

    unload_driver(service2);
    unload_driver(service);
    ret = DeleteFileW(filename);
    ok(ret, "DeleteFile failed: %lu\n", GetLastError());
    ret = DeleteFileW(filename2);
    ok(ret, "DeleteFile failed: %lu\n", GetLastError());

    cat_okfile();

    test_driver3(&ctx);
    subtest("driver_netio");
    test_driver_netio(&ctx);

    subtest("driver_pnp");
    test_pnp_driver(&ctx);

out:
    testsign_cleanup(&ctx);
    FreeLibrary(cfgmgr32);
    UnmapViewOfFile(test_data);
    CloseHandle(mapping);
    CloseHandle(okfile);
    DeleteFileA("C:\\windows\\winetest_ntoskrnl_okfile");
}
