/*
 * Experimental shared kernel allocation backing
 *
 * Copyright (C) 2026 Proton Vanguard contributors
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

#include "ntoskrnl_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntoskrnl);

#define ARENA_SIZE (64 * 1024 * 1024)
#define ARENA_EXEC_OFFSET (48 * 1024 * 1024)
#define ARENA_MAGIC 0x4b41524e
#define BLOCK_FREE 0x46524545
#define BLOCK_USED 0x55534544

/* The section contains offsets, not process-local pointers or handles. The
 * descriptor and one-time initialization state remain local to this process.
 * This does not yet provide an executor mapping or cross-process admission. */
struct arena_header
{
    ULONG magic;
    LONG lock;
    ULONGLONG live_count;
    ULONGLONG used_bytes;
    ULONGLONG first[2];
    ULONGLONG end[2];
};

struct arena_block
{
    ULONGLONG span;
    ULONGLONG prev_span;
    ULONGLONG requested;
    ULONG state;
    ULONG tag;
};

C_ASSERT( sizeof(struct arena_block) == 32 );

static INIT_ONCE arena_once = INIT_ONCE_STATIC_INIT;
static NTSTATUS arena_status;
static BOOL arena_enabled;
static HANDLE arena_section;
static char *arena_base;

static struct arena_block *block_at( SIZE_T offset )
{
    return (struct arena_block *)(arena_base + offset);
}

static BOOL WINAPI initialize_arena( INIT_ONCE *once, void *param, void **context )
{
    struct arena_header *header;
    struct arena_block *block;
    LARGE_INTEGER size;
    SIZE_T view_size = ARENA_SIZE, protect_size = ARENA_EXEC_OFFSET;
    void *protect_base;
    ULONG old_protect;
    WCHAR value[2];
    unsigned int i;

    arena_enabled = GetEnvironmentVariableW( L"WINE_SHARED_KERNEL_MEMORY", value, ARRAY_SIZE(value) ) == 1
            && value[0] == '1';
    TRACE( "shared kernel memory opt-in %u\n", arena_enabled );
    if (!arena_enabled) return TRUE;
#ifndef __x86_64__
    arena_status = STATUS_NOT_SUPPORTED;
    ERR( "shared kernel arena is only implemented for x86_64\n" );
    return TRUE;
#endif

    size.QuadPart = ARENA_SIZE;
    arena_status = NtCreateSection( &arena_section, SECTION_ALL_ACCESS, NULL, &size,
                                   PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL );
    if (arena_status) goto failed;
    arena_status = NtMapViewOfSection( arena_section, NtCurrentProcess(), (void **)&arena_base,
                                      0, 0, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE );
    if (arena_status) goto failed;

    /* Separate NX and executable page classes; an executable allocation never
     * shares a page with an NX allocation. The shared arena header is NX. */
    protect_base = arena_base;
    arena_status = NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                          PAGE_READWRITE, &old_protect );
    if (arena_status) goto failed;

    header = (struct arena_header *)arena_base;
    header->magic = ARENA_MAGIC;
    header->first[0] = PAGE_SIZE;
    header->end[0] = ARENA_EXEC_OFFSET;
    header->first[1] = ARENA_EXEC_OFFSET;
    header->end[1] = ARENA_SIZE;
    for (i = 0; i < 2; ++i)
    {
        block = block_at( header->first[i] );
        block->span = header->end[i] - header->first[i];
        block->state = BLOCK_FREE;
    }
    TRACE( "experimental shared kernel section %p at %p, size %#x\n",
           arena_section, arena_base, ARENA_SIZE );
    return TRUE;

failed:
    if (arena_base) NtUnmapViewOfSection( NtCurrentProcess(), arena_base );
    if (arena_section) NtClose( arena_section );
    arena_base = NULL;
    arena_section = NULL;
    ERR( "shared kernel arena initialization failed, status %#lx\n", arena_status );
    /* A failed configured arena must not produce private fallback allocations.
     * Keep the failure for the lifetime of this module. */
    return TRUE;
}

NTSTATUS kernel_memory_init(void)
{
    InitOnceExecuteOnce( &arena_once, initialize_arena, NULL, NULL );
    return arena_status;
}

BOOL kernel_memory_enabled(void)
{
    kernel_memory_init();
    return arena_enabled;
}

static void lock_arena( struct arena_header *header )
{
    while (InterlockedCompareExchange( &header->lock, 1, 0 )) YieldProcessor();
}

static void unlock_arena( struct arena_header *header )
{
    InterlockedExchange( &header->lock, 0 );
}

/* No host API calls, waits or tracing while the shared metadata lock is held. */
void *kernel_memory_alloc( SIZE_T size, SIZE_T alignment, BOOL executable, BOOL zero, ULONG tag )
{
    const SIZE_T minimum = sizeof(struct arena_block) + MEMORY_ALLOCATION_ALIGNMENT;
    struct arena_header *header;
    struct arena_block *block, *allocated, *next;
    SIZE_T offset, payload, prefix, span, remainder, end;
    unsigned int partition = !!executable;
    void *ret = NULL;

    if (kernel_memory_init() || !arena_enabled || !size || size > ARENA_SIZE
            || alignment < MEMORY_ALLOCATION_ALIGNMENT || (alignment & (alignment - 1)))
        return NULL;
    if (size >= PAGE_SIZE) alignment = max( alignment, PAGE_SIZE );
    span = (sizeof(*block) + size + MEMORY_ALLOCATION_ALIGNMENT - 1) & ~(MEMORY_ALLOCATION_ALIGNMENT - 1);
    header = (struct arena_header *)arena_base;

    lock_arena( header );
    end = header->end[partition];
    for (offset = header->first[partition]; offset < end; offset += block->span)
    {
        block = block_at( offset );
        if (!block->span || block->span > end - offset) break;
        if (block->state != BLOCK_FREE) continue;

        payload = (offset + sizeof(*block) + alignment - 1) & ~(alignment - 1);
        for (;;)
        {
            /* Small pool allocations are wholly contained in one page. */
            if (size < PAGE_SIZE && (payload & (PAGE_SIZE - 1)) + size > PAGE_SIZE)
                payload = (payload + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            prefix = payload - sizeof(*block) - offset;
            if (!prefix || prefix >= minimum) break;
            payload += alignment;
        }
        if (prefix > block->span || span > block->span - prefix) continue;

        if (prefix)
        {
            allocated = block_at( offset + prefix );
            allocated->span = block->span - prefix;
            allocated->prev_span = prefix;
            block->span = prefix;
            block->requested = 0;
            block->tag = 0;
            offset += prefix;
        }
        else
            allocated = block;

        remainder = allocated->span - span;
        if (remainder >= minimum)
        {
            next = block_at( offset + span );
            next->span = remainder;
            next->prev_span = span;
            next->requested = 0;
            next->state = BLOCK_FREE;
            next->tag = 0;
            allocated->span = span;
        }
        if (offset + allocated->span < end)
            block_at( offset + allocated->span )->prev_span = allocated->span;
        if (offset + allocated->span + remainder < end && remainder >= minimum)
            block_at( offset + allocated->span + remainder )->prev_span = remainder;
        allocated->requested = size;
        allocated->state = BLOCK_USED;
        allocated->tag = tag;
        ++header->live_count;
        header->used_bytes += size;
        ret = arena_base + payload;
        break;
    }
    unlock_arena( header );

    if (ret && zero) memset( ret, 0, size );
    return ret;
}

BOOL kernel_memory_free( void *ptr )
{
    struct arena_header *header;
    struct arena_block *block, *next, *previous;
    SIZE_T offset, current, first, end;
    BOOL valid = FALSE;

    if (!arena_base || (ULONG_PTR)ptr < (ULONG_PTR)arena_base + PAGE_SIZE
            || (ULONG_PTR)ptr >= (ULONG_PTR)arena_base + ARENA_SIZE)
        return FALSE;

    offset = (char *)ptr - arena_base - sizeof(*block);
    header = (struct arena_header *)arena_base;
    first = header->first[offset >= ARENA_EXEC_OFFSET];
    end = header->end[offset >= ARENA_EXEC_OFFSET];
    if (offset < first || offset > end - sizeof(*block) || offset % MEMORY_ALLOCATION_ALIGNMENT)
        goto done;

    lock_arena( header );
    /* Reject interior pointers, including stale headers left behind when free
     * blocks coalesce. Never interpret user bytes as an allocator header. */
    for (current = first; current < offset; current += block->span)
    {
        block = block_at( current );
        if (block->span < sizeof(*block) || block->span % MEMORY_ALLOCATION_ALIGNMENT
                || block->span > end - current)
            goto unlock;
    }
    if (current != offset) goto unlock;
    block = block_at( offset );
    if (block->state != BLOCK_USED || block->span < sizeof(*block)
            || block->span % MEMORY_ALLOCATION_ALIGNMENT || block->span > end - offset
            || !block->requested || block->requested > block->span - sizeof(*block))
        goto unlock;

    next = NULL;
    previous = NULL;
    if (offset + block->span < end)
    {
        next = block_at( offset + block->span );
        if (next->prev_span != block->span || next->span < sizeof(*block)
                || next->span % MEMORY_ALLOCATION_ALIGNMENT || next->span > end - offset - block->span
                || (next->state != BLOCK_FREE && next->state != BLOCK_USED))
            goto unlock;
    }
    if (offset > first)
    {
        if (block->prev_span < sizeof(*block) || block->prev_span > offset - first
                || block->prev_span % MEMORY_ALLOCATION_ALIGNMENT)
            goto unlock;
        previous = block_at( offset - block->prev_span );
        if (previous->span != block->prev_span
                || (previous->state != BLOCK_FREE && previous->state != BLOCK_USED))
            goto unlock;
    }

    --header->live_count;
    header->used_bytes -= block->requested;
    block->requested = 0;
    block->state = BLOCK_FREE;
    block->tag = 0;
    if (next && next->state == BLOCK_FREE) block->span += next->span;
    if (previous && previous->state == BLOCK_FREE)
    {
        previous->span += block->span;
        offset -= block->prev_span;
        block = previous;
    }
    if (offset + block->span < end) block_at( offset + block->span )->prev_span = block->span;
    valid = TRUE;
unlock:
    unlock_arena( header );
done:
    if (!valid) ERR( "invalid shared kernel allocation %p\n", ptr );
    /* An invalid pointer within the section is not a private-heap allocation. */
    return TRUE;
}

/* Deliberately retain the section and view until process teardown. Driver
 * unload does not prove that all referenced objects, workers and pending IRPs
 * have drained. Unmapping on a zero count without fencing new admission would
 * race allocations. Failed initialization cleans up immediately above. */
