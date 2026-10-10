/* Benign Wine Unix-call companion for the live-view collision fixture.
 * LGPL 2.1 or later; see a1b-live-private-view-pe.c. */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, void *reserved );
/* Keep a real AMD64 relocation and verify it when the host loader moves us. */
static BOOL (WINAPI * volatile relocation_anchor)( HINSTANCE, DWORD, void * ) = DllMain;
BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, void *reserved )
{
    (void)instance; (void)reason; (void)reserved;
    return relocation_anchor == DllMain;
}
