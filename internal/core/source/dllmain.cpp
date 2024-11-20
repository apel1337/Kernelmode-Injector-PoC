#include <core/linkers/packman.h>

using namespace riot;

[[ nodiscard ]] int DllMain ( HMODULE hModule , DWORD  ul_reason_for_call , LPVOID lpReserved )
{
    if ( ul_reason_for_call == DLL_PROCESS_ATTACH )
    {
        MessageBoxA ( 0 , 0 , 0 , 0 );
        packman::decrypt_memory_pages_for_dump ( );
    }

    return 1;
}
