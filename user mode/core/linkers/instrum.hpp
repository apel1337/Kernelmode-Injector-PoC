#include <core/external/features/visuals/visuals.h>

extern "C" void instrumentation_callback( VOID );
extern "C" void instrumentation_callbacktwo( VOID );

namespace riot
{
	namespace instrum
	{
		// grind on my butt pls s

		__declspec( align( 8 ) ) struct function_table
		{
			__declspec( align( 8 ) ) f_RtlRestoreContext aRtlRestoreContext;
			__declspec( align( 8 ) ) f_CreateThreadpoolWork aCreateThreadpoolWork;
			__declspec( align( 8 ) ) f_SubmitThreadpoolWork aSubmitThreadpoolWork;
			__declspec( align( 8 ) ) f_CloseThreadpoolWork aCloseThreadpoolWork;
			__declspec( align( 8 ) ) f_CreateThreadpool aCreateThreadpool;
			__declspec( align( 8 ) ) f_WaitForThreadpoolWorkCallbacks aWaitForThreadpoolWorkCallbacks;
			__declspec( align( 8 ) ) f_NtWorkerFactoryWorkerReady aNtWorkerFactoryWorkerReady;
			__declspec( align( 8 ) ) f_TpAllocWork TpAllocWork;
			__declspec( align( 8 ) ) f_RtlAllocateHeap aRtlAllocateHeap;

			__declspec( align( 8 ) ) f_WhitelistMem WhitelistMemory;

			function_table( )
			{
				auto ntdll = GetModuleHandleA( encrypt( "ntdll.dll" ) );
				if ( !ntdll ) return;

				auto kernel32 = GetModuleHandleA( encrypt( "kernel32.dll" ) );
				if ( !kernel32 ) return;

				aRtlRestoreContext = reinterpret_cast< f_RtlRestoreContext >(
					GetProcAddress( ntdll , encrypt( "RtlRestoreContext" ) ) );
				aRtlAllocateHeap = reinterpret_cast< f_RtlAllocateHeap >(
					GetProcAddress( ntdll , encrypt( "RtlAllocateHeap" ) ) );
				TpAllocWork = reinterpret_cast< f_TpAllocWork >(
					GetProcAddress( ntdll , encrypt( "TpAllocWork" ) ) );
				aNtWorkerFactoryWorkerReady = reinterpret_cast< f_NtWorkerFactoryWorkerReady >(
					GetProcAddress( ntdll , encrypt( "NtWorkerFactoryWorkerReady" ) ) );
				aCreateThreadpoolWork = reinterpret_cast< f_CreateThreadpoolWork >(
					GetProcAddress( kernel32 , encrypt( "CreateThreadpoolWork" ) ) );
				aSubmitThreadpoolWork = reinterpret_cast< f_SubmitThreadpoolWork >(
					GetProcAddress( kernel32 , encrypt( "SubmitThreadpoolWork" ) ) );
				aCloseThreadpoolWork = reinterpret_cast< f_CloseThreadpoolWork >(
					GetProcAddress( kernel32 , encrypt( "CloseThreadpoolWork" ) ) );
				aCreateThreadpool = reinterpret_cast< f_CreateThreadpool >(
					GetProcAddress( kernel32 , encrypt( "CreateThreadpool" ) ) );
				aWaitForThreadpoolWorkCallbacks = reinterpret_cast< f_WaitForThreadpoolWorkCallbacks >(
					GetProcAddress( kernel32 , encrypt( "WaitForThreadpoolWorkCallbacks" ) ) );
			}
		};

		__declspec( align( 8 ) ) struct shellcode_data
		{
			__declspec( align( 8 ) ) bool m_first;
			__declspec( align( 8 ) ) std::uint64_t m_shell_return;
			__declspec( align( 8 ) ) NTSTATUS m_nt;
			__declspec( align( 8 ) ) PTP_WORK m_work;
			__declspec( align( 8 ) ) HANDLE m_worker_factory;
			__declspec( align( 8 ) ) std::uintptr_t m_task_address;
			__declspec( align( 8 ) ) std::size_t m_task_size;
			__declspec( align( 8 ) ) std::uintptr_t m_task_data;
			__declspec( align( 8 ) ) std::uintptr_t m_ic_base_address;
			__declspec( align( 8 ) ) std::size_t m_ic_size;
			__declspec( align( 8 ) ) std::uintptr_t m_old_ic_address;
			__declspec( align( 8 ) ) function_table* m_function_table;

			shellcode_data( function_table* function_table ) :
				m_shell_return( 0xDEADBEEF ) ,
				m_old_ic_address( NULL ) ,
				m_function_table( function_table ) ,
				m_task_address( NULL ) ,
				m_task_data( NULL ) ,
				m_first( true ) {};
		};

		struct exception_module
		{
			uintptr_t base;
			uintptr_t size;
		};

		struct module_table
		{
			uintptr_t count;
			exception_module entry[ 250 ];
		};

		__forceinline PEB_T* nt_current_peb( )
		{
			teb_t* pTEB = reinterpret_cast< teb_t* >( NtCurrentTeb( ) );
			PEB_T* pPEB = reinterpret_cast< PEB_T* >( pTEB->ProcessEnvironmentBlock );
			return pPEB;
		}

		using f_DLL_ENTRY_POINT = BOOL( WINAPI* )( HINSTANCE hDll , DWORD dwReason , void* pReserved );
	}

	__forceinline UINT_PTR bit_rotate_r( UINT_PTR val , int count )
	{
		return ( val >> count ) | ( val << ( -count ) );
	}
}