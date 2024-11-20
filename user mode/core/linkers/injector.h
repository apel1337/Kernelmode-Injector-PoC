#include <core/linkers/section.hpp>

namespace riot
{
	namespace injector
	{
		inline uint8_t _handler64[ ]
		{
			0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0x01, 0x4C, 0x8B, 0xD9, 0x81, 0x38, 0x63, 0x73, 0x6D, 0xE0,
			0x0F, 0x85, 0x7C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x1C, 0x24, 0x45, 0x33, 0xC9, 0x48, 0xBB, 0xEF,
			0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x4C, 0x39, 0x0B, 0x76, 0x5B, 0x48, 0xB8, 0xF7, 0xBE,
			0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x4D, 0x8B, 0x03, 0x48, 0x8B, 0x10, 0x4D, 0x8B, 0x50, 0x30, 0x4C, 0x3B, 0xD2, 0x72, 0x2C, 0x48,
			0x03, 0x50, 0x08, 0x4C, 0x3B, 0xD2, 0x77, 0x23, 0x49, 0x81, 0x78, 0x20, 0x00, 0x40, 0x99, 0x01,
			0x75, 0x19, 0x49, 0x83, 0x78, 0x38, 0x00, 0x75, 0x12, 0x49, 0xC7, 0x40, 0x20, 0x20, 0x05, 0x93,
			0x19, 0x49, 0x8B, 0x13, 0x48, 0x8B, 0x08, 0x48, 0x89, 0x4A, 0x38, 0x49, 0xFF, 0xC1, 0x48, 0x83,
			0xC0, 0x10, 0x4C, 0x3B, 0x0B, 0x72, 0xB9, 0x33, 0xC0, 0x48, 0x8B, 0x1C, 0x24, 0x48, 0x83, 0xC4,
			0x08, 0xC3, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x08, 0xC3
		};

		class c_interface
		{
		public:
			c_interface( driver::c_interface& driver_ctx )
				: driver_ctx( driver_ctx ) { }

		public:
			template <typename type>
			type rva_to_va( DWORD rva );
			std::uintptr_t get_export( LPCSTR module_name , LPCSTR function_name );

			// instrumentation execution
			std::size_t get_ic_size( void* ic );

			bool resolve_imports( );
			bool write_sections( std::uintptr_t mapped_memory );
			bool relocate_image( std::uintptr_t mapped_memory );
			bool enable_exceptions( std::uintptr_t mapped_memory );

			bool setup_target_image( );
			void set_target_image( std::vector<uint8_t> buffer );
			void load_file( const std::string& file , std::vector<uint8_t>& data );

			bool prepare_injection( );
			bool call_dll_main( );

		private:
			driver::c_interface& driver_ctx;
			std::vector<uint8_t> m_image_mapped;

			ULONGLONG m_inject_address;
			PIMAGE_DOS_HEADER m_dos_header;
			PIMAGE_NT_HEADERS m_nt_headers;
			std::vector<uint8_t> m_target_image;

			void* veh_code;
			std::uintptr_t m_mod_table;

			std::size_t m_set_ic_size;
			std::size_t m_max_shell_size;
			std::size_t m_set_shell_size;
			std::uintptr_t m_ic_base_address;
			std::uintptr_t m_ic_start;
		};

		struct task_shellcode_data;
		using f_internal_func = DWORD( __stdcall* )( task_shellcode_data* data );

		__declspec( align( 8 ) ) struct task_function_table
		{
			__declspec( align( 8 ) ) f_internal_func fcookies;
			__declspec( align( 8 ) ) f_internal_func fexceptions;
			__declspec( align( 8 ) ) f_internal_func ftls_callbacks;
			__declspec( align( 8 ) ) f_internal_func fdll_main;
			__declspec( align( 8 ) ) f_LdrLockLoaderLock LdrLockLoaderLock;
			__declspec( align( 8 ) ) f_LdrUnlockLoaderLock LdrUnlockLoaderLock;
			__declspec( align( 8 ) ) f_RtlAllocateHeap RtlAllocateHeap;
			__declspec( align( 8 ) ) f_NtAllocateVirtualMemory NtAllocateVirtualMemory;
			__declspec( align( 8 ) ) f_RtlFreeHeap RtlFreeHeap;
			__declspec( align( 8 ) ) f_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable;
			__declspec( align( 8 ) ) f_RtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler;
			__declspec( align( 8 ) ) f_LdrProtectMrdata LdrProtectMrdata;
			__declspec( align( 8 ) ) f_RtlAddFunctionTable RtlAddFunctionTable;
			__declspec( align( 8 ) ) f_LdrpHandleTlsData LdrpHandleTlsData;
			__declspec( align( 8 ) ) LIST_ENTRY* LdrpTlsList;
			__declspec( align( 8 ) ) RTL_INVERTED_FUNCTION_TABLE* LdrpInvertedFunctionTable;

			__declspec( align( 8 ) ) f_GetCurrentThreadId aGetCurrentThreadId;
			task_function_table( std::uintptr_t second_address );
		};

		__declspec( align( 8 ) ) struct task_shellcode_data
		{
			__declspec( align( 8 ) ) DWORD cookies_return;
			__declspec( align( 8 ) ) DWORD exception_return;
			__declspec( align( 8 ) ) DWORD tls_return;
			__declspec( align( 8 ) ) DWORD dllmain_return;
			__declspec( align( 8 ) ) bool safe_seh;
			__declspec( align( 8 ) ) void* veh_code;
			__declspec( align( 8 ) ) instrum::module_table* mod_table;

			__declspec( align( 8 ) ) bool first;
			__declspec( align( 8 ) ) std::uintptr_t ic_start;
			__declspec( align( 8 ) ) std::uintptr_t ic_size;

			__declspec( align( 8 ) ) void* fake_seh_directory;

			__declspec( align( 8 ) ) std::uintptr_t base_address;
			__declspec( align( 8 ) ) std::uintptr_t entry_point;

			__declspec( align( 8 ) ) FILETIME system_time;
			__declspec( align( 8 ) ) LARGE_INTEGER performence_count;
			__declspec( align( 8 ) ) DWORD process_pid;

			__declspec( align( 8 ) ) std::uintptr_t hyperion_base;

			__declspec( align( 8 ) ) const IMAGE_OPTIONAL_HEADER64* optional_header;
			__declspec( align( 8 ) ) const IMAGE_NT_HEADERS64* nt_headers;

			__declspec( align( 8 ) ) task_function_table* functions;

			task_shellcode_data(
				std::uintptr_t mapped_image ,
				std::uintptr_t image_entry_point ,
				unsigned int process_id ,
				void* pveh_code ,
				void* pmod_table
			) {
				base_address = mapped_image;
				entry_point = image_entry_point;
				optional_header = nullptr;
				nt_headers = nullptr;
				safe_seh = false;
				fake_seh_directory = nullptr;
				GetSystemTimeAsFileTime( &system_time );
				QueryPerformanceCounter( &performence_count );
				process_pid = process_id;
				veh_code = pveh_code;
				mod_table = reinterpret_cast< instrum::module_table* >( pmod_table );
				first = false;
			}
		};

		inline DWORD __declspec( code_seg( ".t_sec$01" ) ) __stdcall internal_handler( instrum::shellcode_data* data , PCONTEXT context );
		inline DWORD __declspec( code_seg( ".t_sec$02" ) ) __stdcall end_function( );

		inline DWORD __declspec( code_seg( ".i_sec$01" ) ) __stdcall task_internal_handler( PTP_CALLBACK_INSTANCE Instance , task_shellcode_data* Parameter , PTP_WORK Work );
		inline DWORD __declspec( code_seg( ".i_sec$02" ) ) __stdcall task_cookies( task_shellcode_data* Data );
		inline DWORD __declspec( code_seg( ".i_sec$03" ) ) __stdcall task_exceptions( task_shellcode_data* Data );
		inline DWORD __declspec( code_seg( ".i_sec$04" ) ) __stdcall task_tls_callbacks( task_shellcode_data* Data );
		inline DWORD __declspec( code_seg( ".i_sec$05" ) ) __stdcall task_dllmain( task_shellcode_data* Data );
		inline DWORD __declspec( code_seg( ".i_sec$06" ) ) __stdcall task_end_function( );
	}
}