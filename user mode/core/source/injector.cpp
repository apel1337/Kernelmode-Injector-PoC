#include <core/linkers/injector.h>

namespace riot
{
	namespace injector
	{
		template <typename type>
		type c_interface::rva_to_va( DWORD rva ) {
			PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION( m_nt_headers );
			for ( int i = 0; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
				PIMAGE_SECTION_HEADER section = &first_section[ i ];

				if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData ) {
					return type( ( ULONG_PTR ) m_target_image.data( ) + ( ULONG_PTR ) section->PointerToRawData + ( ( ULONG_PTR ) rva - ( ULONG_PTR ) section->VirtualAddress ) );
				}
			}

			return type( 0 );
		}

		std::uintptr_t c_interface::get_export( LPCSTR module_name , LPCSTR function_name ) {
			auto module_handle = LoadLibraryExA( module_name , NULL , DONT_RESOLVE_DLL_REFERENCES );
			auto export_address = reinterpret_cast<std::uint64_t> ( GetProcAddress( module_handle , function_name ) ) - ULONGLONG( module_handle );
			FreeLibrary( module_handle );
			return export_address;
		}

		std::size_t c_interface::get_ic_size( void* ic )
		{
			std::size_t ic_size = 0;
			for ( std::uint8_t* i = static_cast< std::uint8_t* >( ic ); ic_size == 0; i += 1 )
			{
				if ( i[ 0 ] == 0xCC && i[ 1 ] == 0xCC && i[ 2 ] == 0xcc && i[ 3 ] == 0xCC )
					ic_size = static_cast< std::size_t >( i - static_cast< std::uint8_t* >( ic ) );
			}

			return ic_size;
		}

		bool c_interface::resolve_imports( ) {
			auto resolve_function( [ & ] ( LPCSTR module_name , LPCSTR function_name , uintptr_t* function_address ) {
				auto module_handle = LoadLibraryExA( module_name , NULL , DONT_RESOLVE_DLL_REFERENCES );
				if ( !module_handle || module_handle == INVALID_HANDLE_VALUE )
					return false;

				*function_address = ULONGLONG( GetProcAddress( module_handle , function_name ) ) - ULONGLONG( module_handle );
				FreeLibrary( module_handle );
				return bool( *function_address ); } );

			auto import_descriptor = rva_to_va<PIMAGE_IMPORT_DESCRIPTOR>( m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
			if ( !m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress ||
				!m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size ) {
				return false;
			}

			LPSTR module_name = 0;
			while ( module_name = rva_to_va<LPSTR>( import_descriptor->Name ) )
			{
				auto module_handle = uintptr_t( LoadLibraryA( module_name ) );
				if ( !module_handle ) {
					return false;
				}

				auto first_thunk = rva_to_va<PIMAGE_THUNK_DATA>( import_descriptor->FirstThunk );
				while ( first_thunk->u1.AddressOfData )
				{
					if ( first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
					{
						uintptr_t function_address = 0;
						if ( !resolve_function( module_name , LPSTR( first_thunk->u1.Ordinal & 0xFFFF ) , &function_address ) ) {
							printf( encrypt( " > failed to resolve import : (function : %s)\n" ) , LPSTR( first_thunk->u1.Ordinal & 0xFFFF ) );
						}

						first_thunk->u1.Function = function_address;
					}
					else
					{
						auto ibn = rva_to_va<PIMAGE_IMPORT_BY_NAME>( first_thunk->u1.AddressOfData );

						uintptr_t function_address = 0;
						if ( !resolve_function( module_name , LPSTR( ibn->Name ) , &function_address ) ) {
							printf( encrypt( " > failed to resolve import : (function : %s)\n" ) , LPSTR( ibn->Name ) );
						}

						first_thunk->u1.Function = uintptr_t( m_target_image.data( ) ) + function_address;
					}

					first_thunk++;
				}

				import_descriptor++;
			}

			return true;
		}

		bool c_interface::write_sections( uintptr_t mapped_memory ) {
			auto section = IMAGE_FIRST_SECTION( m_nt_headers );
			for ( auto i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i , ++section ) {
				auto section_size = min( section->SizeOfRawData , section->Misc.VirtualSize );
				if ( !section_size ) {
					continue;
				}

				auto mapped_section = ULONGLONG( mapped_memory ) + section->VirtualAddress;
				auto section_buffer = PVOID( ULONGLONG( m_target_image.data( ) ) + section->PointerToRawData );

				printf( encrypt( " > exporting section %s from %p\n" ) , section->Name , section_buffer );

				driver_ctx.write( mapped_section , section_buffer );
			}

			return true;
		}

		bool c_interface::relocate_image( uintptr_t mapped_memory ) {
			struct relocation_entry
			{
				ULONG to_rva;
				ULONG size;

				struct
				{
					WORD offset : 12;
					WORD type : 4;
				} item[ 1 ];
			};

			uintptr_t delta_offset = mapped_memory - m_nt_headers->OptionalHeader.ImageBase;
			if ( !delta_offset ) {
				printf( encrypt( " > image is already relocated.\n" ) );
				return false;
			}
			else if ( !( m_nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) ) {
				printf( encrypt( " > image is not relocatable!\n" ) );
			}

			auto base_directory_relocation = m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
			if ( !base_directory_relocation.VirtualAddress ) {
				return false;
			}

			relocation_entry* relocation = rva_to_va<relocation_entry*>( base_directory_relocation.VirtualAddress );
			uintptr_t relocation_end = ( uintptr_t ) relocation + base_directory_relocation.Size;

			if ( !relocation ) {
				printf( encrypt( " > failed to relocate image.\n" ) );
				return true;
			}

			while ( ( uintptr_t ) relocation < relocation_end && relocation->size )
			{
				DWORD records_count = ( relocation->size - 8 ) >> 1;

				for ( DWORD i = 0; i < records_count; i++ )
				{
					WORD fix_type = ( relocation->item[ i ].type );
					WORD shift_delta = ( relocation->item[ i ].offset ) % 4096;
					if ( fix_type == IMAGE_REL_BASED_ABSOLUTE )
						continue;

					if ( fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64 )
					{
						uintptr_t fix_va = rva_to_va<uintptr_t>( relocation->to_rva );

						if ( !fix_va )
							fix_va = ( uintptr_t ) m_target_image.data( );

						*( uintptr_t* ) ( fix_va + shift_delta ) += delta_offset;
					}
				}

				relocation = ( relocation_entry* ) ( ( LPBYTE ) relocation + relocation->size );
			}

			return true;
		}

		bool c_interface::setup_target_image( ) {
			m_dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( m_target_image.data( ) );
			if ( m_dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
				printf( encrypt( " > failed to retrieve dos header.\n" ) );
				return false;
			}

			m_nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >( m_target_image.data( ) + m_dos_header->e_lfanew );
			if ( m_nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
				printf( encrypt( " > failed to retrieve nt headers.\n" ) );
				return false;
			}

			return true;
		}

		void c_interface::load_file( const std::string& file , std::vector<uint8_t>& data ) {
			std::ifstream fstr( file , std::ios::binary );
			fstr.unsetf( std::ios::skipws );
			fstr.seekg( 0 , std::ios::end );

			const auto file_size = fstr.tellg( );

			fstr.seekg( NULL , std::ios::beg );
			data.reserve( static_cast< uint32_t >( file_size ) );
			data.insert( data.begin( ) , std::istream_iterator<uint8_t>( fstr ) , std::istream_iterator<uint8_t>( ) );
		}

		void c_interface::set_target_image( std::vector<uint8_t> buffer )
		{
			m_target_image = buffer;
		}

		bool c_interface::enable_exceptions( uintptr_t module_base ) {
			const auto& status = section::load_ntdll_functions( );
			if ( !status ) {
				printf( encrypt( " > failed load ntdll functions.\n" ) );
				return false;
			}

			auto process_handle = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ , false , driver_ctx.get_process_pid( ) );
			if ( !process_handle ) {
				printf( encrypt( " > failed to open process.\n" ) );
			}

			auto hwnd = std::shared_ptr<HANDLE>( new HANDLE( process_handle ) , [ ] ( HANDLE* Hwnd ) { CloseHandle( *Hwnd ); } );

			if ( this->m_mod_table == NULL ) {
				const auto& [mod_table, status] = driver_ctx.allocate_virtual( 0x1000 , MEM_RESERVE | MEM_COMMIT , PAGE_READWRITE );
				if ( !mod_table || status != nt_status_t::success )
				{
					printf( encrypt( " > failed to allocate veh module list.\n" ) );
					return false;
				}
				this->m_mod_table = mod_table;
			}

			printf( encrypt( " > veh module table : %llx\n" ) , this->m_mod_table );

			instrum::module_table table { };
			if ( !driver_ctx.read_virtual( this->m_mod_table , &table , sizeof( table ) ) )
			{
				printf( encrypt( " > failed to read veh module list.\n" ) );
				return false;
			}

			table.entry[ table.count ].base = module_base;
			table.entry[ table.count ].size = 0x1000;
			table.count++;

			if ( !driver_ctx.write_virtual( this->m_mod_table , &table , sizeof( table ) ) )
			{
				printf( encrypt( " > failed to write veh module list.\n" ) );
				return false;
			}

			auto replace_stub = [ ] ( uint8_t* ptr , size_t size , auto old_value , auto new_value )
				{
					using value_pointer = std::add_pointer_t<decltype( old_value )>;

					for ( auto data = ptr; data < ptr + size - sizeof( old_value ); data++ )
					{
						if ( *reinterpret_cast< value_pointer >( data ) == old_value )
						{
							*reinterpret_cast< value_pointer >( data ) = new_value;
							return true;
						}
					}

					return false;
				};

			auto shell_section = std::make_unique<section::c_interface>( sizeof( _handler64 ) );
			if ( !shell_section->create( ) ) return false;
			if ( !shell_section->map_view( GetCurrentProcess( ) , PAGE_READWRITE ) ) return false;
			if ( !shell_section->map_view( *hwnd , PAGE_EXECUTE_READWRITE ) ) return false;

			memcpy( shell_section->get_local_address( ) , _handler64 , sizeof( _handler64 ) );
			replace_stub( reinterpret_cast< std::uint8_t* >( shell_section->get_local_address( ) ) , sizeof( _handler64 ) , 0xDEADBEEFDEADBEEF , this->m_mod_table );
			replace_stub( reinterpret_cast< std::uint8_t* >( shell_section->get_local_address( ) ) , sizeof( _handler64 ) , 0xDEADBEEFDEADBEEF , this->m_mod_table + sizeof( std::uintptr_t ) );

			this->veh_code = shell_section->get_remote_address( );
			printf( encrypt( " > VEH written : %llx\n" ) , shell_section->get_remote_address( ) );

			return true;
		}

		bool c_interface::prepare_injection( ) {
			bool status = this->setup_target_image( );
			if ( !status ) {
				printf( encrypt( " > failed to setup target image.\n" ) );
				return status;
			}

			const auto& image_size = m_nt_headers->OptionalHeader.SizeOfImage;
			printf( encrypt( " > attempting to map image of size : 0x%zx\n" ) , image_size );

			const auto& [virtual_memory_base , mapping_status] = driver_ctx.allocate_virtual( image_size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
			if ( !virtual_memory_base || mapping_status != nt_status_t::success ) {
				printf( encrypt( " > failed to allocate virtual memory (status : %i) : %llx\n" ) , mapping_status , virtual_memory_base );
				driver_ctx.flush_logs( );
				return false;
			}
			
			//const auto& [virtual_memory_base , mapping_status] = driver_ctx.create_allocation( image_size );
			//if ( !virtual_memory_base || mapping_status != nt_status_t::success ) {
			//	printf( encrypt( " > failed to retrieve physical mapping. %i\n" ) , mapping_status );
			//	return false;
			//}

			//if ( auto mapping = driver_ctx.find_mapping( virtual_memory_base ) ) {
			//	printf( encrypt( " > total mapped (0x%zx), page type (%s)\n" ) , mapping->mapped_size ,
			//		mapping->is_1gb_mapping ? "1GB" : "2MB" );
			//}

			printf( encrypt( " > virtual memory base : %llx\n" ) , virtual_memory_base );
			printf( encrypt( "..............................................\n" ) );
			Sleep( 250 );

			printf( encrypt( "resolving imports...\n" ) );
			status = resolve_imports( );
			if ( !status ) {
				printf( encrypt( " > failed to resolve imports.\n" ) );
				return status;
			}

			printf( encrypt( "relocating image...\n" ) );
			status = relocate_image( virtual_memory_base );
			if ( !status ) {
				printf( encrypt( " > failed to relocate image.\n" ) );
				return status;
			}

			printf( encrypt( " > old entry point : %lu\n" ) , m_nt_headers->OptionalHeader.AddressOfEntryPoint );
			printf( encrypt( " > new entry point : %llu\n" ) , virtual_memory_base + m_nt_headers->OptionalHeader.AddressOfEntryPoint );

			printf( encrypt( "copying image sections...\n" ) );
			status = write_sections( virtual_memory_base );
			if ( !status ) {
				printf( encrypt( " > failed to copy image sections.\n" ) );
				return status;
			}

			printf( encrypt( "creating veh for c++ exceptions...\n" ) );
			status = enable_exceptions( virtual_memory_base );
			if ( !status ) {
				printf( encrypt( " > failed to enable exceptions.\n" ) );
				return status;
			}

			printf( encrypt( "..............................................\n" ) );
			printf( encrypt( "creating instrumentation callback...\n" ) );
			Sleep( 250 );

			auto instrumentation_callback = &instrumentation_callbacktwo;

			std::size_t shellcode_size = reinterpret_cast< std::uintptr_t >( &end_function ) - reinterpret_cast< std::uintptr_t >( &internal_handler );
			auto set_shell_size = shellcode_size;
			auto max_shell_size = shellcode_size + sizeof( instrum::function_table ) + sizeof( instrum::shellcode_data );

			auto set_ic_size = get_ic_size( instrumentation_callback );
			const std::size_t total_size = set_ic_size + max_shell_size;

			printf( encrypt( " > instrumentation callback size : %llx\n" ) , set_ic_size );
			printf( encrypt( " > instrumentation shellcode size : %llx\n" ) , set_shell_size );

			const auto& [ic_base_address , nt_status] = driver_ctx.allocate_virtual( total_size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
			if ( !ic_base_address || nt_status != nt_status_t::success ) {
				printf( encrypt( " > failed to allocate virtual memory (status : %i) : %llx\n" ) , nt_status , ic_base_address );
				driver_ctx.flush_logs( );
				return false;
			}

			//const auto& [ic_base_address , ic_status] = driver_ctx.create_allocation( total_size );
			//if ( !ic_base_address || ic_status != nt_status_t::success ) {
			//	printf( encrypt( " > failed to retrieve physical mapping base. %i\n" ) , mapping_status );
			//	return false;
			//}

			//if ( auto mapping = driver_ctx.find_mapping( ic_base_address ) ) {
			//	printf( encrypt( " > total mapped (0x%zx), page type (%s)\n" ) , mapping->mapped_size ,
			//		mapping->is_1gb_mapping ? "1GB" : "2MB" );
			//}

			printf( encrypt( " > ic base address : %llx\n" )  , ic_base_address );

			auto ic_start = ic_base_address + 4;
			auto shellcode_start = reinterpret_cast< void* >( ic_base_address + total_size );
			auto shelldata_start = reinterpret_cast< instrum::shellcode_data* >( ic_base_address + set_ic_size + shellcode_size );

			auto function_table = reinterpret_cast< instrum::function_table* >( ic_base_address + set_ic_size + shellcode_size + sizeof( instrum::shellcode_data ) );
			instrum::function_table func_table { };

			if ( !driver_ctx.write_virtual( ic_base_address + set_ic_size + shellcode_size + sizeof( instrum::shellcode_data ) , &func_table , sizeof( instrum::function_table ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			auto shell_data = reinterpret_cast< instrum::shellcode_data* >( ic_base_address + set_ic_size + shellcode_size );
			instrum::shellcode_data temp_shell_data( function_table );
			temp_shell_data.m_ic_base_address = ic_base_address;
			temp_shell_data.m_ic_size = total_size;
			temp_shell_data.m_old_ic_address = 0;

			if ( !driver_ctx.write_virtual( ic_base_address + set_ic_size + shellcode_size , &temp_shell_data , sizeof( instrum::shellcode_data ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			std::unique_ptr<byte[ ]> temp_hold( new byte[ set_ic_size + 1 ] );
			memcpy( temp_hold.get( ) , instrumentation_callback , set_ic_size );
			*reinterpret_cast< std::uint32_t* >( temp_hold.get( ) ) = 0;

			int tick = 1;
			for ( byte* i = temp_hold.get( ); i != &temp_hold.get( )[ set_ic_size ]; i++ )
			{
				if ( *reinterpret_cast< std::uint64_t* >( i ) == 0x7fffffffffff )
				{
					if ( tick )
					{
						printf( encrypt( " > swapped out shellcode data in instrumentation callback\n" ) );
						*reinterpret_cast< instrum::shellcode_data** >( i ) = shell_data;
						break;
					}
					else
					{
						printf( encrypt( " > swapped out instrumentation callback address in callback\n" ) );
						*reinterpret_cast< std::uintptr_t* >( i ) = 0;
						tick++;
					} 
				}
			}

			if ( !driver_ctx.write_virtual( ic_base_address , temp_hold.get( ) , set_ic_size ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			printf( encrypt( " > written instrumentation callback into memory.\n" ) );

			if ( !driver_ctx.write_virtual( ic_base_address + set_ic_size , &internal_handler , shellcode_size ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			printf( encrypt( " > written shellcode into memory\n" ) );

			// stinky
			this->m_set_ic_size = set_ic_size;
			this->m_set_shell_size = set_shell_size;
			this->m_max_shell_size = max_shell_size;
			this->m_inject_address = virtual_memory_base;
			this->m_ic_base_address = ic_base_address;
			this->m_ic_start = ic_start;

			std::getchar( );
			return true;
		}

		bool c_interface::call_dll_main( ) {

			// roka likes lil boys
			// children 🤤🤤🤤

			// sUNC leak 2025 is realllll

			system( encrypt( "cls" ) );
			printf( encrypt( "=== Riot Execution :: injector::c_interface::call_dll_main() ===\n" ) );
			printf( encrypt( "......................................................................\n" ) );
			printf( encrypt( "preparing task shellcode for execution...\n" ) );
			Sleep( 250 );

			const std::size_t& shellcode_size = reinterpret_cast< std::uintptr_t >( &task_end_function ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler );
			const std::size_t& total_size = reinterpret_cast< std::uintptr_t >( &task_end_function ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler ) + sizeof( instrum::shellcode_data ) + sizeof( instrum::function_table );

			const auto& [allocation_base , nt_status] = driver_ctx.allocate_virtual( total_size , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE );
			if ( !allocation_base || nt_status != nt_status_t::success ) {
				printf( encrypt( " > failed to allocate virtual memory (status : %i) : %llx\n" ) , nt_status , allocation_base );
				driver_ctx.flush_logs( );
				return false;
			}

			//const auto& [allocation_base , mapping_status] = driver_ctx.create_allocation( total_size );
			//if ( !allocation_base || mapping_status != nt_status_t::success ) {
			//	printf( encrypt( " > failed to retrieve physical mapping. %i\n" ) , mapping_status );
			//	return false;
			//}

			//if ( auto mapping = driver_ctx.find_mapping( allocation_base ) ) {
			//	printf( encrypt( " > total mapped (0x%zx), page type (%s)\n" ) , mapping->mapped_size ,
			//		mapping->is_1gb_mapping ? "1GB" : "2MB" );
			//}

			if ( !driver_ctx.write_virtual( allocation_base , &task_internal_handler , shellcode_size ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			auto shellcode_data = reinterpret_cast< instrum::shellcode_data* >( allocation_base + shellcode_size );
			auto function_table = reinterpret_cast< instrum::function_table* >( allocation_base + shellcode_size + sizeof( instrum::shellcode_data ) );

			auto temp_shellcode_data = task_shellcode_data { 
				this->m_inject_address ,
				( std::uintptr_t ) this->m_nt_headers->OptionalHeader.AddressOfEntryPoint ,
				driver_ctx.get_process_pid( ) ,
				this->veh_code ,
				( void* ) this->m_mod_table };
			if ( !driver_ctx.write_virtual( allocation_base + shellcode_size , &temp_shellcode_data , sizeof( instrum::shellcode_data ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			auto temp_function_table = task_function_table{ allocation_base };
			if ( !driver_ctx.write_virtual( allocation_base + shellcode_size + sizeof( instrum::shellcode_data ) , &temp_function_table , sizeof( instrum::function_table ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			printf( encrypt( " > updating and running task shellcode.\n" ) );

			auto temp_shell_data = std::make_unique<instrum::shellcode_data>( nullptr );
			if ( !driver_ctx.read_virtual( this->m_ic_base_address + m_set_ic_size + m_set_shell_size , temp_shell_data.get( ) , sizeof( instrum::shellcode_data ) ) )
			{
				printf( encrypt( " > failed to read virtual memory.\n" ) );
				return false;
			}

			temp_shell_data->m_shell_return = 0xDEADBEEF;
			temp_shell_data->m_task_address = allocation_base;
			temp_shell_data->m_task_data = reinterpret_cast< std::uintptr_t >( shellcode_data );
			temp_shell_data->m_task_size = total_size;
			temp_shell_data->m_first = true;

			if ( !driver_ctx.write_virtual( this->m_ic_base_address + m_set_ic_size + m_set_shell_size , temp_shell_data.get( ) , sizeof( instrum::shellcode_data ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			std::uint32_t key = 1;
			if ( !driver_ctx.write_virtual( this->m_ic_base_address , &key , sizeof( instrum::shellcode_data ) ) )
			{
				printf( encrypt( " > failed to write virtual memory.\n" ) );
				return false;
			}

			printf( encrypt( " > enabling instrumentation callback.\n" ) );

			const auto& instrum_status = driver_ctx.create_instrumentation_callback( this->m_ic_start );
			if ( instrum_status != nt_status_t::success )
			{
				printf( encrypt( " > failed to enable instrumentation callback : %i\n" ) , instrum_status );
				return false;
			}

			printf( encrypt( " > instrumentation callback applied, waiting for task to run.\n" ) );

			DWORD shell_return = 0xDEADBEEF; // mashallah cartyboy
			while ( shell_return == 0xDEADBEEF )
			{
				Sleep( 200 );
				if ( !driver_ctx.read_virtual( this->m_ic_base_address + this->m_set_ic_size + this->m_set_shell_size + offsetof( instrum::shellcode_data , m_shell_return ) , &shell_return , sizeof( DWORD ) ) )
				{
					printf( encrypt( " > failed to read virtual memory.\n" ) );
					return false;
				}
			}

			printf( encrypt( " > shellcode return : %i\n" ) , shell_return );

			printf( encrypt( "=== Riot Execution :: entrypoint ===\n" ) );
			printf( encrypt( "...................................................................\n" ) );
			return true;
		}

		inline DWORD __declspec( code_seg( ".t_sec$01" ) ) __stdcall internal_handler( instrum::shellcode_data* data , PCONTEXT context )
		{
			MessageBoxA( 0 , 0 , 0 , 0 );

			const auto& func_table = reinterpret_cast< instrum::function_table* >( data->m_function_table );
			auto teb_pointer = reinterpret_cast< teb_t* >( NtCurrentTeb( ) );

			context->Rip = teb_pointer->InstrumentationCallbackPreviousPc;
			context->Rsp = teb_pointer->InstrumentationCallbackPreviousSp;
			context->Rcx = context->R10;

			data->m_work = func_table->aCreateThreadpoolWork( reinterpret_cast< PTP_WORK_CALLBACK >( data->m_task_address ) , ( PVOID ) data->m_task_data , nullptr );
			if ( data->m_work )
			{
				func_table->aSubmitThreadpoolWork( data->m_work );
				data->m_shell_return = 0;
			}
			else
				data->m_shell_return = 101;
			func_table->aRtlRestoreContext( context , nullptr );
			return 0;
		}

		inline DWORD __declspec( code_seg( ".t_sec$02" ) ) __stdcall end_function( )
		{
			MessageBoxA( 0 , 0 , 0 , 0 );

			return 1337;
		}

		task_function_table::task_function_table( std::uintptr_t base_address )
		{
			fcookies = reinterpret_cast< f_internal_func >( ( reinterpret_cast< std::uintptr_t >( &task_cookies ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler ) ) + base_address );
			fexceptions = reinterpret_cast< f_internal_func >( ( reinterpret_cast< std::uintptr_t >( &task_exceptions ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler ) ) + base_address );
			ftls_callbacks = reinterpret_cast< f_internal_func >( ( reinterpret_cast< std::uintptr_t >( &task_tls_callbacks ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler ) ) + base_address );
			fdll_main = reinterpret_cast< f_internal_func >( ( reinterpret_cast< std::uintptr_t >( &task_dllmain ) - reinterpret_cast< std::uintptr_t >( &task_internal_handler ) ) + base_address );
			
			auto ntdll = GetModuleHandleA( encrypt( "ntdll.dll" ) );
			if ( !ntdll ) return;

			auto kernel32 = GetModuleHandleA( encrypt( "kernel32.dll" ) );
			if ( !kernel32 ) return;

			LdrLockLoaderLock = reinterpret_cast< f_LdrLockLoaderLock >(
				GetProcAddress( ntdll , encrypt( "LdrLockLoaderLock" ) ) );
			LdrUnlockLoaderLock = reinterpret_cast< f_LdrUnlockLoaderLock >(
				GetProcAddress( ntdll , encrypt( "LdrUnlockLoaderLock" ) ) );
			RtlAllocateHeap = reinterpret_cast< f_RtlAllocateHeap >(
				GetProcAddress( ntdll , encrypt( "RtlAllocateHeap" ) ) );
			RtlFreeHeap = reinterpret_cast< f_RtlFreeHeap >(
				GetProcAddress( ntdll , encrypt( "RtlFreeHeap" ) ) );
			LdrpHandleTlsData = reinterpret_cast< f_LdrpHandleTlsData >(
				GetProcAddress( ntdll , encrypt( "LdrpHandleTlsData" ) ) );
			LdrpTlsList = reinterpret_cast< LIST_ENTRY* >(
				GetProcAddress( ntdll , encrypt( "LdrpTlsList" ) ) );
			RtlAddFunctionTable = reinterpret_cast< f_RtlAddFunctionTable >(
				GetProcAddress( ntdll , encrypt( "RtlAddFunctionTable" ) ) );
			LdrpInvertedFunctionTable = reinterpret_cast< RTL_INVERTED_FUNCTION_TABLE* >(
				GetProcAddress( ntdll , encrypt( "KiUserInvertedFunctionTable" ) ) );
			RtlInsertInvertedFunctionTable = reinterpret_cast< f_RtlInsertInvertedFunctionTable >(
				GetProcAddress( ntdll , encrypt( "RtlInsertInvertedFunctionTable" ) ) );
			RtlAddVectoredExceptionHandler = reinterpret_cast< f_RtlAddVectoredExceptionHandler >(
				GetProcAddress( ntdll , encrypt( "RtlAddVectoredExceptionHandler" ) ) );
			NtAllocateVirtualMemory = reinterpret_cast< f_NtAllocateVirtualMemory >(
				GetProcAddress( ntdll , encrypt( "NtAllocateVirtualMemory" ) ) );
			LdrProtectMrdata = reinterpret_cast< f_LdrProtectMrdata >(
				GetProcAddress( ntdll , encrypt( "LdrProtectMrdata" ) ) );
			aGetCurrentThreadId = reinterpret_cast< f_GetCurrentThreadId >(
				GetProcAddress( kernel32 , encrypt( "GetCurrentThreadId" ) ) );
		}

		DWORD __declspec( code_seg( ".i_sec$01" ) ) __stdcall task_internal_handler( PTP_CALLBACK_INSTANCE instance , task_shellcode_data* data , PTP_WORK work )
		{
			MessageBoxA( 0 , 0 , 0 , 0 );
			printf( encrypt( " > running task internal handler.\n" ) );

			const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( data->base_address );
			data->nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS64* >( reinterpret_cast< const std::uint8_t* >( dos_header ) + dos_header->e_lfanew );
			data->optional_header = &data->nt_headers->OptionalHeader;
			const auto& f = data->functions;
			data->cookies_return = f->fcookies( data );
			data->exception_return = f->fexceptions( data );
			data->tls_return = f->ftls_callbacks( data );
			data->dllmain_return = f->fdll_main( data );
			return 0;
		}

		DWORD __declspec( code_seg( ".i_sec$02" ) ) __stdcall task_cookies( task_shellcode_data* data )
		{
			auto pLoadConfig32 = reinterpret_cast< PIMAGE_LOAD_CONFIG_DIRECTORY32 >( data->base_address + data->optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ].VirtualAddress );
			auto pLoadConfig64 = reinterpret_cast< PIMAGE_LOAD_CONFIG_DIRECTORY64 >( pLoadConfig32 );
			if ( !pLoadConfig32 )
				return STATUS_SUCCESS;
			std::uintptr_t pCookie = pLoadConfig64->SecurityCookie;
			if ( !pCookie )
				return STATUS_SUCCESS;

			std::uintptr_t cookie = data->process_pid ^ data->functions->aGetCurrentThreadId( ) ^ reinterpret_cast< uintptr_t >( &cookie );
			cookie ^= *reinterpret_cast< uint64_t* >( &data->system_time );
			cookie ^= ( data->performence_count.QuadPart << 32 ) ^ data->performence_count.QuadPart;
			cookie &= 0xFFFFFFFFFFFF;
			if ( cookie == 0x2B992DDFA232 )
				cookie++;
			pLoadConfig64->SecurityCookie = cookie;
			return 0;
		}

		DWORD __declspec( code_seg( ".i_sec$03" ) ) __stdcall task_exceptions( task_shellcode_data* data )
		{
			auto f = data->functions;

			bool Inserted = false;
			auto table = f->LdrpInvertedFunctionTable;
			for ( ULONG i = 0; i < table->Count; i++ )
			{
				if ( table->Entries[ i ].ImageBase == ( void* ) data->base_address )
				{
					Inserted = true;
					break;
				}
			}
			if ( !Inserted )
			{
				f->RtlInsertInvertedFunctionTable( ( void* ) data->base_address , data->optional_header->SizeOfImage );
				for ( DWORD i = 0; i < table->Count; i++ )
				{
					if ( table->Entries[ i ].ImageBase != ( void* ) data->base_address )
						continue;
					if ( table->Entries[ i ].SizeOfTable )
					{
						data->safe_seh = true;
						data->mod_table->count--;
						Inserted = true;
						break;
					}
					//SIZE_T FakeDirSize = 0x800 * sizeof( void* );
					//if ( NT_FAIL( f->NtAllocateVirtualMemory( NtCurrentProcess( ) , &data->fake_seh_directory , 0 , &FakeDirSize , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE ) ) )
					//	break;

					UINT_PTR pRaw = reinterpret_cast< UINT_PTR >( data->fake_seh_directory );
					auto cookie = *P_KUSER_SHARED_DATA_COOKIE;
					UINT_PTR pEncoded = bit_rotate_r( cookie ^ pRaw , cookie & 0x3F );
					f->LdrProtectMrdata( FALSE );
					table->Entries[ i ].ExceptionDirectory = reinterpret_cast< IMAGE_RUNTIME_FUNCTION_ENTRY* >( pEncoded );
					f->LdrProtectMrdata( TRUE );
					Inserted = true;
					break;
				}
			}
			if ( !Inserted )
			{
				//on x64 also try documented method
				auto size = data->optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ].Size;
				if ( size )
				{
					auto* pExceptionHandlers = reinterpret_cast< RUNTIME_FUNCTION* >( data->base_address + data->optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ].VirtualAddress );
					auto EntryCount = size / sizeof( RUNTIME_FUNCTION );
					if ( !f->RtlAddFunctionTable( pExceptionHandlers , MDWD( EntryCount ) , data->base_address ) )
					{
						return INTERNALS_FAILED_TO_ACTIVATE_SEH_EXCEPTIONS;
					}
				}
				else
				{
					return INTERNALS_FAILED_TO_ACTIVATE_SEH_EXCEPTIONS;
				}
			}
			//if (!data->Dependency)
			//{
			//    f->RtlAddVectoredExceptionHandler(0, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(data->VEHCode));
			//}
			return 0;
		}

		DWORD __declspec( code_seg( ".i_sec$04" ) ) __stdcall task_tls_callbacks( task_shellcode_data* data )
		{
			if ( !data->optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].Size )
				return STATUS_SUCCESS;
			auto f = data->functions;

			auto* pTLS = reinterpret_cast< IMAGE_TLS_DIRECTORY* >( data->base_address + data->optional_header->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress );

			auto* pDummyLdr = reinterpret_cast< LDR_DATA_TABLE_ENTRY* >( f->RtlAllocateHeap( instrum::nt_current_peb( )->ProcessHeap , HEAP_ZERO_MEMORY , sizeof( LDR_DATA_TABLE_ENTRY ) * 1 ) );
			if ( !pDummyLdr )
				return INTERNALS_FAILED_TO_ALLOC_HEAP_FOR_DUMMY_LDR;
			pDummyLdr->DllBase = ( BYTE* ) data->base_address;

			f->LdrpHandleTlsData( pDummyLdr );
			auto* pCallback = reinterpret_cast< PIMAGE_TLS_CALLBACK* >( pTLS->AddressOfCallBacks );
			for ( ; pCallback && ( *pCallback ); ++pCallback )
			{
				auto Callback = *pCallback;
				Callback( ( BYTE* ) data->base_address , DLL_PROCESS_ATTACH , nullptr );
			}

			auto current = f->LdrpTlsList->Flink;
			while ( current != f->LdrpTlsList )
			{
				auto entry = reinterpret_cast< TLS_ENTRY* >( current );
				if ( entry->ModuleEntry == pDummyLdr )
				{
					entry->ModuleEntry = nullptr;

					break;
				}

				current = current->Flink;
			}

			f->RtlFreeHeap( instrum::nt_current_peb( )->ProcessHeap , NULL , pDummyLdr );
			return 0;
		}

		DWORD __declspec( code_seg( ".i_sec$05" ) ) __stdcall task_dllmain( task_shellcode_data* data )
		{
			if ( !data->entry_point )
				return 0;
			instrum::f_DLL_ENTRY_POINT DllMain = reinterpret_cast< instrum::f_DLL_ENTRY_POINT >( data->base_address + data->entry_point );
			ULONG		State = 0;
			ULONG_PTR	Cookie = 0;
			bool		locked = NT_SUCCESS( data->functions->LdrLockLoaderLock( NULL , &State , &Cookie ) );
			DWORD Ret = DllMain( reinterpret_cast< HINSTANCE >( data->base_address ) , DLL_PROCESS_ATTACH , nullptr );
			if ( locked )
				data->functions->LdrUnlockLoaderLock( NULL , Cookie );
			return Ret;
		}

		DWORD __declspec( code_seg( ".i_sec$06" ) ) __stdcall task_end_function( )
		{
			return 1337;
		}
	}
}