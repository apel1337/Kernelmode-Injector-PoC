#include <core/driver/driver.hpp>
#include <thread>
#include <chrono>
#include <winternl.h>

namespace riot
{
	namespace driver
	{
		bool c_interface::setup( )
		{
			memory_buffer = VirtualAlloc(
				nullptr ,
				sizeof( server::request_data ) ,
				MEM_COMMIT ,
				PAGE_READWRITE
			);
			if ( !memory_buffer ) {
				return false;
			}

			log_buffer = VirtualAlloc(
				nullptr ,
				sizeof( server::log_entry_t ) * max_messages ,
				MEM_COMMIT ,
				PAGE_READWRITE
			);
			if ( !log_buffer ) {
				return false;
			}

			bool status = create_value( encrypt( "log_array" ) , log_buffer );
			if ( !status ) {
				return false;
			}

			status = create_value( encrypt( "buffer" ) , memory_buffer );
			if ( !status ) {
				return false;
			}

			status = create_value( encrypt( "client_id" ) , GetCurrentProcessId( ) );
			if ( !status ) {
				return false;
			}

			server::request_data request{ };
			request.is_client_running = true;
			std::memcpy( memory_buffer , &request , sizeof( request ) );
			return true;
		}

		void c_interface::flush_logs( )
		{
			auto log_array = 
				reinterpret_cast< server::log_entry_t* >( log_buffer );
			if ( !log_array ) {
				printf( encrypt( " > failed to retrieve log buffer.\n" ) );
				return;
			}

			for ( std::uint32_t idx = 0; idx < max_messages; idx++ )
			{
				if ( !log_array[ idx ].present ) {
					continue;
				}

				printf( encrypt( " > %s\n" ) , log_array[ idx ].payload );
			}

			memset( log_buffer , 0 , max_messages * sizeof( server::log_entry_t ) );
		}

		template <typename type>
		bool c_interface::create_value( const char* value_name , type request )
		{
			HKEY handle_key = 0;
			auto result = RegCreateKeyExA( HKEY_LOCAL_MACHINE , key_path , 0 , nullptr , REG_OPTION_NON_VOLATILE , KEY_SET_VALUE , nullptr , &handle_key , nullptr );
			if ( result != ERROR_SUCCESS ) {
				return false;
			}

			result = RegSetValueExA( handle_key , value_name , 0 , REG_QWORD , reinterpret_cast< const BYTE* >( &request ) , sizeof( request ) );
			if ( result != ERROR_SUCCESS ) {
				return false;
			}

			RegCloseKey( handle_key );
			return true;
		}

		void c_interface::send_cmd( server::request_data& request )
		{
			std::memcpy( memory_buffer , &request , sizeof( request ) );

			server::request_data* out_request = reinterpret_cast< server::request_data* >( memory_buffer );
			while ( !out_request->is_operation_completed ) {
				std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
			}

			request = *out_request;
		}

		bool c_interface::read_virtual( uintptr_t address , void* buffer , size_t size )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = address;
			request.buffer = buffer;
			request.size = size;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::read_virtual;

			send_cmd( request );

			return request.operation_status == nt_status_t::success;
		}

		bool c_interface::write_virtual( uintptr_t address , void* buffer , size_t size )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = address;
			request.buffer = buffer;
			request.size = size;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::write_virtual;

			send_cmd( request );

			return request.operation_status == nt_status_t::success;
		}

		bool c_interface::read_physical_km( uintptr_t address , void* buffer , size_t size )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.buffer = buffer;
			request.size = size;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::read_physical;

			send_cmd( request );

			return request.operation_status == nt_status_t::success;
		}

		bool c_interface::write_physical_km( uintptr_t address , void* buffer , size_t size )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.buffer = buffer;
			request.size = size;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::write_physical;

			send_cmd( request );

			return request.operation_status == nt_status_t::success;
		}

		const std::uintptr_t c_interface::get_kernel_export( const char* image_name , const char* module_name )
		{
			const auto image_base = get_kernel_image( image_name );
			if ( !image_base ) {
				return 0;
			}

			const auto module = LoadLibraryA( image_name );
			if ( !module ) {
				return 0;
			}

			std::uintptr_t address =
				reinterpret_cast< std::uintptr_t >(
					GetProcAddress(
						module ,
						module_name ) );
			if ( !address ) {
				return 0;
			}

			address = address - reinterpret_cast< std::uintptr_t >( module );
			address = address + image_base;

			FreeLibrary( module );
			return address;
		}

		const std::uintptr_t c_interface::get_kernel_image( const char* module_name )
		{
			void* buffer = nullptr;
			unsigned long buffer_size = 0;

			auto status = NtQuerySystemInformation(
				static_cast< SYSTEM_INFORMATION_CLASS >( SystemModuleInformation ) ,
				buffer ,
				buffer_size ,
				&buffer_size
			);

			while ( status == STATUS_INFO_LENGTH_MISMATCH ) {
				VirtualFree( buffer , NULL , MEM_RELEASE );
				buffer = VirtualAlloc( nullptr , buffer_size , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );
				status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( SystemModuleInformation ) , buffer , buffer_size , &buffer_size );
			}

			if ( !NT_SUCCESS( status ) ) {
				VirtualFree( buffer , NULL , MEM_RELEASE );
				return 0;
			}

			const auto modules = static_cast< PRTL_PROCESS_MODULES >( buffer );
			for ( auto idx = 0u; idx < modules->NumberOfModules; ++idx ) {
				const auto current_module_name = std::string( reinterpret_cast< char* >( modules->Modules[ idx ].FullPathName ) + modules->Modules[ idx ].OffsetToFileName );
				if ( !_stricmp( current_module_name.c_str( ) , module_name ) ) {
					const auto result = reinterpret_cast< uint64_t >( modules->Modules[ idx ].ImageBase );
					VirtualFree( buffer , NULL , MEM_RELEASE );
					return result;
				}
			}

			VirtualFree( buffer , NULL , MEM_RELEASE );
			return 0;
		}

		std::pair<std::uintptr_t , nt_status_t> c_interface::allocate_virtual( size_t size , int flags , int protection )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.size = size;
			request.flags = flags;
			request.protection = protection;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::allocate_virtual;

			send_cmd( request );

			return { reinterpret_cast< uintptr_t >( request.buffer ) , request.operation_status };
		}

		std::pair<std::uintptr_t , nt_status_t> c_interface::protect_virtual( uintptr_t address , size_t size , int protection )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.size = size;
			request.protection = protection;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::protect_virtual;

			std::memcpy( memory_buffer , &request , sizeof( request ) );

			send_cmd( request );

			return { request.protection , request.operation_status };
		}

		void c_interface::free_virtual( uintptr_t address , int flags )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.flags = flags;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::free_virtual;

			send_cmd( request );
		}

		void c_interface::free_physical( uintptr_t address , size_t size )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.size = size;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::free_physical;

			send_cmd( request );
		}

		void c_interface::swap_virtual( uintptr_t source , uintptr_t destination )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = source;
			request.address2 = destination;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::swap_virtual;

			send_cmd( request );
		}

		MEMORY_BASIC_INFORMATION c_interface::query_virtual( uintptr_t address )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.dirbase = get_directory_table_base( );
			request.address = address;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::query_virtual;

			send_cmd( request );

			return request.mbi;
		}

		const std::uintptr_t c_interface::get_text_section( uintptr_t module_base )
		{
			for ( std::uintptr_t idx = 0; ; idx++ ) {
				std::uintptr_t curr_page = module_base + idx * 0x1000;
				if ( !curr_page ) {
					continue;
				}

				auto world = read<uintptr_t>( curr_page + 0x1221B738 );
				if ( !world )
					continue;

				auto level = read<uintptr_t>( world + 0x30 );
				if ( !level )
					continue;

				auto outer_world = read<uintptr_t>( level + 0xc0 );
				if ( outer_world != world )
					continue;

				auto mbi = query_virtual( curr_page );
				printf( "current page : %llx\n" , curr_page );
				printf( "RegionSize : %llu\n" , mbi.RegionSize );
				printf( "BaseAddress : %llx\n" , mbi.BaseAddress );
				printf( "PartitionId : %i\n" , mbi.PartitionId );
				printf( "Protect : %i\n" , mbi.Protect );
				printf( "State : %i\n" , mbi.State );

				return curr_page;

				//auto mbi = query_virtual( curr_page );
				//if ( mbi.RegionSize == 9166848 && mbi.PartitionId == 0 && mbi.Protect == 1 && mbi.State == 4096 )
				//{
				//	return curr_page;
				//}
			}

			return 0;
		}

		const std::uintptr_t c_interface::get_directory_table_base( uintptr_t module_base )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = module_base;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::get_directory_table_base;

			send_cmd( request );

			return request.address2;
		}

		void c_interface::resolve_directory_table_base( uintptr_t module_base )
		{
			for ( ;; ) {
				auto directory_table = get_directory_table_base( module_base );
				{
					std::lock_guard<std::mutex> lock( mutex );
					if ( directory_table != get_directory_table_base( ) )
					{
						dirbase.store( directory_table );
						condition.notify_all( );
					}
				}
				std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
			}
		}

		const std::uintptr_t c_interface::get_directory_table_base( )
		{
			return dirbase.load( );
		}

		const std::uintptr_t c_interface::get_free_2mb_memory_base( )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::get_free_2mb_memory_base;

			send_cmd( request );

			return request.address;
		}

		const std::uintptr_t c_interface::get_free_1gb_memory_base( )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::get_free_1gb_memory_base;

			send_cmd( request );

			return request.address;
		}

		const std::pair<std::uintptr_t , nt_status_t> c_interface::allocate_2mb_fallback( std::size_t aligned_size )
		{
			constexpr std::size_t PAGE_2MB = 0x200000;
			const auto pages_needed = ( aligned_size + PAGE_2MB - 1 ) / PAGE_2MB;
			std::vector<std::uintptr_t> allocated_pages;

			for ( size_t i = 0; i < pages_needed; i++ ) {
				auto page = get_free_2mb_memory_base( );
				if ( !page || page % PAGE_2MB ) {
					printf( encrypt( " > failed to allocate 2MB page %zu of %zu\n" ) , i , pages_needed );
					cleanup_partial_allocation( allocated_pages );
					return { 0, nt_status_t::insufficient_resources };
				}
				allocated_pages.push_back( page );
			}

			auto virtual_memory_base = allocated_pages[ 0 ];
			for ( size_t i = 0; i < allocated_pages.size( ); i++ ) {
				const auto current_page = allocated_pages[ i ];
				const auto page_size = ( i == allocated_pages.size( ) - 1 )
					? ( aligned_size - ( i * PAGE_2MB ) )
					: PAGE_2MB;

				m_physical_mappings.emplace_back( current_page , PAGE_2MB , page_size );
			}

			return { virtual_memory_base, nt_status_t::success };
		}

		const std::pair<std::uintptr_t , nt_status_t> c_interface::create_allocation( std::size_t allocation_size )
		{
			constexpr std::size_t PAGE_2MB = 0x200000;
			constexpr std::size_t PAGE_1GB = 0x40000000;
			constexpr std::size_t PAGE_4KB = 0x1000;

			const auto aligned_size = ( allocation_size + ( PAGE_4KB - 1 ) ) & ~( PAGE_4KB - 1 );
			if ( aligned_size > PAGE_1GB ) {
				printf( encrypt( " > max allocation size is 1gb.\n" ) );
				return { 0, nt_status_t::length_mismatch };
			}

			std::uintptr_t virtual_memory_base = 0;
			std::size_t page_block_size = PAGE_2MB;

			if ( aligned_size > PAGE_2MB ) {
				page_block_size = PAGE_1GB;
				virtual_memory_base = get_free_1gb_memory_base( );
				if ( !virtual_memory_base || virtual_memory_base % page_block_size ) {
					printf( encrypt( " > 1GB allocation failed, falling back to 2MB pages.\n" ) );
					return allocate_2mb_fallback( aligned_size );
				}
			}
			else {
				virtual_memory_base = get_free_2mb_memory_base( );
				if ( !virtual_memory_base || virtual_memory_base % page_block_size ) {
					printf( encrypt( " > invalid or unaligned 2MB physical mapping.\n" ) );
					return { 0, nt_status_t::length_mismatch };
				}
			}

			auto existing = std::find_if( m_physical_mappings.begin( ) , m_physical_mappings.end( ) ,
				[ virtual_memory_base ] ( const mapping::physical_mapping& mapping ) {
					return mapping.virtual_base == virtual_memory_base;
				} );

			if ( existing == m_physical_mappings.end( ) ) {
				m_physical_mappings.emplace_back( mapping::physical_mapping{ virtual_memory_base, page_block_size, aligned_size } );
				return { virtual_memory_base, nt_status_t::success };
			}

			printf( encrypt( " > physical mapping already in use.\n" ) );
			return { 0, nt_status_t::pending };
		}

		const mapping::physical_mapping* c_interface::find_mapping( std::uintptr_t virtual_address )
		{
			auto it = std::find_if( m_physical_mappings.begin( ) , m_physical_mappings.end( ) ,
				[ virtual_address ] ( const mapping::physical_mapping& mapping ) {
					return virtual_address >= mapping.virtual_base &&
						virtual_address < ( mapping.virtual_base + mapping.mapped_size );
				} );

			return it != m_physical_mappings.end( ) ? &( *it ) : nullptr;
		}

		const std::size_t& c_interface::get_remaining_space( std::uintptr_t base_address )
		{
			auto mapping = find_mapping( base_address );
			if ( !mapping ) return 0;

			return mapping->mapped_size - mapping->usable_size;
		}

		bool c_interface::is_address_in_usable_range( std::uintptr_t address )
		{
			auto mapping = find_mapping( address );
			if ( !mapping ) return false;

			return address >= mapping->virtual_base &&
				address < ( mapping->virtual_base + mapping->usable_size );
		}

		nt_status_t c_interface::cleanup_allocation( std::uintptr_t virtual_base )
		{
			auto it = std::remove_if( m_physical_mappings.begin( ) , m_physical_mappings.end( ) ,
				[ this , virtual_base ] ( const mapping::physical_mapping& mapping ) {
					if ( mapping.virtual_base == virtual_base ) {
						if ( mapping.virtual_base ) {
							free_physical(
								mapping.virtual_base ,
								mapping.mapped_size
							);
						}
						return true;
					}
					return false;
				} );

			if ( it == m_physical_mappings.end( ) ) {
				printf( encrypt( " > no mapping found for cleanup at 0x%llx\n" ) , virtual_base );
				return nt_status_t::insufficient_resources;
			}

			m_physical_mappings.erase( it , m_physical_mappings.end( ) );
			return nt_status_t::success;
		}

		void c_interface::cleanup_all_allocations( )
		{
			std::for_each( m_physical_mappings.begin( ) , m_physical_mappings.end( ) ,
				[ this ] ( const mapping::physical_mapping& mapping ) {
					if ( mapping.virtual_base ) {
						free_physical(
							mapping.virtual_base ,
							mapping.mapped_size
						);
					}
				} );

			m_physical_mappings.clear( );
		}

		void c_interface::cleanup_partial_allocation( const std::vector<std::uintptr_t>& allocated_pages )
		{
			std::for_each( allocated_pages.begin( ) , allocated_pages.end( ) ,
				[ this ] ( const std::uintptr_t& page ) {
					if ( page ) {
						free_physical(
							page ,
							0x200000  // 2MB page size
						);
					}
				} );
		}

		void c_interface::unload_driver( )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::unload;

			std::memcpy( memory_buffer , &request , sizeof( request ) );
		}

		std::uintptr_t c_interface::translate_linear( uintptr_t virtual_address )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = virtual_address;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::translate_linear;

			send_cmd( request );

			return request.address2;
		}

		const std::uintptr_t c_interface::physical_for_virtual( std::uintptr_t physical_address )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = physical_address;
			request.size = sizeof( physical_address );
			request.target_pid = target_pid;
			request.operation_type = server::request_type::get_virtual;

			send_cmd( request );

			return request.address2;
		}

		const std::uintptr_t c_interface::virtual_for_physical( uintptr_t virtual_address )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = virtual_address;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::get_physical;

			send_cmd( request );

			return request.address2;
		}

		const nt_status_t c_interface::create_instrumentation_callback( uintptr_t callback )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.address = callback;
			request.target_pid = target_pid;
			request.operation_type = server::request_type::create_instrum_callback;

			send_cmd( request );

			return request.operation_status;
		}

		bool c_interface::read_physical( const uintptr_t address , void* buffer , const std::uintptr_t size )
		{
			if ( address >= 0x7FFFFFFFFFFF ) {
				return false;
			}

			SIZE_T total_size = size;

			auto physical_address = translate_linear( address );
			if ( !physical_address ) {
				return false;
			}

			printf( encrypt( "physical address : %llx\n" ) , physical_address );

			//auto final_size = find_min(
			//	0x1000 - ( physical_address & 0xFFF ) ,
			//	total_size );

			//auto result = read_physical_km(
			//	physical_address ,
			//	buffer ,
			//	final_size );
			//if ( !result ) {
			//	return false;
			//}

			return true;
		}

		bool c_interface::write_physical( const uintptr_t address , void* buffer , const std::uintptr_t size )
		{
			if ( address >= 0x7FFFFFFFFFFF ) {
				return false;
			}

			SIZE_T total_size = size;
			auto physical_address = translate_linear( address );
			if ( !physical_address ) {
				return false;
			}

			printf( encrypt( "physical address : %llx\n" ) , physical_address );

			//auto final_size = find_min(
			//	0x1000 - ( physical_address & 0xFFF ) ,
			//	total_size );

			//auto result = write_physical_km(
			//	physical_address ,
			//	( char* ) ( buffer ) ,
			//	final_size );
			//if ( !result ) {
			//	return false;
			//}

			return true;
		}

		PSYSTEM_BIGPOOL_INFORMATION c_interface::query_bigpools( )
		{
			static const pNtQuerySystemInformation NtQuerySystemInformation =
				( pNtQuerySystemInformation ) GetProcAddress( GetModuleHandleA( encrypt( "ntdll.dll" ) ) , encrypt( "NtQuerySystemInformation" ) );

			DWORD length = 0;
			DWORD size = 0;
			LPVOID heap = HeapAlloc( GetProcessHeap( ) , HEAP_ZERO_MEMORY , 0 );
			heap = HeapReAlloc( GetProcessHeap( ) , HEAP_ZERO_MEMORY , heap , 0xFF );
			NTSTATUS ntLastStatus = NtQuerySystemInformation( SystemBigPoolInformation , heap , 0x30 , &length );
			heap = HeapReAlloc( GetProcessHeap( ) , HEAP_ZERO_MEMORY , heap , length + 0x1F );
			size = length;
			ntLastStatus = NtQuerySystemInformation( SystemBigPoolInformation , heap , size , &length );

			return reinterpret_cast< PSYSTEM_BIGPOOL_INFORMATION >( heap );
		}

		const std::uintptr_t c_interface::get_guarded_region( )
		{
			uintptr_t guard_regions = 0;
			auto pool_information = query_bigpools( );
			if ( pool_information )
			{
				auto count = pool_information->Count;
				for ( auto i = 0ul; i < count; i++ )
				{
					SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[ i ];
					const auto virtual_address = ( PVOID ) ( ( uintptr_t ) allocation_entry->VirtualAddress & ~1ull );
					if ( allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000 )
						if ( guard_regions == 0 && allocation_entry->TagUlong == 'TnoC' )
							guard_regions = reinterpret_cast< uintptr_t >( virtual_address );
				}
			}

			return guard_regions;
		}

		void c_interface::set_guarded_region( uintptr_t guarded_region )
		{
			this->guarded_region = guarded_region;
		}

		const std::uintptr_t c_interface::get_eprocess( std::uint32_t process_id )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.target_pid = process_id;
			request.operation_type = server::request_type::get_eprocess;

			send_cmd( request );

			return request.address;
		}

		const std::uintptr_t c_interface::get_base_address( const std::uintptr_t e_process )
		{
			server::request_data request{};
			request.is_client_running = true;
			request.is_operation_completed = false;
			request.target_pid = target_pid;
			request.address = e_process;
			request.operation_type = server::request_type::get_base_address;

			send_cmd( request );

			return request.address2;
		}

		bool c_interface::get_process_pid( std::wstring module_name , std::uint32_t* process_id )
		{
			const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
			if ( !snapshot || snapshot == INVALID_HANDLE_VALUE ) {
				return false;
			}

			PROCESSENTRY32W process_entry{ };
			process_entry.dwSize = sizeof( process_entry );
			Process32FirstW( snapshot , &process_entry );
			do {
				if ( !module_name.compare( process_entry.szExeFile ) ) {
					*process_id = process_entry.th32ProcessID;
					return true;
				}
			} while ( Process32NextW( snapshot , &process_entry ) );

			return false;
		}

		void c_interface::set_process_pid( std::uint32_t pid )
		{
			target_pid = pid;
		}

		std::uint32_t c_interface::get_process_pid( )
		{
			return target_pid;
		}
	}
}