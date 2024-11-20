#include <core/linkers/handler.h>

namespace riot
{
	namespace thread
	{
		bool handler( )
		{
			const auto status = thread::copy_thread_flags( );
			if ( !status ) {
				exports::dbg_print( encrypt( "[riot] failed to copy thread flags.\n" ) );
				return false;
			}

			while ( true )
			{
				client::request_data request { };
				if ( !( client::m_client->get( &request ) ) ) {
					exports::dbg_print( encrypt( "[riot] client process is no longer active.\n" ) );
					break;
				}

				if ( !request.is_client_running ) {
					continue;
				}

				client::m_client->flush_logs( );

				if ( request.is_operation_completed ) {
					continue;
				}

				if ( !request.target_pid ) {
					continue;
				}

				auto target_process = reinterpret_cast< PEPROCESS > (
					process::get_eprocess( request.target_pid ) );

				switch ( request.operation_type )
				{
				case client::request_type::read_virtual:
				{
					SIZE_T address_size = 0;
					request.operation_status =
						exports::mm_copy_virtual_memory( target_process , ( void* ) ( request.address ) , client::m_client->get_client_process( ) ,
							request.buffer , request.size , oxorany( UserMode ) , &address_size );
					break;
				}
				case client::request_type::write_virtual:
				{
					SIZE_T address_size = 0;
					request.operation_status =
						exports::mm_copy_virtual_memory( client::m_client->get_client_process( ) , request.buffer , target_process ,
							( void* ) ( request.address ) , request.size , oxorany( UserMode ) , &address_size );
					break;
				}
				case client::request_type::read_physical:
				{
					request.operation_status =
						rwx::read_physical_address( request.address , request.buffer , request.size )
						? nt_status_t::success : nt_status_t::length_mismatch;
					break;
				}
				case client::request_type::write_physical:
				{
					request.operation_status =
						rwx::write_physical_address( request.address , request.buffer , request.size )
						? nt_status_t::success : nt_status_t::length_mismatch;
					break;
				}
				case client::request_type::allocate_virtual:
				{
					uintptr_t o_process = process::attach(
						( uintptr_t ) target_process );
					if ( !o_process ) break;

					void* allocation_base = nullptr;
					request.operation_status =
						exports::zw_allocate_virtual_memory( NtCurrentProcess( ) , &allocation_base ,
							( ULONG_PTR ) ( 0 ) , &request.size , request.flags , request.protection );

					std::memcpy( &request.buffer , &allocation_base , sizeof( allocation_base ) );
					process::attach( o_process );
				} break;
				case client::request_type::protect_virtual:
				{
					uintptr_t o_process = process::attach(
						( uintptr_t ) target_process );

					void* address = ( void* ) request.address;
					ULONG size = ( ULONG ) request.size;
					ULONG new_protection = request.protection , old_protection = oxorany( 0 );
					request.operation_status =
						exports::zw_protect_virtual_memory( NtCurrentProcess( ) ,
							&address , &size , new_protection , &old_protection );

					request.protection = ULONGLONG( old_protection );
					process::attach( o_process );
				} break;
				case client::request_type::free_virtual:
				{
					uintptr_t o_process = process::attach(
						( uintptr_t ) target_process );

					uintptr_t size = 0;
					void* address = ( void* ) request.address;
					request.operation_status =
						exports::zw_free_virtual_memory( NtCurrentProcess( ) ,
							&address , &size , request.flags );

					process::attach( o_process );
				} break;
				case client::request_type::swap_virtual:
				{
					uintptr_t o_process = process::attach(
						( uintptr_t ) target_process );

					void* original_pointer = _InterlockedExchangePointer(
						( void** ) request.address , ( void* ) request.address2 );

					request.buffer = original_pointer;
					process::attach( o_process );
				} break;
				case client::request_type::query_virtual:
				{
					uintptr_t o_process = process::attach(
						( uintptr_t ) target_process );

					memory_basic_information mbi{ };
					request.operation_status =
						exports::zw_query_virtual_memory( NtCurrentProcess( ) , ( void* ) request.address ,
							MemoryBasicInformation , &mbi , sizeof( mbi ) , 0 );

					request.mbi = mbi;
					process::attach( o_process );
				} break;
				case client::request_type::free_physical:
				{
					exports::mm_unmap_io_space( reinterpret_cast< void* >( request.address ) , request.size );
				} break;
				case client::request_type::create_instrum_callback:
				{
					request.operation_status =
						exports::enable_instrumentation_callbacks( target_process , reinterpret_cast< PVOID >( request.address ) );
				} break;
				case client::request_type::get_virtual:
				{
					request.address2 = exports::get_virtual_for_physical( request.address );
				} break;
				case client::request_type::get_physical:
				{
					request.address2 = exports::get_physical_address( request.address );
				} break;
				case client::request_type::translate_linear:
				{
					request.address2 = page::translate_linear( request.address );
				} break;
				case client::request_type::get_directory_table_base:
				{
					request.address2 = page::get_directory_table_base( request.address );
				} break;
				case client::request_type::get_eprocess:
				{
					request.address = reinterpret_cast< uintptr_t >( target_process );
				} break;
				case client::request_type::get_base_address:
				{
					request.address2 = reinterpret_cast< uintptr_t >(
						exports::ps_get_process_section_base_address( reinterpret_cast< PEPROCESS >( request.address ) ) );
				} break;
				case client::request_type::get_free_2mb_memory_base:
				{
					request.address = page::get_free_2mb_memory_base( );
				} break;
				case client::request_type::get_free_1gb_memory_base:
				{
					request.address = page::get_free_1gb_memory_base( );
				} break;
				}

				if ( request.operation_type == client::request_type::unload )
				{
					//exports::obf_dereference_object( target_process );
					break;
				}

				request.is_operation_completed = true;
				client::m_client->send( &request );

				//exports::obf_dereference_object( target_process );
			}

			flush::flush_traces( );
			return false;
		}
	}
}