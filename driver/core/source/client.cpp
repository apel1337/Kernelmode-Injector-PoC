#include <core/linkers/client.h>

namespace riot
{
	namespace client
	{
		bool c_interface::setup ( ) 
		{
			auto status = get_value ( encrypt ( L"client_id" ) , this->client_id );
			if ( !status ) {
				exports::dbg_print ( encrypt ( "[riot] failed to get client id\n" ) );
				return status;
			}

			this->client_process = 
				reinterpret_cast< PEPROCESS >( process::get_eprocess( this->client_id ) );
			if ( !this->client_process ) {
				exports::dbg_print ( encrypt ( "[riot] failed to get client process\n" ) );
				return status;
			}

			this->process_cr3.flags = process::get_process_cr3(
				reinterpret_cast< std::uintptr_t >( this->client_process ) );
			if ( !this->process_cr3.flags ) {
				return false;
			}

			status = get_value ( encrypt ( L"buffer" ) , this->target_buffer );
			if ( !status ) {
				exports::dbg_print ( encrypt ( "[riot] failed to get buffer\n" ) );
				return status;
			}

			status = get_value( encrypt( L"log_array" ) , this->log_buffer );
			if ( !status ) {
				exports::dbg_print( encrypt( "[riot] failed to get log array\n" ) );
				return status;
			}

			return status;
		}

		void c_interface::cleanup( )
		{
			std::size_t region_size{ };
			exports::obf_dereference_object( this->client_process );

			exports::zw_free_virtual_memory(
				this->get_client_process( ) ,
				reinterpret_cast< void** >( &this->target_buffer ) ,
				&region_size ,
				MEM_RELEASE
			);

			exports::zw_free_virtual_memory(
				this->get_client_process( ) ,
				reinterpret_cast< void** >( &this->log_buffer ) ,
				&region_size ,
				MEM_RELEASE
			);
		}

		template <typename type>
		bool c_interface::get_value ( const wchar_t* value_name , type& result_value ) {
			UNICODE_STRING unicode_key_path = { oxorany ( 0 ) } , unicode_value_name = { oxorany ( 0 ) };
			exports::rtl_init_unicode_string ( &unicode_key_path , key_path );
			exports::rtl_init_unicode_string ( &unicode_value_name , value_name );

			OBJECT_ATTRIBUTES object_attributes = { oxorany( 0 ) };
			InitializeObjectAttributes( &object_attributes , &unicode_key_path ,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

			HANDLE key_handle = NULL;
			auto status = exports::zw_open_key( &key_handle , oxorany( KEY_READ ) , &object_attributes );
			if ( status != nt_status_t::success ) {
				return false;
			}

			ULONG buffer_size = oxorany( sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( type ) );
			auto key_value_info = ( KEY_VALUE_PARTIAL_INFORMATION* ) exports::ex_allocate_pool( NonPagedPool , buffer_size );
			if ( !key_value_info ) {
				exports::zw_close( key_handle );
				return false;
			}

			status = exports::zw_query_value_key( key_handle , &unicode_value_name , KeyValuePartialInformation , key_value_info , buffer_size , &buffer_size );
			if ( status != nt_status_t::success ) {
				exports::ex_free_pool_with_tag( key_value_info , oxorany( 0 ) );
				exports::zw_close( key_handle );
				return false;
			}

			result_value = *reinterpret_cast< type* > ( key_value_info->Data );
			exports::ex_free_pool_with_tag( key_value_info , oxorany( 0 ) );
			exports::zw_close( key_handle );

			return true;
		}

		bool c_interface::send( client::prequest_data request ) {
			size_t buffer_size = oxorany ( 0 );

			if ( !this->client_process || !this->target_buffer )
			{
				exports::dbg_print( encrypt( "[riot] invalid client process or target buffer\n" ) );
				return false;
			}

			auto status = exports::mm_copy_virtual_memory (
				exports::io_get_current_process ( ) , 
				request , 
				this->client_process ,
				this->target_buffer ,
				sizeof ( client::request_data ) , 
				oxorany ( 0 ) ,
				&buffer_size );

			return status == nt_status_t::success;
		}

		bool c_interface::get ( client::prequest_data out_request ) {
			size_t buffer_size = oxorany( 0 );
			client::request_data request {};

			if ( !this->client_process || !this->target_buffer )
			{
				exports::dbg_print( encrypt( "[riot] invalid client process or target buffer\n" ) );
				return false;
			}

			auto status = exports::mm_copy_virtual_memory(
				this->client_process ,
				this->target_buffer ,
				exports::io_get_current_process( ) ,
				&request ,
				sizeof( request ) ,
				oxorany( 0 ) ,
				&buffer_size
			);

			if ( status == nt_status_t::success )
			{
				*out_request = request;
			}
			else
			{
				exports::dbg_print( encrypt( "[riot] failed to copy memory from client process\n" ) );
			}

			return status == nt_status_t::success;
		}

		void c_interface::log_print( const char* format , ... ) {
			logs::move_tail_ahead( );

			auto current_entry = &logs::m_log_entries[ logs::m_head_index ];
			current_entry->present = true;

			va_list args = nullptr;
			va_start( args , format );
			logs::format( current_entry->payload , format , args );
			va_end( args );

			logs::move_head_ahead( );
		}

		void c_interface::flush_logs( ) {
			if ( !this->log_buffer )
			{
				exports::dbg_print( encrypt( "[riot] invalid log buffer\n" ) );
				return;
			}

			std::uint32_t buffer_index = oxorany( 0 );
			size_t buffer_size = oxorany( 0 );

			auto log_array =
				reinterpret_cast< logs::log_entry_t* >( this->log_buffer );
			if ( !log_array ) {
				exports::dbg_print( encrypt( "[riot] invalid log array\n" ) );
				return;
			}

			for ( std::uint32_t idx = logs::m_tail_index;
				idx != logs::m_head_index;
				idx = ( idx + 1 ) % max_messages )
			{
				if ( buffer_index > max_messages ) {
					break;
				}

				auto status = exports::mm_copy_virtual_memory(
					exports::io_get_current_process( ) ,
					&logs::m_log_entries[ idx ] ,
					this->client_process ,
					&log_array[ buffer_index ] ,
					sizeof( logs::log_entry_t ) ,
					oxorany( 0 ) ,
					&buffer_size );

				if ( status != nt_status_t::success ) {
					continue;
				}

				std::memset( &logs::m_log_entries[ buffer_index ] , 0 , sizeof( logs::m_log_entries[ buffer_index ] ) );

				buffer_index++;
			}

			logs::m_tail_index = logs::m_head_index;
		}

		PEPROCESS c_interface::get_client_process ( ) {
			return client_process;
		}
	}
}