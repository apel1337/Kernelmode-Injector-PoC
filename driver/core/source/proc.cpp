#include <core/linkers/proc.h>

namespace riot
{
	namespace process
	{
		std::uintptr_t attach( std::uintptr_t e_process )
		{
			auto current_thread = __readgsqword( oxorany( 0x188 ) );
			if ( !current_thread )
				return 0;

			auto apc_state = *( uintptr_t* ) ( current_thread + oxorany( 0x98 ) );
			auto old_process = *( uintptr_t* ) ( apc_state + oxorany( 0x20 ) );
			*( uintptr_t* ) ( apc_state + oxorany( 0x20 ) ) = e_process;

			auto dir_table_base = *( uintptr_t* ) ( e_process + oxorany( 0x28 ) );
			__writecr3( dir_table_base );

			return old_process;
		}

		std::uintptr_t get_eprocess( std::uint32_t process_id )
		{
			auto process_list_head = exports::ps_active_process_head( );
			if ( !process_list_head ) {
				return 0;
			}

			const auto link_va =
				reinterpret_cast< std::addr_t >( process_list_head ) -
				exports::ps_initial_system_process( );
			if ( !link_va ) {
				return 0;
			}

			for ( auto flink = process_list_head->m_flink; flink; flink = flink->m_flink )
			{
				const auto next_eprocess = reinterpret_cast< std::addr_t >( flink ) - link_va;
				if ( !next_eprocess ) {
					continue;
				}

				const auto next_process_id = exports::ps_get_process_id( next_eprocess );
				if ( next_process_id == process_id ) {
					return next_eprocess;
				}
			}

			return 0;
		}

		std::uintptr_t get_eprocess( const wchar_t* process_name )
		{
			const auto process_list_head = exports::ps_active_process_head( );
			if ( !process_list_head ) {
				return 0;
			}

			const auto linkage_va =
				reinterpret_cast< std::addr_t >( process_list_head ) -
				exports::ps_initial_system_process( );
			if ( !linkage_va ) {
				return 0;
			}

			for ( auto flink = process_list_head->m_flink; flink; flink = flink->m_flink )
			{
				const auto next_eprocess = reinterpret_cast< std::addr_t >( flink ) - linkage_va;
				if ( !next_eprocess || !exports::ps_get_process_exit_status( next_eprocess ) ) {
					continue;
				}

				auto unicode_name{ exports::ps_query_full_process_image_name( next_eprocess ) };
				if ( !unicode_name->m_buffer
					|| !unicode_name->m_length
					|| !unicode_name->m_maximum_length )
					continue;

				if ( std::wcscmp( unicode_name->m_buffer , process_name ) )
				{
					return next_eprocess;
				}
			}

			return 0;
		}

		std::uintptr_t get_process_cr3( std::uintptr_t e_process )
		{
			static auto function_address = 
				exports::find_export< std::addr_t >( encrypt( "KeCapturePersistentThreadState" ) );
			if ( !function_address ) {
				return 0;
			}

			while ( function_address[ 0x0 ] != 0x48
				|| function_address[ 0x1 ] != 0x8b
				|| function_address[ 0x2 ] != 0x48 )
				function_address++;

			return *reinterpret_cast< std::uintptr_t* >
				( e_process + *reinterpret_cast< std::int8_t* >( &function_address[ 0x3 ] ) );
		}
	}
}