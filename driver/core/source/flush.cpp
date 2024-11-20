#include <core/linkers/flush.h>

namespace riot
{
	namespace flush
	{
		[[ nodiscard ]] void cleaup_dpc_routine(
			PKDPC dpc ,
			PVOID deferred_context ,
			PVOID system_argument1 ,
			PVOID system_argument2
		) {
			//exports::ex_free_pool( g::allocation_pool );
		}

		[[ nodiscard ]] void flush_traces( )
		{
			auto current_thread = 
				exports::ps_get_current_thread( );
			thread::revert_thread_flags( );

			auto status = exports::ps_get_thread_exit_status( current_thread );
			if ( !status )
			{
				client::m_client->cleanup( );

				KDPC cleanup_dpc{ };
				exports::ke_initialize_dpc( &cleanup_dpc , cleaup_dpc_routine , nullptr );
				exports::ke_insert_queue_dpc( &cleanup_dpc , nullptr , nullptr );
			}

			exports::zw_terminate_thread( g::thread_handle , nt_status_t::success );
		}
	}
}