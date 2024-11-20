#include <core/linkers/nmi.h>

namespace riot
{
	namespace nmi
	{
		bool nmi_callback( void* context , BOOLEAN handled ) 
		{
			UNREFERENCED_PARAMETER( handled );

			auto nmi_context = reinterpret_cast< PNMI_CONTEXT >( context );

			std::uint32_t processor_count = KeGetCurrentProcessorNumber( );
			exports::dbg_print( encrypt( "[riot] current core : %lu\n" ) , processor_count );

			auto kprcb = __readmsr( 0xc0000101 );
			auto task_state_segment =
				*reinterpret_cast< TASK_STATE_SEGMENT_64** >( kprcb + 0x008 );
			auto isr_machine_frame = 
				reinterpret_cast< PMACHINE_FRAME >( task_state_segment->Ist3 - sizeof( MACHINE_FRAME ) );
			exports::dbg_print( encrypt( "[riot] isr machine frame rip : %llx\n" ) , isr_machine_frame->rip );

			if ( isr_machine_frame->rip <= oxorany( 0x00007FFFFFFFFFFF ) ) {
				exports::dbg_print( encrypt( "[riot] user mode thread max address\n" ) );
				nmi_context[ processor_count ].user_thread = oxorany( true );
			}

			nmi_context[ processor_count ].interrupted_rip = isr_machine_frame->rip;
			nmi_context[ processor_count ].interrupted_rsp = isr_machine_frame->rsp;
			nmi_context[ processor_count ].callback_count += oxorany( 1 );

			exports::dbg_print( encrypt( "[riot] realeasing nmi callback.\n" ) );
			return true;
		}

		bool register_nmi_callback( PNMI_CONTEXT nmi_context ) {
			auto proc_affinity =
				reinterpret_cast< PKAFFINITY_EX > (
					exports::ex_allocate_pool2(
						oxorany( POOL_FLAG_NON_PAGED ) ,
						oxorany( sizeof( KAFFINITY_EX ) ) ,
						proc_affinity_pool ) );
			if ( !proc_affinity )
				return false;

			void* registration_handle = exports::ke_register_nmi_callback(
				reinterpret_cast< PNMI_CALLBACK >( nmi_callback ) , nmi_context );
			if ( !registration_handle ) {
				exports::dbg_print( encrypt( "[riot] failed to register nmi callback\n" ) );
				exports::ex_free_pool_with_tag( proc_affinity , proc_affinity_pool );
				return false;
			}

			LARGE_INTEGER delay = { oxorany( 0 ) };
			delay.QuadPart -= oxorany( 100 * 10000 );
			for ( std::uint32_t core = oxorany( 0 ); core < exports::ke_query_active_processor_count( 0 ); core++ )
			{
				exports::ke_initialize_affinity_ex( proc_affinity );
				exports::ke_add_processor_affinity_ex( proc_affinity , core );

				exports::hal_send_nmi( proc_affinity );
				exports::ke_delay_execution_thread( KernelMode , FALSE , &delay );
			}

			exports::ke_deregister_nmi_callback( registration_handle );
			exports::ex_free_pool_with_tag( proc_affinity , proc_affinity_pool );

			return true;
		}

		bool get_system_module_information( PSYSTEM_MODULES module_information ) {
			ULONG size = oxorany( 0 );
			if ( !exports::rtl_query_module_information( &size , oxorany( sizeof( RTL_MODULE_EXTENDED_INFO ) ) , 0 ) == nt_status_t::success ) {
				exports::dbg_print( encrypt( "[riot] failed to query module information" ) );
				return false;
			}

			auto driver_information =
				reinterpret_cast< PRTL_MODULE_EXTENDED_INFO > (
					exports::ex_allocate_pool2( oxorany( POOL_FLAG_NON_PAGED ) , size , oxorany( system_modules_pool ) ) );
			if ( !driver_information )
			{
				exports::dbg_print( encrypt( "[riot] failed to allocate pool" ) );
				return false;
			}

			if ( !exports::rtl_query_module_information( &size , oxorany( sizeof( RTL_MODULE_EXTENDED_INFO ) ) , driver_information ) == nt_status_t::success ) {
				exports::dbg_print( encrypt( "[riot] failed to pass the pointer to the allocated buffer" ) );
				exports::ex_free_pool_with_tag( driver_information , system_modules_pool );
				return false;
			}

			module_information->address = driver_information;
			module_information->module_count = size / oxorany( sizeof( RTL_MODULE_EXTENDED_INFO ) );

			return true;
		}

		bool spoof_nmi_data( )
		{
			auto nmi_context =
				reinterpret_cast< PNMI_CONTEXT > (
					exports::ex_allocate_pool2(
						POOL_FLAG_NON_PAGED ,
						exports::ke_query_active_processor_count( 0 ) * sizeof( NMI_CONTEXT ) ,
						nmi_context_pool ) );
			if ( !nmi_context )
				return false;

			SYSTEM_MODULES system_modules = { 0 };
			bool status = get_system_module_information( &system_modules );
			if ( !status ) {
				exports::dbg_print( encrypt( "[riot] failed to retrivie module information." ) );
				return status;
			}

			status = register_nmi_callback( nmi_context );
			if ( !status ) {
				exports::dbg_print( encrypt( "[riot] failed to run nmi callbacks." ) );
				exports::ex_free_pool_with_tag( system_modules.address , system_modules_pool );
				exports::ex_free_pool_with_tag( nmi_context , nmi_context_pool );
				return status;
			}

			status = utils::analyse_nmi_data( nmi_context , &system_modules );
			if ( !status )
				exports::dbg_print( encrypt( "[riot] failed to analyse nmi data." ) );

			exports::ex_free_pool_with_tag( system_modules.address , system_modules_pool );
			exports::ex_free_pool_with_tag( nmi_context , nmi_context_pool );

			return status;
		}

		bool hide_driver( )
		{
			SYSTEM_MODULES system_modules = { 0 };
			RtlZeroMemory( &system_modules , sizeof( SYSTEM_MODULES ) );

			bool status = get_system_module_information( &system_modules );
			if ( !status ) {
				exports::dbg_print( encrypt( "[riot] failed to retrive system modules" ) );
				return status;
			}

			auto head = reinterpret_cast< PINVALID_DRIVERS_HEAD > (
				exports::ex_allocate_pool2(
					oxorany( POOL_FLAG_NON_PAGED ) ,
					sizeof( INVALID_DRIVERS_HEAD ) ,
					invalid_driver_list_head_pool ) );
			if ( !head ) {
				exports::ex_free_pool_with_tag( system_modules.address , system_modules_pool );
				return false;
			}

			head->count = oxorany( 0 ) , head->first_entry = reinterpret_cast< PINVALID_DRIVER > ( oxorany( 0 ) );

			auto entry = head->first_entry;
			auto entry_next = entry;
			while ( entry_next != reinterpret_cast< PINVALID_DRIVER > ( oxorany( 0 ) ) ) {
				//exports::dbg_print( encrypt( "[riot] found invalid driver : %wZ\n" ) , entry_next->driver->DriverName );
				entry_next = entry_next->next;
			}

			auto head_first = head;
			if ( head_first->count > oxorany( 0 ) )
			{
				for ( int i = oxorany( 0 ); i < head->count; i++ )
				{
					if ( !head_first->first_entry )
						continue;

					auto first_entry = head_first->first_entry;
					head_first->first_entry = head_first->first_entry->next;
					exports::ex_free_pool_with_tag( first_entry , invalid_driver_list_entry_pool );
				}
			}
			else
			{
				exports::dbg_print( encrypt( "[riot] no invalid drivers found\n" ) );
			}

			exports::ex_free_pool_with_tag( head , invalid_driver_list_head_pool );
			exports::ex_free_pool_with_tag( entry , system_modules_pool );

			return status;
		}

		namespace utils
		{
			bool is_instruction_in_invalid_region( std::uint64_t rip_instr , PSYSTEM_MODULES system_modules ) {
				for ( int i = oxorany( 0 ); i < system_modules->module_count; i++ ) {
					PRTL_MODULE_EXTENDED_INFO system_module =
						reinterpret_cast< PRTL_MODULE_EXTENDED_INFO >(
							( ( uintptr_t ) system_modules->address + i * sizeof( RTL_MODULE_EXTENDED_INFO ) ) );

					std::uint64_t base = reinterpret_cast< std::uint64_t > (
						system_module->ImageBase );
					std::uint64_t end = base + system_module->ImageSize;

					if ( rip_instr >= base && rip_instr <= end ) {
						return true;
					}
				}

				return false;
			}

			bool analyse_nmi_data( PNMI_CONTEXT nmi_context , PSYSTEM_MODULES system_modules ) {
				for ( ULONG core = oxorany( 0 ); core < exports::ke_query_active_processor_count( 0 ); core++ ) {
					if ( !nmi_context[ core ].callback_count ) {
						exports::dbg_print( encrypt( "[riot] no nmi callbacks were running." ) );
						return true;
					}

					if ( nmi_context[ core ].user_thread )
						continue;

					if ( !is_instruction_in_invalid_region(
						nmi_context[ core ].interrupted_rip , system_modules ) )
						exports::dbg_print( encrypt( "[riot] RIP was executing in invalid memory : %llx" ) , nmi_context[ core ].interrupted_rip );
				}

				return true;
			}
		}
	}
}