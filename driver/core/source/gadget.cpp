#include <core/linkers/gadget.h>

namespace riot
{
	namespace gadget
	{
		bool find_gadget( uintptr_t driver_base_address , uintptr_t* used_jmp_rcx_gadget )
		{
			std::uintptr_t current_executable_section = 0;
			std::uint64_t current_executable_section_size = 0;

			const auto& status = rwx::discover_next_executable_section( driver_base_address , &current_executable_section , &current_executable_section_size );
			if ( !status ) {
				return false;
			}

			auto jmp_rcx_gadget = scan::find_pattern( current_executable_section , current_executable_section_size , encrypt( "\xFF\xE1" ) , encrypt( "xx" ) );
			if ( !jmp_rcx_gadget ) {
				return false;
			}

			*used_jmp_rcx_gadget = jmp_rcx_gadget;
			return exports::mm_is_address_valid(
				reinterpret_cast< void* >( *used_jmp_rcx_gadget ) );
		}

		bool create_gagdet( uintptr_t driver_base_address , void* thread_function )
		{
			std::uintptr_t used_jmp_rcx_gadget = 0;
			auto status = find_gadget( driver_base_address , &used_jmp_rcx_gadget );
			if ( !status ) return false;

			client::m_client->log_print( encrypt( "jmp rcx gadget [%llx]" ) , used_jmp_rcx_gadget );

			status = NT_SUCCESS(
				exports::ps_create_system_thread(
					&g::thread_handle ,
					GENERIC_ALL ,
					nullptr ,
					nullptr ,
					nullptr ,
					PKSTART_ROUTINE( used_jmp_rcx_gadget ) ,
					thread_function ) );

			exports::zw_close( g::thread_handle );
			return status;
		}
	}
}