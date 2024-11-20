#include <core/linkers/kthread.h>

namespace riot
{
	namespace thread
	{
		[[ nodiscard ]] std::uintptr_t get_psp_cid_table( )
		{

			return 0;
		}

		[[ nodiscard ]] bool is_address_in_module_list(
			std::uint64_t address
		) {
			if ( !address ) {
				exports::dbg_print( encrypt( "[riot] address parameter is invalid.\n" ) );
				return false;
			}

			ULONG length = 0;
			auto status = exports::query_system_information( nullptr , length , &length );
			if ( status != nt_status_t::length_mismatch ) {
				return false;
			}

			auto buffer = exports::ex_allocate_pool( NonPagedPool , length );
			if ( !buffer ) {
				return false;
			}

			status = exports::query_system_information( buffer , length , &length );
			if ( status != nt_status_t::success ) {
				exports::ex_free_pool( buffer );
				return false;
			}

			auto module_list = 
				reinterpret_cast< prtl_process_modules >( buffer );
			for ( auto idx = 0ul; idx < module_list->number_of_modules; idx++ )
			{
				const auto& current_module = module_list->modules[ idx ];

				if ( address >= ( std::uint64_t ) current_module.image_base &&
					address <= ( std::uint64_t ) current_module.image_base + current_module.image_size )
				{
					exports::dbg_print( encrypt( "in module bounds : %llx\n" ) , current_module );
					exports::ex_free_pool( buffer );
					return true;
				}
			}

			exports::ex_free_pool( buffer );
			return false;
		}

		[[ nodiscard ]] ethread* get_system_thread( )
		{
			for ( std::uint32_t thread_id = oxorany( 4 ); thread_id < oxorany( 0xffff ); thread_id += oxorany( 4 ) )
			{
				ethread* current_thread = nullptr;
				auto status = exports::ps_lookup_thread_by_thread_id( thread_id , &current_thread );
				if ( status != nt_status_t::success ) {
					continue;
				}

				auto current_kthread =
					reinterpret_cast< kthread* >( current_thread );
				if ( !current_kthread ) {
					continue;
				}

				if ( !exports::ps_is_system_thread( current_thread ) ) {
					continue;
				}

				const auto* thread = exports::ps_get_current_thread( );
				if ( current_thread == thread ) {
					continue;
				}

				//if ( !is_address_in_module_list( reinterpret_cast< std::uint64_t >( current_thread->StartAddress ) ) ) {
				//	continue;
				//}

				return current_thread;
			}

			return 0;
		}

		[[ nodiscard ]] bool copy_thread_flags( )
		{
			auto current_ethread = exports::ps_get_current_thread( );
			if ( !current_ethread ) {
				return false;
			}

			auto legit_ethread = get_system_thread( );
			if ( !legit_ethread ) {
				return false;
			}

			current_ethread->Win32StartAddress = legit_ethread->Win32StartAddress;
			current_ethread->HideFromDebugger = true;

			auto current_kthread =
				reinterpret_cast< kthread* >( current_ethread );
			auto legit_kthread =
				reinterpret_cast< kthread* >( legit_ethread );

			current_kthread->Win32Thread = legit_kthread->Win32Thread;
			current_kthread->ThreadFlags = legit_kthread->ThreadFlags;
			current_kthread->Tag = legit_kthread->Tag;
			current_kthread->KernelApcDisable = legit_kthread->KernelApcDisable;

			current_kthread->MiscFlags &= ~( 1ul << 10 ); // SystemThread
			current_kthread->MiscFlags &= ~( 1ul << 4 ); // AlertAble
			current_kthread->MiscFlags &= ~( 1ul << 14 ); // ApcQueuable

			exports::obf_dereference_object( legit_ethread );
			return true;
		}

		[[ nodiscard ]] void revert_thread_flags( )
		{
			auto current_ethread = exports::ps_get_current_thread( );
			if ( !current_ethread ) {
				return;
			}

			auto current_kthread =
				reinterpret_cast< kthread* >( current_ethread );

			current_kthread->MiscFlags |= ( 1ul << 10 ); // SystemThread
			current_kthread->MiscFlags |= ( 1ul << 4 ); // AlertAble
			current_kthread->MiscFlags |= ( 1ul << 14 ); // ApcQueuable
		}
	}
}