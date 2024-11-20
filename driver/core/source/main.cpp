#include <core/linkers/handler.h>

using namespace riot;

error entry_point( uintptr_t ntos_base_address , void* allocation_pool )
{
	g::ntos_base_address = ntos_base_address;
	g::allocation_pool = allocation_pool;
	if ( !ntos_base_address || !allocation_pool ) {
		exports::dbg_print( encrypt( "[riot] invalid ntos base address or allocation pool\n" ) );
		return error::error_parameters;
	}

	auto nt_build_number = exports::nt_build_number( );

	g::mm_pfn_database =
		reinterpret_cast< ppfn >( page::get_mm_pfn_database( ) );
	if ( !g::mm_pfn_database ) {
		exports::dbg_print( encrypt( "[riot] failed to get mm pfn database\n" ) );
		return error::error_unsupported;
	}

	g::self_referencing_pte_address = page::get_self_referencing_pte_address( );
	if ( !g::self_referencing_pte_address ) {
		exports::dbg_print( encrypt( "[riot] failed to get self referencing pte\n" ) );
		return error::error_unsupported;
	}

	//bool status = nmi::spoof_nmi_data( );
	//if ( !status ) {
	//	exports::dbg_print( encrypt( "[riot] failed to spoof nmi data\n" ) );
	//	return error::error_interrupts;
	//}

	client::m_client->set_key_path( encrypt( L"\\Registry\\Machine\\SOFTWARE\\Riot" ) );
	bool status = client::m_client->setup( );
	if ( !status ) {
		exports::dbg_print( encrypt( "[riot] failed to create communication\n" ) );
		return error::error_communication;
	}

	client::m_client->log_print( encrypt( "ntos base address [%llx]" ) , ntos_base_address );
	client::m_client->log_print( encrypt( "pool allocation base [%llx]" ) , allocation_pool );
	client::m_client->log_print( encrypt( "nt build number [%i]" ) , nt_build_number );
	client::m_client->log_print( encrypt( "mm pfn database [%llx]" ) , g::mm_pfn_database );
	client::m_client->log_print( encrypt( "self referencing pte [%llx]" ) , g::self_referencing_pte_address );

	status = gadget::create_gagdet( ntos_base_address , thread::handler );
	if ( !status ) {
		client::m_client->log_print( encrypt( "failed to create gadget" ) );
		return error::error_gadget;
	}

	client::m_client->log_print( encrypt( "created jmp rcx thread [%llx]" ) , g::thread_handle );

	return error::error_success;
}