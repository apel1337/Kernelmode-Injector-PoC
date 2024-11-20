#include <core/linkers/stdafx.h>
#include <core/linkers/exception.h>

using namespace riot;

int __cdecl main( int argc , char** argv )
{
	SetConsoleTitleA( encrypt( "Riot Injector" ) );
	SetUnhandledExceptionFilter( exception::exception_filter );
	if ( !service::util::enable_privilege( encrypt( L"SeDebugPrivilege" ).decrypt( ) ) ) {
		return false;
	}

	if ( argc < 2 )
	{
		MessageBoxA( 0 , encrypt( "failed to get the target driver, please drap and drop your .sys over riot injector." ) ,
			encrypt( "Riot Injector" ) , MB_ICONWARNING | MB_OK );
		return 0;
	}

	std::vector<std::uint8_t> raw_driver;
	util::open_binary_file( argv[ 1 ] , raw_driver );
	printf( encrypt( "initializing Riot Injector...\n" ) );
	printf( encrypt( "=== Riot Execution :: driver_interface::c_interface::setup() ===\n" ) );
	printf( encrypt( "...................................................................\n" ) );
	Sleep( 250 );

	driver::c_interface driver_ctx( encrypt( "SOFTWARE\\Riot" ) );
	bool setup_drv = driver_ctx.setup( );
	if ( !setup_drv ) {
		printf( encrypt( " > failed to load shared driver\n" ) );
		return std::getchar( );
	}

	auto start = std::chrono::high_resolution_clock::now( );
	printf( encrypt( "resolving piddb cache table...\n" ) );

	riot::drv_image image_ctx( raw_driver );
	bool load_drv = riot::load_drv( );
	if ( !load_drv )
	{
		printf( encrypt( " > failed to load vulnerable driver\n" ) );
		return std::getchar( );
	}

	riot::kernel_ctx kernel_ctx;
	const auto drv_timestamp = util::get_file_header( ( void* ) ( raw_driver_bytes ) )->TimeDateStamp;
	if ( !kernel_ctx.clear_piddb_cache( riot::drv_key , drv_timestamp ) )
	{
		perror( encrypt( " > failed to clear piddb cache table.\n" ) );
		return std::getchar( );
	}

	auto stop = std::chrono::high_resolution_clock::now( );
	auto duration = std::chrono::duration_cast< std::chrono::milliseconds >( stop - start );
	printf( encrypt( " > found piddb cache table in %llu ms!\n" ) , duration.count( ) );

	printf( encrypt( "...................................................................\n" ) );
	printf( encrypt( "exporting payload sections...\n" ) );

	const auto get_export_name = ( [ & ] ( const char* base , const char* name )
		{
			return reinterpret_cast< std::uintptr_t >( util::get_kernel_export( base , name ) );
		} );

	{
		image_ctx.fix_imports( get_export_name );

		image_ctx.map( );
	}

	printf( encrypt( "...................................................................\n" ) );
	printf( encrypt( "allocating kernel memory pages for payload...\n" ) );
	printf( encrypt( "removing PE Headers from allocation base..\n" ) );

	const auto pool_base =
		kernel_ctx.allocate_pool(
			image_ctx.size( ) ,
			NonPagedPool
		);

	printf( encrypt( "allocation base (size : %llu) : %p\n" ) , image_ctx.size( ) , pool_base );

	image_ctx.relocate( pool_base );
	kernel_ctx.write_kernelraw( pool_base , image_ctx.data( ) , image_ctx.size( ) );
	auto entry_point = reinterpret_cast< std::uintptr_t >( pool_base ) + image_ctx.entry_point( );
	printf( encrypt( " > payload entrypoint : %llu\n" ) , image_ctx.entry_point( ) );

	using syscall_t = server::error( __stdcall* )(
		std::uintptr_t ntos_base_address , 
		void* allocation_pool );

	auto return_value = kernel_ctx.syscall<syscall_t>(
		reinterpret_cast< void* >( entry_point ) ,
		driver_ctx.get_kernel_image( encrypt( "ntoskrnl.exe" ) ) ,
		pool_base );

	printf( encrypt( " > entrypoint returned (entrypoint : %llx) : %i\n" ) , entry_point, return_value );

	// ONLY WINDOWS 11, everything related to mapper is working fine on win 10 (prolly a sig issue)

	// Currently, there is an issue with communication between the kernel module (KM) and user mode (UM).
	// I will push an update to address this shortly. Additionally, I have observed that:
	// printf(encrypt(" > Entrypoint returned (entrypoint : %llx) : %i\n"), entry_point, return_value)
	// The return_value is returning an incorrect callback on Windows 11 -> (access violation/stack buffer overrun).
	// This issue can be easily resolved by swapping syscall functions.

	switch ( return_value )
	{
	case server::error::error_unknown:
	{
		printf( encrypt( "unknown failure contact support.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_parameters:
	{
		printf( encrypt( "passed invalid parameters to entry point, restart.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_unsupported:
	{
		printf( encrypt( "unsupported windows version, contact support.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_interrupts:
	{
		printf( encrypt( "failed to spoof interrupts data, contact support.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_communication:
	{
		printf( encrypt( "failed to create communication, contact support.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_gadget:
	{
		printf( encrypt( "failed to create thread gadget, contact support.\n" ) );
		kernel_ctx.free_pool( pool_base );
	} break;
	case server::error::error_success:
	{
		printf( encrypt( "=== Payload Execution :: entrypoint ===\n" ) );
		printf( encrypt( "...................................................................\n" ) );
	} break;
	}

	riot::unload_drv( );
	std::getchar( );

	if ( return_value == server::error::error_success )
	{
		system( encrypt( "cls" ) );
		printf( encrypt( "=== Riot Execution :: injector::c_interface::prepare_injection() ===\n" ) );
		printf( encrypt( "......................................................................\n" ) );
		printf( encrypt( "flushing root logger...\n" ) );

		driver_ctx.flush_logs( );

		printf( encrypt( ".......................................................\n" ) );
		printf( encrypt( "resolving module information...\n" ) );

		start = std::chrono::high_resolution_clock::now( );

		std::uint32_t process_id = 0;
		while ( !driver_ctx.get_process_pid( target_process , &process_id ) ) {
			Sleep( 250 );
		}

		driver_ctx.set_process_pid( process_id );

		printf( encrypt( " > process pid : %i\n" ) , process_id );

		auto e_process = driver_ctx.get_eprocess( process_id );
		if ( !e_process ) {
			printf( encrypt( " > failed to resolve peprocess.\n" ) );
			driver_ctx.unload_driver( );
			return std::getchar( );
		}

		printf( encrypt( " > keprocess : %llx\n" ) , e_process );

		auto module_handle = driver_ctx.get_base_address( e_process );
		if ( !module_handle ) {
			printf( encrypt( " > failed to resolve module handle.\n" ) );
			driver_ctx.unload_driver( );
			return std::getchar( );
		}

		printf( encrypt( " > base address : %llx\n" ) , module_handle );

		stop = std::chrono::high_resolution_clock::now( );
		duration = std::chrono::duration_cast< std::chrono::milliseconds >( stop - start );
		printf( encrypt( " > resolved module information in %llu ms\n" ) , duration.count( ) );
		printf( encrypt( "..............................................\n" ) );

		printf( encrypt( "resolving directory table base...\n" ) );

		start = std::chrono::high_resolution_clock::now( );

		std::jthread( [ & ] ( ) -> void { driver_ctx.resolve_directory_table_base( module_handle ); } ).detach( );
		std::unique_lock<std::mutex> lock( driver_ctx.mutex );
		driver_ctx.condition.wait( lock , [ &driver_ctx ] { return driver_ctx.get_directory_table_base( ) != 0; } );
		uintptr_t directory_table_base = driver_ctx.get_directory_table_base( );
		driver_ctx.flush_logs( );

		stop = std::chrono::high_resolution_clock::now( );
		duration = std::chrono::duration_cast< std::chrono::milliseconds >( stop - start );
		printf( encrypt( " > resolved directory table base in %llu ms\n" ) , duration.count( ) );
		printf( encrypt( " > directory table base : %llx\n" ) , directory_table_base );
		printf( encrypt( "..............................................\n" ) );

#ifdef _VALORANT
		printf( encrypt( "resolving guarded regions...\n" ) );
		start = std::chrono::high_resolution_clock::now( );
		uintptr_t guarded_region = driver_ctx.get_guarded_region( );
		driver_ctx.set_guarded_region( guarded_region );

		stop = std::chrono::high_resolution_clock::now( );
		duration = std::chrono::duration_cast< std::chrono::milliseconds >( stop - start );
		printf( encrypt( " > resolved guarded regions in %llu ms\n" ) , duration.count( ) );
		printf( encrypt( " > guarded region : %llx\n" ) , guarded_region );
		printf( encrypt( "..............................................\n" ) );
#endif // _VALORANT

#ifdef _FORTNITE
		//printf( encrypt( "resolving text section...\n" ) );
		//start = std::chrono::high_resolution_clock::now( );
		//uintptr_t text_section = driver_ctx.get_text_section( module_handle );

		//stop = std::chrono::high_resolution_clock::now( );
		//duration = std::chrono::duration_cast< std::chrono::milliseconds >( stop - start );
		//printf( encrypt( " > resolved text section in %llu ms\n" ) , duration.count( ) );
		//printf( encrypt( " > text section : %llx\n" ) , text_section );
		//printf( encrypt( "..............................................\n" ) );
#else
		static_assert ( false ,
			"Please change the use of text_section, on line 242 to module_handle for different configurations. DOUBLE CLICK AND DELETE ME!" );
#endif // _FORTNITE

		//if ( MessageBoxA( 0 , encrypt( "manual mapping will inject the local internal.dll file into the target process via PTE manipulation method." ) ,
		//	encrypt( "would you like to manual map into the target process?" ) ,
		//	MB_YESNO | MB_ICONSTOP | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_SETFOREGROUND ) == IDYES )
		//{
		std::getchar( );
		system( encrypt( "cls" ) );
		printf( encrypt( "=== Riot Execution :: injector::c_interface::prepare_injection() ===\n" ) );
		printf( encrypt( "......................................................................\n" ) );
		printf( encrypt( "preparing injection...\n" ) );

		injector::c_interface injector_ctx( driver_ctx );

		std::vector<uint8_t> file_buffer{ };
		injector_ctx.load_file( encrypt( "internal.dll" ).decrypt( ) , file_buffer );
		printf( encrypt( " > file buffer : %p\n" ) , file_buffer.data( ) );

		injector_ctx.set_target_image( file_buffer );
		if ( !injector_ctx.prepare_injection( ) ) {
			driver_ctx.unload_driver( );
			return std::getchar( );
		}

		if ( !injector_ctx.call_dll_main( ) ) {
			driver_ctx.unload_driver( );
			return std::getchar( );
		}

		printf( encrypt( " > successful, unloading.\n" ) );
		driver_ctx.unload_driver( );
		return std::getchar( );
		//}

		//auto setup_overlay = overlay->setup( process_id );
		//if ( !setup_overlay ) {
		//	printf( encrypt( " > failed to setup overlay.\n" ) );
		//	driver_ctx.unload_driver( );
		//	return std::getchar( );
		//}

		//driver::module_handle = text_section , driver::m_vm = driver_ctx.get( );
		//entity::c_interface entity_ctx;
		//std::jthread( [ & ] ( ) -> void { entity_ctx.tick( ); } ).detach( );
		//overlay->tick( entity_ctx.render_queue );
	}

	driver_ctx.unload_driver( );
	return std::getchar( );
}