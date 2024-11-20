#include <core/linkers/section.hpp>

namespace riot
{
	namespace section
	{
		bool c_interface::create( ) {
			auto status = NtCreateSection( &handle , SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE , NULL , reinterpret_cast< PLARGE_INTEGER >( &size ) , PAGE_EXECUTE_READWRITE , SEC_COMMIT , NULL );
			if ( status < 0 )
				return false;

			printf( encrypt( " > created section (size : %llx)\n" ) , size );
			return true;
		}

		bool c_interface::map_view( HANDLE process_handle , DWORD permissions ) {
			const auto address = ( process_handle == GetCurrentProcess( ) ) ? &local_address : &remote_address;
			auto status = NtMapViewOfSection( handle , process_handle , address , NULL , NULL , NULL , &size , 2 , NULL , permissions );
			if ( status == 0 && handle == nullptr ) {
				printf( encrypt( " > failed to map view of section : 0x%X\n" ) , GetLastError( ) );
				return false;
			}

			printf( encrypt( " > mapped view of section for handle : %llx\n" ) , handle );
			return true;
		}

		bool c_interface::unmap_view( HANDLE process_handle ) {
			const auto address = ( process_handle == GetCurrentProcess( ) ) ? &local_address : &remote_address;
			auto status = NtUnmapViewOfSection( process_handle , address );
			if ( status < 0 )
				return false;

			printf( encrypt( " > unmapped view of section.\n" ) );
			return true;
		}

		std::size_t c_interface::get_size( ) {
			return size;
		}

		PVOID c_interface::get_remote_address( ) {
			return remote_address;
		}

		PVOID c_interface::get_local_address( ) {
			return local_address;
		}
	}
}