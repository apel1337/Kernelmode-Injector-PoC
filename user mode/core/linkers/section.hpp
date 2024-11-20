#include <core/linkers/instrum.hpp>

namespace riot
{
	namespace section
	{
		class c_interface
		{
		public:
			c_interface( std::size_t size ) :
				size( size ) , 
				local_address( nullptr ) , 
				remote_address( nullptr ) ,
				handle( nullptr ) { };

			bool create( );
			bool map_view( HANDLE process_handle , DWORD permissions );
			bool unmap_view( HANDLE process_handle );

			std::size_t get_size( );

			PVOID get_remote_address( );
			PVOID get_local_address( );

		private:
			HANDLE handle;
			std::size_t size;

			PVOID local_address;
			PVOID remote_address;
		};

		inline bool load_ntdll_functions( )
		{
			auto ntdll = GetModuleHandleA( "ntdll.dll" );
			if ( !ntdll ) return false;

			NtMapViewOfSection = reinterpret_cast< f_NtMapViewOfSection >(
				GetProcAddress( ntdll , encrypt( "NtMapViewOfSection" ) ) );
			if ( !NtMapViewOfSection ) return false;

			NtUnmapViewOfSection = reinterpret_cast< f_NtUnmapViewOfSection >(
				GetProcAddress( ntdll , encrypt( "NtUnmapViewOfSection" ) ) );
			if ( !NtUnmapViewOfSection ) return false;

			NtCreateSection = reinterpret_cast< f_NtCreateSection >(
				GetProcAddress( ntdll , encrypt( "NtCreateSection" ) ) );
			if ( !NtCreateSection ) return false;

			return true;
		}
	}
}