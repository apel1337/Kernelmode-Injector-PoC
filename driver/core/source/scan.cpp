#include <core/linkers/scan.h>

namespace riot
{
	namespace scan
	{
		[[ nodiscard ]] bool check_mask ( 
			const char* base , 
			const char* pattern , 
			const char* mask 
		) {
			for ( ; *mask; ++base , ++pattern , ++mask ) {
				if ( *mask == oxorany( 'x' ) && *base != *pattern ) {
					return oxorany( false );
				}
			}

			return oxorany( true );
		};

		[[ nodiscard ]] std::uintptr_t find_pattern( 
			std::uintptr_t base_address , 
			std::uint64_t size_of_address , 
			const char* pattern ,
			const char* mask 
		) {
			size_of_address = size_of_address - std::strlen( mask );

			for ( size_t idx = 0; idx < size_of_address; ++idx ) {
				if ( check_mask( reinterpret_cast< const char* >( base_address + idx ) ,  pattern , mask ) ) {
					return base_address + idx;
				}
			}

			return oxorany( NULL );
		}

		[[ nodiscard ]] void* split_memory(
			void* start , 
			size_t size , 
			const void* pattern 
		) {
			auto module_start = static_cast< const unsigned char* >( start );
			auto pattern_start = static_cast< const unsigned char* >( pattern );

			for ( std::uintptr_t idx = 0; idx < size - sizeof( pattern ); ++idx )
			{
				size_t i = 0;
				for ( ; i < sizeof( pattern ); ++i ) {
					if ( module_start[ idx + i ] != pattern_start[ i ] )
						break;
				}

				if ( i == sizeof( pattern ) ) return const_cast< unsigned char* >( &module_start[ idx ] );
			}

			return nullptr;
		}
	}
}