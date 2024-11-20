#include <core/linkers/rwx.h>

namespace riot
{
	namespace rwx
	{
		bool read_physical_address ( std::uint64_t address , void* buffer , std::uint64_t size )
		{
			MM_COPY_ADDRESS phyiscal_address = { };
			phyiscal_address.PhysicalAddress.QuadPart = address;

			SIZE_T number_of_bytes = 0;
			return exports::mm_copy_memory ( buffer , phyiscal_address , size , oxorany ( MM_COPY_MEMORY_PHYSICAL ) , &number_of_bytes ) == nt_status_t::success;
		}

		bool write_physical_address ( std::uint64_t address , void* buffer , std::uint64_t size )
		{
			PHYSICAL_ADDRESS address_to_write = { };
			address_to_write.QuadPart = address;

			auto mapped_page = exports::map_io_space_ex ( address_to_write , size , oxorany ( PAGE_READWRITE ) );
			if ( !mapped_page ) {
				return false;
			}

			std::memcpy ( mapped_page , buffer , size );

			exports::mm_unmap_io_space ( mapped_page , size );
			return true;
		}

		bool discover_next_executable_section( std::uint64_t image_base , std::uint64_t* executable_section_base , std::uint64_t* executable_section_size )
		{
			bool status = true;

			bool has_found_start_section_base = false;
			if ( *executable_section_base == 0 )
			{
				has_found_start_section_base = true;
			}

			auto driver_dos_header = reinterpret_cast< dos_header_t* >( image_base );
			if ( !driver_dos_header->is_valid( ) )
			{
				status = false;
				goto exit;
			}

			auto driver_nt_header = reinterpret_cast< nt_headers_t* >( reinterpret_cast< ULONG_PTR >( driver_dos_header ) + driver_dos_header->m_lfanew );
			if ( !driver_nt_header->is_valid( ) )
			{
				status = false;
				goto exit;
			}

			auto driver_section_header = reinterpret_cast< section_header_t* >( 
				reinterpret_cast< std::uintptr_t >( driver_nt_header ) + 
				driver_nt_header->m_size_of_optional_header + 0x18 );

			for ( int i = 0; i < driver_nt_header->m_number_of_sections; i++ )
			{
				auto current_section_base = reinterpret_cast< std::uint64_t >( driver_dos_header ) + driver_section_header[ i ].m_virtual_address;
				if ( has_found_start_section_base == FALSE && current_section_base == *executable_section_base )
				{
					has_found_start_section_base = TRUE;
					continue;
				}
				else if ( has_found_start_section_base && driver_section_header[ i ].m_characteristics & 0x20000000 /*IMAGE_SCN_MEM_EXECUTE*/ )
				{
					*executable_section_base = current_section_base;
					*executable_section_size = driver_section_header[ i ].m_size_of_raw_data;
					break;
				}
			}
		exit:
			return status;
		}
	}
}