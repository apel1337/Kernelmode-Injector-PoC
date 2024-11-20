#include <core/linkers/client.h>

namespace riot
{
	namespace rwx
	{
		bool read_physical_address (
			std::uint64_t address ,
			void* buffer ,
			std::uint64_t size );

		bool write_physical_address (
			std::uint64_t address , 
			void* buffer ,
			std::uint64_t size );

		bool discover_next_executable_section(
			std::uint64_t image_base ,
			std::uint64_t* executable_section_base ,
			std::uint64_t* executable_section_size );
	}
}