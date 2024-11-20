#include <core/linkers/rwx.h>

namespace riot
{
	namespace scan
	{
		[[ nodiscard ]] bool check_mask(
			const char* base ,
			const char* pattern ,
			const char* mask 
		);

		[[ nodiscard ]] std::uintptr_t find_pattern(
			std::uintptr_t base_address ,
			std::uint64_t size_of_address ,
			const char* pattern ,
			const char* mask 
		);

		[[ nodiscard ]] void* split_memory(
			void* start ,
			size_t size ,
			const void* pattern 
		);
	}
}