#include <core/linkers/exports.h>

namespace riot
{
	namespace process
	{
		std::uintptr_t attach(
			std::uintptr_t e_process );

		std::uintptr_t get_eprocess(
			std::uint32_t process_id );

		std::uintptr_t get_eprocess(
			const wchar_t* process_name );

		std::uintptr_t get_process_cr3(
			std::uintptr_t e_process );
	}
}