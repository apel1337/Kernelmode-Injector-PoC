#include <core/linkers/gadget.h>

namespace riot
{
	namespace thread
	{
		[[ nodiscard ]] std::uintptr_t get_psp_cid_table( );

		[[ nodiscard ]] bool is_address_in_module_list(
			std::uint64_t address
		);

		[[ nodiscard ]] ethread* get_system_thread( );

		[[ nodiscard ]] bool copy_thread_flags( );
		[[ nodiscard ]] void revert_thread_flags( );

		[[ nodiscard ]] bool unlink_thread( );
	}
}