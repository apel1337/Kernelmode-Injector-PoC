#include <core/linkers/nmi.h>

namespace riot
{
	namespace gadget
	{
		bool find_gadget( uintptr_t driver_base_address , uintptr_t* used_jmp_rcx_gadget );
		bool create_gagdet( uintptr_t driver_base_address , void* thread_function );
	}
}