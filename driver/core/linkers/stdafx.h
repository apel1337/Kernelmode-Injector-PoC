#include <core/linkers/ia32.h>
#include <core/backend/skcrypt/skcrypter.h>
#include <core/backend/oxorany/oxorany_include.h>

namespace riot
{
	enum class error : int
	{
		error_success = 0 ,
		error_unknown = 1 ,
		error_parameters = 2 ,
		error_unsupported = 3 ,
		error_interrupts = 4 ,
		error_communication = 5 ,
		error_gadget = 6 ,
	};

	namespace g
	{
		inline void* allocation_pool = nullptr;
		inline uintptr_t ntos_base_address = 0;

		inline uintptr_t self_referencing_pte_address = 0;
		inline ppfn mm_pfn_database = nullptr;
		inline HANDLE thread_handle = nullptr;

		inline pml4e pml4_table[ 512 ];
		inline pml4e pdpt_table[ 512 ];
		inline pml4e pd_table[ 512 ];
		inline pte pt_table[ 512 ];

		inline pml4e free_4kb_pml4_table[ 512 ];
		inline pml4e free_1gb_pdpt_table[ 512 ];
		inline pml4e free_2mb_pd_table[ 512 ];
	}
}