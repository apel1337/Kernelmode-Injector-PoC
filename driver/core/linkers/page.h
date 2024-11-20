#include <core/linkers/scan.h>

namespace riot
{
	namespace page
	{
		inline std::uint32_t m_free_pml4_index = -1;
		inline pml4e m_pml4_table[ 512 ]{ 0 };
		inline pml4e m_pdpt_table[ 512 ]{ 0 };
		inline pml4e m_pd_2mb_table[ 512 ][ 512 ]{ 0 };

		uintptr_t get_directory_table_base(
			uintptr_t base_address );
		uintptr_t translate_linear(
			uintptr_t virtual_address );

		bool map_physical_page(
			uintptr_t virtual_address );
		bool map_physical_memory(
			std::uint32_t pml4_index );

		void cache_pml4_table( ppml4e pml4_table );
		void cache_pdpt_table( ppml4e pdpt_table );
		void cache_pd_table( ppml4e pd_table );
		void cache_pt_table( ppte pt_table );

		std::uintptr_t get_free_4kb_memory_base( );
		std::uintptr_t get_free_2mb_memory_base( );
		std::uintptr_t get_free_1gb_memory_base( );

		std::uintptr_t calculate_pml4e_physical_memory_base(
			std::uint32_t pml4_index );
		std::uintptr_t calculate_pdpte_physical_memory_base(
			std::uint32_t pdpt_index );
		std::uintptr_t calculate_pde_physical_memory_base(
			std::uint32_t pd_index );

		void* get_mm_pfn_database( );
		std::uintptr_t get_self_referencing_pte_address( );
	}
}