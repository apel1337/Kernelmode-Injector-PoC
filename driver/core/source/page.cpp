#include <core/linkers/page.h>

namespace riot
{
	namespace page
	{
		uintptr_t get_self_referencing_pte_address( )
		{
			ppml4e pml4e = nullptr;
			ppml4e pdpte = nullptr;
			ppml4e pde = nullptr;
			ppte pte = nullptr;

			cr3 system_dirbase{ };
			system_dirbase.flags = __readcr3( );
			auto phsical_system_directory = system_dirbase.page_frame_number << 12;
			auto system_directory = reinterpret_cast< ppml4e > (
				exports::get_virtual_for_physical( phsical_system_directory ) );
			for ( std::uint64_t idx = 0; idx < 512; idx++ )
			{
				const auto& pml4e = system_directory[ idx ];
				if ( !pml4e.hard.present ) continue;
				if ( pml4e.hard.pfn != system_dirbase.page_frame_number ) continue;

				auto pml4 = ( idx + 0x1FFFE00ui64 ) << 39ui64;
				auto pdpt = ( idx << 30ui64 ) + pml4;
				auto pd = ( idx << 30ui64 ) + pml4 + ( idx << 21ui64 );
				auto pt = ( idx << 12ui64 ) + pdpt;
				return idx * 8 + pt;
			}

			return 0;
		}

		void* get_mm_pfn_database( ) {
			unsigned char shellcode[ ] = {
				0x48, 0x8B, 0xC1,		// mov     rax, rcx
				0x48, 0xC1, 0xE8, 0x0C, // shr     rax, 0Ch
				0x48, 0x8D, 0x14, 0x40, // lea     rdx, [rax + rax * 2]
				0x48, 0x03, 0xD2,		// add     rdx, rdx
				0x48, 0xB8,				// mov     rax, 0FFFFFA8000000008h
			};

			auto mm_get_virtual_for_physical =
				exports::find_export<unsigned char*>( encrypt( "MmGetVirtualForPhysical" ) );
			if ( !mm_get_virtual_for_physical ) {
				return nullptr;
			}

			auto* function = reinterpret_cast< unsigned char* >(
				scan::split_memory( mm_get_virtual_for_physical , 0x20 , shellcode ) );
			if ( !function ) {
				return nullptr;
			}

			return PAGE_ALIGN(
				*reinterpret_cast< ppfn* >(
					function + sizeof( shellcode ) ) );
		}

		uintptr_t translate_linear( uintptr_t virtual_address )
		{
			_virt_addr_t virt_addr{ virtual_address };

			auto pml4_entry = g::pml4_table[ virt_addr.pml4e_index ];
			if ( !pml4_entry.hard.present ) return 0;

			auto pdpt_entry = g::pdpt_table[ virt_addr.pdpte_index ];
			if ( !pdpt_entry.hard.present ) return 0;

			if ( pdpt_entry.hard.large_page ) {
				pte pdpte_1gb_entry { pdpt_entry.value };

				return ( pdpte_1gb_entry.hard.pfn << 30 ) + virt_addr.offset_1gb;
			}

			auto pd_entry = g::pdpt_table[ virt_addr.pde_index ];
			if ( !pd_entry.hard.present ) return 0;

			if ( pd_entry.hard.large_page ) {
				pte pde_2mb_entry{ pd_entry.value };

				return ( pde_2mb_entry.hard.pfn << 21 ) + virt_addr.offset_2mb;
			}

			auto pt_entry = g::pt_table[ virt_addr.pte_index ];
			if ( !pt_entry.hard.present ) return 0;

			return ( pt_entry.hard.pfn << 12 ) * virt_addr.offset_4kb;
		}

		uintptr_t get_directory_table_base( uintptr_t base_address )
		{
			_virt_addr_t virtual_address{ base_address };

			auto physical_ranges = exports::mm_get_physical_memory_ranges( );
			for ( std::uint32_t idx = 0; idx < 512 ; idx++ ) {
				auto physical_range = physical_ranges[ idx ];
				if ( !physical_range.BaseAddress.QuadPart || !physical_range.NumberOfBytes.QuadPart )
					break;

				std::uint64_t start_pfn = physical_range.BaseAddress.QuadPart >> 12;
				std::uint64_t end_pfn = start_pfn + ( physical_range.NumberOfBytes.QuadPart >> 12 );
				client::m_client->log_print( "scanning PFNs in range [%llx - %llx]" , start_pfn , end_pfn );

				for ( auto current_pfn = start_pfn; current_pfn < end_pfn; current_pfn++ ) {
					cr3 process_cr3{ current_pfn << 12 };
					if ( !process_cr3.flags ) continue;
					if ( ( process_cr3.flags & 0xFFFFFFFFFF000 ) < 0x100000 ) {
						continue;
					}

					auto pnf_entry = &g::mm_pfn_database[ process_cr3.page_frame_number ];
					if ( pnf_entry->flags.modified > 1 || pnf_entry->flags.read_in_progress > 1 || pnf_entry->flags.write_in_progress > 1 ) {
						client::m_client->log_print( encrypt( "invalid page flags: modified [%llx], read_in_progress [%llx], write_in_progress [%llx]" ) ,
							pnf_entry->flags.modified , pnf_entry->flags.read_in_progress , pnf_entry->flags.write_in_progress );
						continue;
					}

					pml4e pml4_table[ 512 ]{};
					auto status = rwx::read_physical_address( process_cr3.page_frame_number << 12 , &pml4_table , sizeof( pml4_table ) );
					if ( !status && !pml4_table ) continue;

					auto pml4_entry = pml4_table[ virtual_address.pml4e_index ];
					if ( !pml4_entry.hard.present ) continue;
					cache_pml4_table( pml4_table );

					pml4e pdpt_table[ 512 ]{};
					status = rwx::read_physical_address( pml4_entry.hard.pfn << 12 , &pdpt_table , sizeof( pdpt_table ) );
					if ( !status && !pdpt_table ) continue;

					auto pdpt_entry = pdpt_table[ virtual_address.pdpte_index ];
					if ( !pdpt_entry.hard.present ) continue;
					cache_pdpt_table( pdpt_table );

					pml4e pd_table[ 512 ]{};
					status = rwx::read_physical_address( pdpt_entry.hard.pfn << 12 , &pd_table , sizeof( pd_table ) );
					if ( !status && !pd_table ) continue;

					auto pd_entry = pd_table[ virtual_address.pde_index ];
					if ( !pd_entry.hard.present ) continue;
					cache_pd_table( pd_table );

					pte pt_table[ 512 ]{};
					status = rwx::read_physical_address( pd_entry.hard.pfn << 12 , &pt_table , sizeof( pt_table ) );
					if ( !status && !pt_table ) continue;

					auto pt_entry = pt_table[ virtual_address.pte_index ];
					if ( !pt_entry.hard.present ) continue;
					cache_pt_table( pt_table );

					client::m_client->log_print( "free pml4 index [%i]" , m_free_pml4_index );
					client::m_client->log_print( "mapped pml4e [%llx]" , g::pml4_table[ virtual_address.pml4e_index ] );
					client::m_client->log_print( "mapped pdpte [%llx]" , g::pdpt_table[ virtual_address.pdpte_index ] );
					client::m_client->log_print( "mapped pde [%llx]" , g::pd_table[ virtual_address.pde_index ] );
					client::m_client->log_print( "mapped pte [%llx]" , g::pt_table[ virtual_address.pte_index ] );

					return process_cr3.flags;
				}
			}

			return 0;
		}

		bool map_physical_memory( std::uint32_t free_pml4_idx )
		{
			m_pml4_table[ free_pml4_idx ].hard.present = 1;
			m_pml4_table[ free_pml4_idx ].hard.read_write = 1;
			m_pml4_table[ free_pml4_idx ].hard.pfn = exports::get_physical_address( reinterpret_cast< std::uintptr_t >( &m_pdpt_table ) ) >> 12;
			m_pml4_table[ free_pml4_idx ].hard.no_execute = 0;
			if ( !m_pml4_table[ free_pml4_idx ].hard.pfn )
				return false;

			for ( std::uint32_t idx = 0; idx < 512; idx++ )
			{
				m_pdpt_table[ idx ].hard.present = 1;
				m_pdpt_table[ idx ].hard.read_write = 1;
				m_pdpt_table[ idx ].hard.pfn = exports::get_physical_address( reinterpret_cast< std::uintptr_t >( &m_pd_2mb_table[ idx ] ) ) >> 12;
				m_pdpt_table[ idx ].hard.no_execute = 0;
				if ( !m_pdpt_table[ idx ].hard.pfn )
					return false;

				for ( std::uint32_t i = 0; i < 512; i++ )
				{
					m_pd_2mb_table[ idx ][ i ].hard.present = 1;
					m_pd_2mb_table[ idx ][ i ].hard.read_write = 1;
					m_pd_2mb_table[ idx ][ i ].hard.large_page = 1;
					m_pd_2mb_table[ idx ][ i ].hard.no_execute = 0;
					m_pd_2mb_table[ idx ][ i ].hard.pfn = ( idx << 9 ) + i;
				}
			}

			return true;
		}

		bool map_physical_page( uintptr_t virtual_address )
		{
			_virt_addr_t virt_addr{ virtual_address };

			auto pml4_table =
				reinterpret_cast< ppml4e >( exports::get_physical_address( __readcr3( ) ) );
			if ( !pml4_table ) return false;

			auto pdpt_table =
				reinterpret_cast< ppml4e >( exports::get_physical_address( pml4_table[ virt_addr.pml4e_index ].hard.pfn << 12 ) );
			if ( !pdpt_table )
			{
				auto allocation_base = exports::mm_allocate_contiguous_memory( 0x1000 );
				if ( !allocation_base ) return false;
				std::memset( allocation_base , 0 , 0x1000 );

				auto page_frame_number = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( allocation_base ) ) >> 12;
				if ( !page_frame_number ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}

				auto pte_table =
					reinterpret_cast< ppte >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pte_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pte_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pte_table ) ) >> 12;
				if ( !pte_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					return false;
				}

				auto pde_table =
					reinterpret_cast< ppml4e >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pde_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pde_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pde_table ) ) >> 12;
				if ( !pde_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					exports::mm_free_contiguous_memory( pde_table );
					return false;
				}

				auto pdpte_table =
					reinterpret_cast< ppml4e >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pdpte_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					exports::mm_free_contiguous_memory( pde_table );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pdpte_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pdpte_table ) ) >> 12;
				if ( !pdpte_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					exports::mm_free_contiguous_memory( pde_table );
					exports::mm_free_contiguous_memory( pdpte_table );
					return false;
				}

				pte_table[ virt_addr.pte_index ].value = 0;
				pte_table[ virt_addr.pte_index ].hard.present = 1;
				pte_table[ virt_addr.pte_index ].hard.page_write_through = 1;
				pte_table[ virt_addr.pte_index ].hard.global_page = 1;
				pte_table[ virt_addr.pte_index ].hard.no_execute = 0;
				pte_table[ virt_addr.pte_index ].hard.pfn = page_frame_number;

				pde_table[ virt_addr.pde_index ].value = 0;
				pde_table[ virt_addr.pde_index ].hard.present = 1;
				pde_table[ virt_addr.pde_index ].hard.page_write_through = 1;
				pde_table[ virt_addr.pde_index ].hard.no_execute = 0;
				pde_table[ virt_addr.pde_index ].hard.pfn = pte_pfn;

				pdpte_table[ virt_addr.pdpte_index ].value = 0;
				pdpte_table[ virt_addr.pdpte_index ].hard.present = 1;
				pdpte_table[ virt_addr.pdpte_index ].hard.page_write_through = 1;
				pdpte_table[ virt_addr.pdpte_index ].hard.no_execute = 0;
				pdpte_table[ virt_addr.pdpte_index ].hard.pfn = pde_pfn;

				pml4_table[ virt_addr.pml4e_index ].value = 0;
				pml4_table[ virt_addr.pml4e_index ].hard.present = 1;
				pml4_table[ virt_addr.pml4e_index ].hard.page_write_through = 1;
				pml4_table[ virt_addr.pml4e_index ].hard.no_execute = 0;
				pml4_table[ virt_addr.pml4e_index ].hard.pfn = pdpte_pfn;

				__invlpg( reinterpret_cast< void* >( virtual_address ) );

				return true;
			}

			auto pde_table =
				reinterpret_cast< ppml4e >( exports::get_physical_address( pdpt_table[ virt_addr.pdpte_index ].hard.pfn << 12 ) );
			if ( !pde_table )
			{
				auto allocation_base = exports::mm_allocate_contiguous_memory( 0x1000 );
				if ( !allocation_base ) return false;
				std::memset( allocation_base , 0 , 0x1000 );

				auto page_frame_number = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( allocation_base ) ) >> 12;
				if ( !page_frame_number ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}

				auto pte_table =
					reinterpret_cast< ppte >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pte_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pte_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pte_table ) ) >> 12;
				if ( !pte_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					return false;
				}

				auto pde_table =
					reinterpret_cast< ppml4e >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pde_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pde_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pde_table ) ) >> 12;
				if ( !pde_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					exports::mm_free_contiguous_memory( pde_table );
					return false;
				}

				pte_table[ virt_addr.pte_index ].value = 0;
				pte_table[ virt_addr.pte_index ].hard.present = 1;
				pte_table[ virt_addr.pte_index ].hard.page_write_through = 1;
				pte_table[ virt_addr.pte_index ].hard.global_page = 1;
				pte_table[ virt_addr.pte_index ].hard.no_execute = 0;
				pte_table[ virt_addr.pte_index ].hard.pfn = page_frame_number;

				pde_table[ virt_addr.pde_index ].value = 0;
				pde_table[ virt_addr.pde_index ].hard.present = 1;
				pde_table[ virt_addr.pde_index ].hard.page_write_through = 1;
				pde_table[ virt_addr.pde_index ].hard.no_execute = 0;
				pde_table[ virt_addr.pde_index ].hard.pfn = pte_pfn;

				pdpt_table[ virt_addr.pdpte_index ].value = 0;
				pdpt_table[ virt_addr.pdpte_index ].hard.present = 1;
				pdpt_table[ virt_addr.pdpte_index ].hard.page_write_through = 1;
				pdpt_table[ virt_addr.pdpte_index ].hard.no_execute = 0;
				pdpt_table[ virt_addr.pdpte_index ].hard.pfn = pde_pfn;

				__invlpg( reinterpret_cast< void* >( virtual_address ) );

				return true;
			}

			auto pte_table =
				reinterpret_cast< ppte >( exports::get_physical_address( pde_table[ virt_addr.pde_index ].hard.pfn << 12 ) );
			if ( !pte_table )
			{
				auto allocation_base = exports::mm_allocate_contiguous_memory( 0x1000 );
				if ( !allocation_base ) return false;
				std::memset( allocation_base , 0 , 0x1000 );

				auto page_frame_number = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( allocation_base ) ) >> 12;
				if ( !page_frame_number ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}

				pte_table =
					reinterpret_cast< ppte >( exports::mm_allocate_contiguous_memory( 0x1000 ) );
				if ( !pte_table ) {
					exports::mm_free_contiguous_memory( allocation_base );
					return false;
				}
				std::memset( pte_table , 0 , 0x1000 );

				auto pte_pfn = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( pte_table ) ) >> 12;
				if ( !pte_pfn ) {
					exports::mm_free_contiguous_memory( allocation_base );
					exports::mm_free_contiguous_memory( pte_table );
					return false;
				}

				pte_table[ virt_addr.pte_index ].value = 0;
				pte_table[ virt_addr.pte_index ].hard.present = 1;
				pte_table[ virt_addr.pte_index ].hard.page_write_through = 1;
				pte_table[ virt_addr.pte_index ].hard.global_page = 1;
				pte_table[ virt_addr.pte_index ].hard.no_execute = 0;
				pte_table[ virt_addr.pte_index ].hard.pfn = page_frame_number;

				pde_table[ virt_addr.pde_index ].value = 0;
				pde_table[ virt_addr.pde_index ].hard.present = 1;
				pde_table[ virt_addr.pde_index ].hard.page_write_through = 1;
				pde_table[ virt_addr.pde_index ].hard.no_execute = 0;
				pde_table[ virt_addr.pde_index ].hard.pfn = pte_pfn;

				__invlpg( reinterpret_cast< void* >( virtual_address ) );

				return true;
			}

			auto allocation_base = exports::mm_allocate_contiguous_memory( 0x1000 );
			if ( !allocation_base ) return false;
			std::memset( allocation_base , 0 , 0x1000 );

			auto page_frame_number = exports::get_virtual_for_physical( reinterpret_cast< uintptr_t >( allocation_base ) ) >> 12;
			if ( !page_frame_number ) {
				exports::mm_free_contiguous_memory( allocation_base );
				return false;
			}

			pte_table[ virt_addr.pte_index ].value = 0;
			pte_table[ virt_addr.pte_index ].hard.present = 1;
			pte_table[ virt_addr.pte_index ].hard.page_write_through = 1;
			pte_table[ virt_addr.pte_index ].hard.global_page = 1;
			pte_table[ virt_addr.pte_index ].hard.no_execute = 0;
			pte_table[ virt_addr.pte_index ].hard.pfn = page_frame_number;

			__invlpg( reinterpret_cast< void* >( virtual_address ) );

			return true;
		}

		void cache_pml4_table( ppml4e pml4_table )
		{
			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto pml4_entry = pml4_table[ idx ];
				if ( !pml4_entry.hard.present ) {
					g::free_4kb_pml4_table[ idx ] = pml4_entry;
					continue;
				}

				g::pml4_table[ idx ] = pml4_entry;
			}
		}

		void cache_pdpt_table( ppml4e pdpt_table )
		{
			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto pdpt_entry = pdpt_table[ idx ];
				if ( !pdpt_entry.hard.present ) {
					if ( pdpt_entry.hard.large_page ) {
						g::free_1gb_pdpt_table[ idx ] = pdpt_entry;
					}
					continue;
				}

				g::pdpt_table[ idx ] = pdpt_entry;
			}
		}

		void cache_pd_table( ppml4e pd_table )
		{
			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto pd_entry = pd_table[ idx ];
				if ( !pd_entry.hard.present ) {
					if ( pd_entry.hard.large_page ) {
						g::free_2mb_pd_table[ idx ] = pd_entry;
					}
					continue;
				}

				g::pd_table[ idx ] = pd_entry;
			}
		}

		void cache_pt_table( ppte pt_table )
		{
			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto pt_entry = pt_table[ idx ];
				if ( !pt_entry.hard.present ) continue;

				g::pt_table[ idx ] = pt_entry;
			}
		}

		std::uintptr_t get_free_4kb_memory_base( )
		{
			if ( g::free_4kb_pml4_table == nullptr ) return 0;

			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto free_4kb_pml4_entry = g::free_4kb_pml4_table[ idx ];
				if ( free_4kb_pml4_entry.hard.present ) continue;
				free_4kb_pml4_entry.hard.no_execute = 0;

				auto physical_memory_base = calculate_pml4e_physical_memory_base( idx );
				if ( !physical_memory_base ) continue;
				if ( ( physical_memory_base >> 47 ) != 0 ) continue; // is address canonical

				if ( physical_memory_base % 0x1000 ) continue; // is address aligned
				if ( physical_memory_base > 0xFFFFFFFFFFFF ) continue; // check if within max physical address limit
				if ( physical_memory_base < 0x100000 ) continue; // is address in reserved ranges (first 1MB)

				auto virtual_memory_base = reinterpret_cast< std::uintptr_t >(
					exports::mm_map_io_space( physical_memory_base , 0x1000 ) );
				if ( !virtual_memory_base ) continue;

				if ( !virtual_memory_base % 0x1000 ) continue; // is address aligned
				if ( virtual_memory_base < 0xFFFF800000000000 ) continue; // is address in kernel space
				if ( virtual_memory_base > 0xFFFFFFFFFFFFFFFE - 0x1000 ) continue; // check overflow

				map_physical_page( virtual_memory_base );

				g::free_4kb_pml4_table[ idx ].hard.present = 1; // mark entry as used
				return virtual_memory_base;
			}

			return 0;
		}

		std::uintptr_t get_free_2mb_memory_base( )
		{
			if ( g::free_2mb_pd_table == nullptr ) return 0;

			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto free_2mb_pd_entry = g::free_2mb_pd_table[ idx ];
				if ( free_2mb_pd_entry.hard.present ) continue;
				if ( !free_2mb_pd_entry.hard.large_page ) continue;
				free_2mb_pd_entry.hard.no_execute = 0;

				auto physical_memory_base = calculate_pde_physical_memory_base( idx );
				if ( !physical_memory_base ) continue;
				if ( ( physical_memory_base >> 47 ) != 0 ) continue; // is address canonical

				if ( physical_memory_base % 0x200000 ) continue; // is address aligned
				if ( physical_memory_base > 0xFFFFFFFFFFFF ) continue; // check if within max physical address limit
				if ( physical_memory_base < 0x100000 ) continue; // is address in reserved ranges (first 1MB)

				auto virtual_memory_base = reinterpret_cast< std::uintptr_t >(
					exports::mm_map_io_space( physical_memory_base , 0x200000 ) );
				if ( !virtual_memory_base ) continue;

				if ( virtual_memory_base % 0x200000 ) continue; // is address aligned
				if ( virtual_memory_base < 0xFFFF800000000000 ) continue; // is address in kernel space
				if ( virtual_memory_base > 0xFFFFFFFFFFFFFFFE - 0x200000 ) continue; // check overflow

				map_physical_page( virtual_memory_base );

				g::free_2mb_pd_table[ idx ].hard.present = 1; // mark entry as used
				return virtual_memory_base;
			}

			return 0;
		}

		std::uintptr_t get_free_1gb_memory_base( )
		{
			if ( g::free_1gb_pdpt_table == nullptr ) return 0;

			for ( std::uint32_t idx = 0; idx < oxorany( 512 ); idx++ )
			{
				auto free_1gb_pdpt_entry = g::free_1gb_pdpt_table[ idx ];
				if ( free_1gb_pdpt_entry.hard.present ) continue;
				if ( !free_1gb_pdpt_entry.hard.large_page ) continue;
				free_1gb_pdpt_entry.hard.no_execute = 0;

				auto physical_memory_base = calculate_pdpte_physical_memory_base( idx );
				if ( !physical_memory_base ) continue;
				if ( ( physical_memory_base >> 47 ) != 0 ) continue; // is address canonical

				if ( physical_memory_base % 0x40000000 ) continue; // is address aligned
				if ( physical_memory_base > 0xFFFFFFFFFFFF ) continue; // check if within max physical address limit
				if ( physical_memory_base < 0x100000 ) continue; // is address in reserved ranges (first 1MB)

				auto virtual_memory_base = reinterpret_cast< std::uintptr_t >(
					exports::mm_map_io_space( physical_memory_base , 0x40000000 ) );
				if ( !virtual_memory_base ) continue;

				if ( virtual_memory_base % 0x40000000 ) continue; // is address aligned
				if ( virtual_memory_base < 0xFFFF800000000000 ) continue; // is address in kernel space
				if ( virtual_memory_base > 0xFFFFFFFFFFFFFFFE - 0x40000000 ) continue; // check overflow

				map_physical_page( virtual_memory_base );

				g::free_1gb_pdpt_table[ idx ].hard.present = 1; // mark entry as used
				return virtual_memory_base;
			}

			return 0;
		}

		std::uintptr_t calculate_pml4e_physical_memory_base( std::uint32_t pml4e_idx )
		{
			return static_cast< std::uintptr_t >( pml4e_idx ) << 36;
		}

		std::uintptr_t calculate_pdpte_physical_memory_base( std::uint32_t pdpt_index )
		{
			return static_cast< std::uintptr_t >( pdpt_index ) << 27;
		}

		std::uintptr_t calculate_pde_physical_memory_base( std::uint32_t pd_index )
		{
			return static_cast< std::uintptr_t >( pd_index ) << 18;
		}
	}
}