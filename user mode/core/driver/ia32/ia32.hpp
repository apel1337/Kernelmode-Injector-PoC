#pragma once

namespace riot
{
	typedef union _virt_addr_t
	{
		std::uintptr_t value;
		struct
		{
			std::uint64_t offset : 12;
			std::uint64_t pt_index : 9;
			std::uint64_t pd_index : 9;
			std::uint64_t pdpt_index : 9;
			std::uint64_t pml4_index : 9;
			std::uint64_t reserved : 16;
		};
	} virt_addr_t , * pvirt_addr_t;
	static_assert( sizeof( virt_addr_t ) == sizeof( PVOID ) , "Size mismatch, only 64-bit supported." );

	typedef union _pml4e
	{
		struct
		{
			std::uint64_t present : 1;					// Must be 1 if the region is valid.
			std::uint64_t read_write : 1;				// Write access control (0 = read-only, 1 = read/write)
			std::uint64_t user_supervisor : 1;			// User/supervisor access control (0 = supervisor, 1 = user)
			std::uint64_t page_write_through : 1;		// Write-through caching
			std::uint64_t cached_disable : 1;			// Cache disable (1 = disable caching)
			std::uint64_t accessed : 1;					// Set when accessed
			std::uint64_t dirty : 1;					// Set when written to (only valid for large pages)
			std::uint64_t page_size : 1;				// Set if mapping a 1GB page (1 = large page)
			std::uint64_t ignored1 : 4;					// Ignored by hardware
			std::uint64_t pfn : 36;						// Physical frame number of the 4KB page
			std::uint64_t reserved_for_software : 4;	// Reserved for software use only
			std::uint64_t reserved_for_hardware : 11;	// Reserved for hardware use only
			std::uint64_t no_execute : 1;				// No-execute (NX) bit, set to disable execution
		} hard;

		std::uint64_t value;
	} pml4e , * ppml4e;
	static_assert( sizeof( pml4e ) == sizeof( void* ) , "size mismatch, only 64-bit supported." );

	typedef union _pte
	{
		struct
		{
			std::uint64_t present : 1;                // Must be 1 if the page is valid
			std::uint64_t read_write : 1;             // Write access control (0 = read-only, 1 = read/write)
			std::uint64_t user_supervisor : 1;        // User/supervisor access control (0 = supervisor, 1 = user)
			std::uint64_t page_write_through : 1;     // Write-through caching
			std::uint64_t cached_disable : 1;         // Cache disable (1 = disable caching)
			std::uint64_t accessed : 1;               // Set when accessed
			std::uint64_t dirty : 1;                  // Set when written to
			std::uint64_t global_page : 1;            // Set if the page is global (won't be flushed on CR3 switch)
			std::uint64_t ignored1 : 3;               // Ignored by hardware
			std::uint64_t pfn : 36;                   // Physical frame number of the 4KB page
			std::uint64_t reserved : 4;               // Reserved for future use
			std::uint64_t ignored2 : 7;               // Ignored by software
			std::uint64_t protection_key : 4;         // Protection Key (if PKE bit in CR4 is set)
			std::uint64_t no_execute : 1;             // No-execute (NX) bit, set to disable execution
		} hard;

		std::uint64_t value;
	} pte , * ppte;
	static_assert( sizeof( pte ) == sizeof( void* ) , "size mismatch, only 64-bit supported." );

	struct pt_entries
	{
		std::pair<ppml4e , pml4e>	pml4;
		std::pair<ppml4e , pml4e>		pdpt;
		std::pair<ppml4e , pml4e>		pd;
		std::pair<ppte , pte>			pt;
	};

	typedef struct _rtl_balanced_node {
		union {
			struct _rtl_balanced_node* children[ 2 ];
			struct {
				struct _rtl_balanced_node* left;
				struct _rtl_balanced_node* right;
			};
		};

		union {
			UCHAR red : 1;
			UCHAR balance : 2;
			ULONG_PTR parentvalue;
		};
	} rtl_balanced_node , * prtl_balanced_node;

	typedef struct _single_list_entry {
		struct _single_list_entry* next;
	} single_list_entry , * psingle_list_entry;

	enum nt_status_t {
		success ,
		alerted = 0x101 ,
		timeout = 0x102 ,
		pending = 0x103 ,
		length_mismatch = 0xC0000004 , 
		insufficient_resources = 0xC000009A 
	};

	typedef struct _mi_active_pfn
	{
		union
		{
			struct
			{
				struct /* bitfield */
				{
					/* 0x0000 */ unsigned __int64 tradable : 1; /* bit position: 0 */
					/* 0x0000 */ unsigned __int64 nonpagedbuddy : 43; /* bit position: 1 */
				}; /* bitfield */
			} /* size: 0x0008 */ leaf;
			struct
			{
				struct /* bitfield */
				{
					/* 0x0000 */ unsigned __int64 tradable : 1; /* bit position: 0 */
					/* 0x0000 */ unsigned __int64 wsleage : 3; /* bit position: 1 */
					/* 0x0000 */ unsigned __int64 oldestwsleleafentries : 10; /* bit position: 4 */
					/* 0x0000 */ unsigned __int64 oldestwsleleafage : 3; /* bit position: 14 */
					/* 0x0000 */ unsigned __int64 nonpagedbuddy : 43; /* bit position: 17 */
				}; /* bitfield */
			} /* size: 0x0008 */ pagetable;
			/* 0x0000 */ unsigned __int64 entireactivefield;
		}; /* size: 0x0008 */
	} mi_active_pfn , * pmi_active_pfn; /* size: 0x0008 */

	//0x4 bytes (sizeof)
	struct _mmpte_hardware
	{
		ULONG valid : 1;                                                          //0x0
		ULONG writable : 1;                                                       //0x0
		ULONG owner : 1;                                                          //0x0
		ULONG writethrough : 1;                                                   //0x0
		ULONG cachedisable : 1;                                                   //0x0
		ULONG accessed : 1;                                                       //0x0
		ULONG dirty : 1;                                                          //0x0
		ULONG largepage : 1;                                                      //0x0
		ULONG global : 1;                                                         //0x0
		ULONG copyonwrite : 1;                                                    //0x0
		ULONG prototype : 1;                                                      //0x0
		ULONG write : 1;                                                          //0x0
		ULONG pageframenumber : 20;                                               //0x0
	};

	//0x4 bytes (sizeof)
	struct _mmpte_prototype
	{
		ULONG valid : 1;                                                          //0x0
		ULONG protoaddresslow : 8;                                                //0x0
		ULONG readonly : 1;                                                       //0x0
		ULONG prototype : 1;                                                      //0x0
		ULONG protoaddresshigh : 21;                                              //0x0
	};

	//0x4 bytes (sizeof)
	struct _mmpte_software
	{
		ULONG valid : 1;                                                          //0x0
		ULONG pagefilelow : 4;                                                    //0x0
		ULONG protection : 5;                                                     //0x0
		ULONG prototype : 1;                                                      //0x0
		ULONG transition : 1;                                                     //0x0
		ULONG pagefilehigh : 20;                                                  //0x0
	};

	//0x8 bytes (sizeof)
	struct _mmpte_timestamp
	{
		ULONGLONG mustbezero : 1;                                                 //0x0
		ULONGLONG pagefilelow : 4;                                                //0x0
		ULONGLONG protection : 5;                                                 //0x0
		ULONGLONG prototype : 1;                                                  //0x0
		ULONGLONG transition : 1;                                                 //0x0
		ULONGLONG unused : 20;                                                    //0x0
		ULONGLONG globaltimestamp : 32;                                           //0x0
	};

	//0x4 bytes (sizeof)
	struct _mmpte_transition
	{
		ULONG valid : 1;                                                          //0x0
		ULONG write : 1;                                                          //0x0
		ULONG owner : 1;                                                          //0x0
		ULONG writethrough : 1;                                                   //0x0
		ULONG cachedisable : 1;                                                   //0x0
		ULONG protection : 5;                                                     //0x0
		ULONG prototype : 1;                                                      //0x0
		ULONG transition : 1;                                                     //0x0
		ULONG pageframenumber : 20;                                               //0x0
	};

	//0x8 bytes (sizeof)
	struct _mmpte_subsection
	{
		ULONGLONG valid : 1;                                                      //0x0
		ULONGLONG unused0 : 3;                                                    //0x0
		ULONGLONG swizzlebit : 1;                                                 //0x0
		ULONGLONG protection : 5;                                                 //0x0
		ULONGLONG prototype : 1;                                                  //0x0
		ULONGLONG coldpage : 1;                                                   //0x0
		ULONGLONG unused1 : 3;                                                    //0x0
		ULONGLONG executeprivilege : 1;                                           //0x0
		ULONGLONG subsectionaddress : 48;                                          //0x0
	};

	struct _mmpte_list
	{
		ULONGLONG valid : 1;                                                      //0x0
		ULONGLONG oneentry : 1;                                                   //0x0
		ULONGLONG filler0 : 2;                                                    //0x0
		ULONGLONG swizzlebit : 1;                                                 //0x0
		ULONGLONG protection : 5;                                                 //0x0
		ULONGLONG prototype : 1;                                                  //0x0
		ULONGLONG transition : 1;                                                 //0x0
		ULONGLONG filler1 : 16;                                                   //0x0
		ULONGLONG nextentry : 36;                                                 //0x0
	};

	typedef struct _mmpte
	{
		union
		{
			union
			{
				/* 0x0000 */ volatile unsigned __int64 volatilelong;
				/* 0x0000 */ struct _mmpte_hardware hard;
				/* 0x0000 */ struct _mmpte_prototype proto;
				/* 0x0000 */ struct _mmpte_software soft;
				/* 0x0000 */ struct _mmpte_timestamp timestamp;
				/* 0x0000 */ struct _mmpte_transition trans;
				/* 0x0000 */ struct _mmpte_subsection subsect;
				/* 0x0000 */ struct _mmpte_list list;
			}; /* size: 0x0008 */
		} /* size: 0x0008 */ u;
	} mmpte , * pmmpte; /* size: 0x0008 */

	//0x4 bytes (sizeof)
	struct _mipfnblink
	{
		union
		{
			struct
			{
				ULONG blink : 24;                                                 //0x0
				ULONG tbflushstamp : 4;                                           //0x0
				ULONG unused : 1;                                                 //0x0
				ULONG pageblinkdeletebit : 1;                                     //0x0
				ULONG pageblinklockbit : 1;                                       //0x0
				ULONG sharecount : 30;                                            //0x0
				ULONG pagesharecountdeletebit : 1;                                //0x0
				ULONG pagesharecountlockbit : 1;                                  //0x0
			};
			ULONG entirefield;                                                  //0x0
			volatile long lock;                                                 //0x0
			struct
			{
				ULONG locknotused : 30;                                           //0x0
				ULONG deletebit : 1;                                              //0x0
				ULONG lockbit : 1;                                                //0x0
			};
		};
	};

	//0x1 bytes (sizeof)
	struct _mmpfnentry1
	{
		UCHAR pagelocation : 3;                                                   //0x0
		UCHAR writeinprogress : 1;                                                //0x0
		UCHAR modified : 1;                                                       //0x0
		UCHAR readinprogress : 1;                                                 //0x0
		UCHAR cacheattribute : 2;                                                 //0x0
	};

	//0x1 bytes (sizeof)
	struct _mmpfnentry3
	{
		UCHAR priority : 3;                                                       //0x0
		UCHAR onprotectedstandby : 1;                                             //0x0
		UCHAR inpageerror : 1;                                                    //0x0
		UCHAR systemchargedpage : 1;                                              //0x0
		UCHAR removalrequested : 1;                                               //0x0
		UCHAR parityerror : 1;                                                    //0x0
	};

	//0x4 bytes (sizeof)
	struct _mi_pfn_ulong5
	{
		union
		{
			ULONG entirefield;                                                  //0x0
			struct
			{
				ULONG nodeblinkhigh : 21;                                         //0x0
				ULONG nodeflinkmiddle : 11;                                       //0x0
			} standbylist;                                                      //0x0
			struct
			{
				UCHAR modifiedlistbucketindex : 4;                                //0x0
			} mappedpagelist;                                                   //0x0
			struct
			{
				UCHAR anchorlargepagesize : 2;                                    //0x0
				UCHAR spare0 : 6;                                                 //0x0
				UCHAR spare1 : 8;                                                 //0x1
				USHORT spare2;                                                  //0x2
			} active;                                                           //0x0
		};
	};

	typedef struct _mmpfn
	{
		union
		{
			struct _list_entry list_entry;
			struct _rtl_balanced_node tree_node;

			struct
			{
				union
				{
					struct
					{
						struct _single_list_entry next_slist_pfn;
						void* next;

						// Bitfield for flink and node flink low parts
						struct
						{
							unsigned __int64 flink : 40;            // Forward link
							unsigned __int64 node_flink_low : 24;   // Node flink low
						};

						// Active page frame number (PFN) structure
						struct _mi_active_pfn active;
					};
				} u1;

				// Pointer to page table entry (PTE) or its long representation
				union
				{
					struct _mmpte* pte_address;
					unsigned __int64 pte_long;
				};

				// Original page table entry
				struct _mmpte original_pte;
			};
		};

		// Blink or backward link
		struct _mipfnblink u2;

		union
		{
			union
			{
				struct
				{
					// Reference count and entries
					unsigned short reference_count;
					struct _mmpfnentry1 e1;
					struct _mmpfnentry3 e3;
				};

				struct
				{
					// Reference count only
					unsigned short reference_count;
				} e2;

				struct
				{
					// Full 32-bit field representation
					unsigned long entire_field;
				} e4;
			};
		} u3;

		// PFN-related structure
		struct _mi_pfn_ulong5 u5;

		union
		{
			union
			{
				// Bitfield describing various attributes of the PFN
				struct
				{
					unsigned __int64 pte_frame : 40; // PFN's page table frame
					unsigned __int64 resident_page : 1;  // Page is resident
					unsigned __int64 unused1 : 1;
					unsigned __int64 unused2 : 1;
					unsigned __int64 partition : 10; // Partition
					unsigned __int64 file_only : 1;  // File-backed page
					unsigned __int64 pfn_exists : 1;  // PFN exists
					unsigned __int64 node_flink_high : 5;  // High bits of node flink
					unsigned __int64 page_identity : 3;  // Page identity
					unsigned __int64 prototype_pte : 1;  // Prototype PTE
				};

				// Full 64-bit representation
				unsigned __int64 entire_field;
			};
		} u4;

	} mmpfn , * pmmpfn;
}