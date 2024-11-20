#pragma once
#include <core/linkers/std.h>

namespace riot
{
	typedef enum {
		pdpt_table_valid , // Means that the pml4 at the correct index already points to a remapped pdpt table
		pde_table_valid ,  // Means that the pdpt at the correct index already points to a remapped pde table
		pte_table_valid ,  // Means that the pde at the correct index already points to a remapped pte table
		non_valid ,        // Means that the pml4 indexes didn't match
	} usable_entry_t;

	typedef union _virt_addr_t
	{
		struct
		{
			std::uint64_t offset_1gb : 21;
			std::uint64_t pdpte_index : 9;
			std::uint64_t pml4e_index : 9;
			std::uint64_t reserved : 16;
		};

		struct
		{
			std::uint64_t offset_2mb : 21;
			std::uint64_t pde_index : 9;
			std::uint64_t pdpte_index : 9;
			std::uint64_t pml4e_index : 9;
			std::uint64_t reserved : 16;
		};

		struct
		{
			std::uint64_t offset_4kb : 12;
			std::uint64_t pte_index : 9;
			std::uint64_t pde_index : 9;
			std::uint64_t pdpte_index : 9;
			std::uint64_t pml4e_index : 9;
			std::uint64_t reserved : 16;
		};

		std::uintptr_t value;
	} virt_addr_t , * pvirt_addr_t;
	static_assert( sizeof( virt_addr_t ) == sizeof( void* ) , "size mismatch, only 64-bit supported." );

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
			std::uint64_t large_page : 1;				// Page size (1 = entry maps a 1-GByte page)
			std::uint64_t ignored1 : 4;					// Ignored by hardware
			std::uint64_t pfn : 36;						// Physical frame number of the 4KB page
			std::uint64_t reserved_for_software : 4;	// Reserved for software use only
			std::uint64_t reserved_for_hardware : 11;	// Reserved for hardware use only
			std::uint64_t no_execute : 1;				// No-execute (NX) bit, set to disable execution
		} hard;

		std::uint64_t value;
	} pml4e , * ppml4e;

	typedef union _pte
	{
		struct
		{
			std::uint64_t present : 1;					// Must be 1 if the page is valid
			std::uint64_t read_write : 1;				// Write access control (0 = read-only, 1 = read/write)
			std::uint64_t user_supervisor : 1;			// User/supervisor access control (0 = supervisor, 1 = user)
			std::uint64_t page_write_through : 1;		// Write-through caching
			std::uint64_t cached_disable : 1;			// Cache disable (1 = disable caching)
			std::uint64_t accessed : 1;					// Set when accessed
			std::uint64_t dirty : 1;					// Set when written to
			std::uint64_t page_attribute_table : 1;		// Page Attribute Table bit (affects memory type selection)
			std::uint64_t global_page : 1;				// Set if the page is global (won't be flushed on CR3 switch)
			std::uint64_t ignored1 : 3;					// Ignored by hardware
			std::uint64_t pfn : 36;						// Physical frame number of the 4KB page
			std::uint64_t reserved : 4;					// Reserved for future use
			std::uint64_t ignored2 : 7;					// Ignored by software
			std::uint64_t protection_key : 4;			// Protection Key (if PKE bit in CR4 is set)
			std::uint64_t no_execute : 1;				// No-execute (NX) bit, set to disable execution
		} hard;

		std::uint64_t value;
	} pte , * ppte;

    typedef union _pfn {
        struct {
            std::uint64_t pte_frame : 25;                  // Frame number in PFN
            std::uint64_t image_verified : 1;              // Image verification status
            std::uint64_t awe_allocation : 1;              // Allocation type (AWE)
            std::uint64_t prototype_pte : 1;               // Prototype PTE
            std::uint64_t page_color : 4;                  // Page color (for balancing)
            std::uint64_t page_location : 3;               // State (free, standby, etc.)
            std::uint64_t modified : 1;                    // Modified bit
            std::uint64_t read_in_progress : 1;            // Ongoing read
            std::uint64_t write_in_progress : 1;           // Ongoing write
            std::uint64_t in_transition : 1;               // Paging transition
            std::uint64_t reserved_flags : 3;              // Reserved flags
        } flags;

        struct {
            std::uint16_t reference_count;           // Reference count (2 bytes)
            std::uint16_t padding;                   // Padding for 8-byte alignment
            std::uint64_t flink;                     // Forward link (8 bytes)
            std::uint64_t blink;                     // Backward link (8 bytes)
            std::uint32_t ws_index;                  // Working set index (4 bytes)
            std::uint32_t ws_padding;                // Padding for 8-byte alignment
            std::uint64_t pte_address;               // Pointer to PTE in memory (8 bytes)
        } meta_data;

    } pfn , * ppfn;

	typedef union _cr3 {
        std::uint64_t flags;

		struct {
            std::uint64_t pcid : 12;
            std::uint64_t page_frame_number : 36;
            std::uint64_t reserved_1 : 12;
            std::uint64_t reserved_2 : 3;
            std::uint64_t pcid_invalidate : 1;
		};
	} cr3 , * pcr3;
	static_assert( sizeof( cr3 ) == sizeof( void* ) , "size mismatch, only 64-bit supported." );

	typedef union _ktss64
	{
		struct
		{
			std::uint32_t reserved0;                    // Reserved (must be 0)
			std::uint64_t rsp0;                         // Stack pointer for ring 0
			std::uint64_t rsp1;                         // Stack pointer for ring 1
			std::uint64_t rsp2;                         // Stack pointer for ring 2
			std::uint64_t ist[ 7 ];                     // Interrupt stack table pointers (IST1 - IST7)
			std::uint64_t reserved1;                    // Reserved (must be 0)
			std::uint16_t reserved2;                    // Reserved (must be 0)
			std::uint16_t iomap_base;                   // I/O map base address
		};
	} ktss64 , * pktss64;

	typedef struct _KAFFINITY_EX
	{
		std::uint8_t Count;
		std::uint16_t Size;
		unsigned long Reserved;
		std::uint64_t Bitmap[ 20 ];

	} KAFFINITY_EX , * PKAFFINITY_EX;

	typedef struct _RTL_MODULE_EXTENDED_INFO
	{
		void* ImageBase;
		unsigned long ImageSize;
		std::uint16_t FileNameOffset;
		char FullPathName[ 0x100 ];
	} RTL_MODULE_EXTENDED_INFO , * PRTL_MODULE_EXTENDED_INFO;

	typedef struct _SYSTEM_MODULES
	{
		void* address;
		int module_count;
	}SYSTEM_MODULES , * PSYSTEM_MODULES;

	typedef struct _INVALID_DRIVER
	{
		struct _INVALID_DRIVER* next;
		void* driver;
	}INVALID_DRIVER , * PINVALID_DRIVER;

	typedef struct _INVALID_DRIVERS_HEAD
	{
		PINVALID_DRIVER first_entry;
		int count;		//keeps track of the number of drivers in the list
	}INVALID_DRIVERS_HEAD , * PINVALID_DRIVERS_HEAD;

	typedef struct _MACHINE_FRAME
	{
		std::uint64_t rip;
		std::uint64_t cs;
		std::uint64_t eflags;
		std::uint64_t rsp;
		std::uint64_t ss;
	} MACHINE_FRAME , * PMACHINE_FRAME;

    typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
    {
        unsigned long Version;
        unsigned long Reserved;
        void* Callback;
    } PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION , * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

    //0x18 bytes (sizeof)
    struct dispatcher_header_t
    {
        union
        {
            volatile std::int32_t Lock;                                                 //0x0
            std::int32_t LockNV;                                                        //0x0
            struct
            {
                std::uint8_t Type;                                                     //0x0
                std::uint8_t Signalling;                                               //0x1
                std::uint8_t Size;                                                     //0x2
                std::uint8_t Reserved1;                                                //0x3
            };
            struct
            {
                std::uint8_t TimerType;                                                //0x0
                union
                {
                    std::uint8_t TimerControlFlags;                                    //0x1
                    struct
                    {
                        std::uint8_t Absolute : 1;                                       //0x1
                        std::uint8_t Wake : 1;                                           //0x1
                        std::uint8_t EncodedTolerableDelay : 6;                          //0x1
                    };
                };
                std::uint8_t Hand;                                                     //0x2
                union
                {
                    std::uint8_t TimerMiscFlags;                                       //0x3
                    struct
                    {
                        std::uint8_t Index : 6;                                          //0x3
                        std::uint8_t Inserted : 1;                                       //0x3
                        volatile std::uint8_t Expired : 1;                               //0x3
                    };
                };
            };
            struct
            {
                std::uint8_t Timer2Type;                                               //0x0
                union
                {
                    std::uint8_t Timer2Flags;                                          //0x1
                    struct
                    {
                        std::uint8_t Timer2Inserted : 1;                                 //0x1
                        std::uint8_t Timer2Expiring : 1;                                 //0x1
                        std::uint8_t Timer2CancelPending : 1;                            //0x1
                        std::uint8_t Timer2SetPending : 1;                               //0x1
                        std::uint8_t Timer2Running : 1;                                  //0x1
                        std::uint8_t Timer2Disabled : 1;                                 //0x1
                        std::uint8_t Timer2ReservedFlags : 2;                            //0x1
                    };
                };
                std::uint8_t Timer2ComponentId;                                        //0x2
                std::uint8_t Timer2RelativeId;                                         //0x3
            };
            struct
            {
                std::uint8_t QueueType;                                                //0x0
                union
                {
                    std::uint8_t QueueControlFlags;                                    //0x1
                    struct
                    {
                        std::uint8_t Abandoned : 1;                                      //0x1
                        std::uint8_t DisableIncrement : 1;                               //0x1
                        std::uint8_t QueueReservedControlFlags : 6;                      //0x1
                    };
                };
                std::uint8_t QueueSize;                                                //0x2
                std::uint8_t QueueReserved;                                            //0x3
            };
            struct
            {
                std::uint8_t ThreadType;                                               //0x0
                std::uint8_t ThreadReserved;                                           //0x1
                union
                {
                    std::uint8_t ThreadControlFlags;                                   //0x2
                    struct
                    {
                        std::uint8_t CycleProfiling : 1;                                 //0x2
                        std::uint8_t CounterProfiling : 1;                               //0x2
                        std::uint8_t GroupScheduling : 1;                                //0x2
                        std::uint8_t AffinitySet : 1;                                    //0x2
                        std::uint8_t Tagged : 1;                                         //0x2
                        std::uint8_t EnergyProfiling : 1;                                //0x2
                        std::uint8_t SchedulerAssist : 1;                                //0x2
                        std::uint8_t ThreadReservedControlFlags : 1;                     //0x2
                    };
                };
                union
                {
                    std::uint8_t DebugActive;                                          //0x3
                    struct
                    {
                        std::uint8_t ActiveDR7 : 1;                                      //0x3
                        std::uint8_t Instrumented : 1;                                   //0x3
                        std::uint8_t Minimal : 1;                                        //0x3
                        std::uint8_t Reserved4 : 2;                                      //0x3
                        std::uint8_t AltSyscall : 1;                                     //0x3
                        std::uint8_t UmsScheduled : 1;                                   //0x3
                        std::uint8_t UmsPrimary : 1;                                     //0x3
                    };
                };
            };
            struct
            {
                std::uint8_t MutantType;                                               //0x0
                std::uint8_t MutantSize;                                               //0x1
                std::uint8_t DpcActive;                                                //0x2
                std::uint8_t MutantReserved;                                           //0x3
            };
        };
        std::int32_t SignalState;                                                       //0x4
        list_entry_t WaitListHead;                                        //0x8
    };

    union ularge_integer_t
    {
        struct
        {
            std::uint32_t  LowPart;                                                      //0x0
            std::uint32_t  HighPart;                                                     //0x4
        };
        struct
        {
            std::uint32_t  LowPart;                                                      //0x0
            std::uint32_t  HighPart;                                                     //0x4
        } u;                                                                    //0x0
        std::uint64_t QuadPart;                                                     //0x0
    };

    //0x40 bytes (sizeof)
    struct ktimer_t
    {
        struct dispatcher_header_t Header;                                       //0x0
        union ularge_integer_t DueTime;                                          //0x18
        struct list_entry_t TimerListEntry;                                      //0x20
        struct _KDPC* Dpc;                                                      //0x30
        std::uint16_t Processor;                                                       //0x38
        std::uint16_t TimerType;                                                       //0x3a
        std::uint32_t Period;                                                           //0x3c
    };

    //0x30 bytes (sizeof)
    struct kapc_state_t
    {
        list_entry_t ApcListHead[ 2 ];                                      //0x0
        struct _KPROCESS* Process;                                              //0x20
        union
        {
            std::uint8_t InProgressFlags;                                              //0x28
            struct
            {
                std::uint8_t KernelApcInProgress : 1;                                    //0x28
                std::uint8_t SpecialApcInProgress : 1;                                   //0x28
            };
        };
        std::uint8_t KernelApcPending;                                                 //0x29
        union
        {
            std::uint8_t UserApcPendingAll;                                            //0x2a
            struct
            {
                std::uint8_t SpecialUserApcPending : 1;                                  //0x2a
                std::uint8_t UserApcPending : 1;                                         //0x2a
            };
        };
    };

    //0x1 bytes (sizeof)
    union kwait_status_register_t
    {
        std::uint8_t Flags;                                                            //0x0
        std::uint8_t State : 3;                                                          //0x0
        std::uint8_t Affinity : 1;                                                       //0x0
        std::uint8_t Priority : 1;                                                       //0x0
        std::uint8_t Apc : 1;                                                            //0x0
        std::uint8_t UserApc : 1;                                                        //0x0
        std::uint8_t Alert : 1;                                                          //0x0
    };

    //0x30 bytes (sizeof)
    struct kwait_block_t
    {
        struct list_entry_t WaitListEntry;                                       //0x0
        std::uint8_t WaitType;                                                         //0x10
        volatile std::uint8_t BlockState;                                              //0x11
        std::uint16_t WaitKey;                                                         //0x12
        std::int32_t SpareLong;                                                         //0x14
        union
        {
            struct kthread* Thread;                                            //0x18
            struct _KQUEUE* NotificationQueue;                                  //0x18
        };
        void* Object;                                                           //0x20
        void* SparePtr;                                                         //0x28
    };

    //0x10 bytes (sizeof)
    struct group_affinity_t
    {
        std::uint64_t Mask;                                                         //0x0
        std::uint16_t Group;                                                           //0x8
        std::uint16_t Reserved[ 3 ];                                                     //0xa
    };

    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        void* Section;
        void* MappedBase;
        void* image_base;
        unsigned long image_size;
        unsigned long Flags;
        std::uint16_t LoadOrderIndex;
        std::uint16_t InitOrderIndex;
        std::uint16_t LoadCount;
        std::uint16_t OffsetToFileName;
        char FullPathName[ 256 ];
    } RTL_PROCESS_MODULE_INFORMATION , * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _rtl_process_modules
    {
        unsigned long number_of_modules;
        RTL_PROCESS_MODULE_INFORMATION modules[ 1 ];
    } rtl_process_modules , * prtl_process_modules;

    //0x58 bytes (sizeof)
    struct kapc_t
    {
        std::uint8_t Type;                                                             //0x0
        std::uint8_t SpareByte0;                                                       //0x1
        std::uint8_t Size;                                                             //0x2
        std::uint8_t SpareByte1;                                                       //0x3
        std::uint32_t SpareLong0;                                                       //0x4
        struct kthread* Thread;                                                //0x8
        struct list_entry_t ApcListEntry;                                        //0x10
        union
        {
            struct
            {
                void( *KernelRoutine )( struct kapc_t* arg1 , void( **arg2 )( void* arg1 , void* arg2 , void* arg3 ) , void** arg3 , void** arg4 , void** arg5 ); //0x20
                void( *RundownRoutine )( struct kapc_t* arg1 );                     //0x28
                void( *NormalRoutine )( void* arg1 , void* arg2 , void* arg3 );      //0x30
            };
            void* Reserved[ 3 ];                                                  //0x20
        };
        void* NormalContext;                                                    //0x38
        void* SystemArgument1;                                                  //0x40
        void* SystemArgument2;                                                  //0x48
        std::uint8_t ApcStateIndex;                                                     //0x50
        std::uint8_t ApcMode;                                                           //0x51
        std::uint8_t Inserted;                                                         //0x52
    };

    //0x18 bytes (sizeof)
    struct kevent_t
    {
        struct dispatcher_header_t Header;                                       //0x0
    };

    struct kthread
    {
        struct dispatcher_header_t Header;                                       //0x0
        void* SListFaultAddress;                                                //0x18
        std::uint64_t QuantumTarget;                                                //0x20
        void* InitialStack;                                                     //0x28
        void* volatile StackLimit;                                              //0x30
        void* StackBase;                                                        //0x38
        std::uint64_t ThreadLock;                                                   //0x40
        volatile std::uint64_t CycleTime;                                           //0x48
        std::uint64_t CurrentRunTime;                                                   //0x50
        std::uint64_t ExpectedRunTime;                                                  //0x54
        void* KernelStack;                                                      //0x58
        struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
        struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
        union kwait_status_register_t WaitRegister;                              //0x70
        volatile std::uint8_t Running;                                                 //0x71
        std::uint8_t Alerted[ 2 ];                                                       //0x72
        union
        {
            struct
            {
                std::uint64_t AutoBoostActive : 1;                                        //0x74
                std::uint64_t ReadyTransition : 1;                                        //0x74
                std::uint64_t WaitNext : 1;                                               //0x74
                std::uint64_t SystemAffinityActive : 1;                                   //0x74
                std::uint64_t Alertable : 1;                                              //0x74
                std::uint64_t UserStackWalkActive : 1;                                    //0x74
                std::uint64_t ApcInterruptRequest : 1;                                    //0x74
                std::uint64_t QuantumEndMigrate : 1;                                      //0x74
                std::uint64_t UmsDirectedSwitchEnable : 1;                                //0x74
                std::uint64_t TimerActive : 1;                                            //0x74
                std::uint64_t SystemThread : 1;                                           //0x74
                std::uint64_t ProcessDetachActive : 1;                                    //0x74
                std::uint64_t CalloutActive : 1;                                          //0x74
                std::uint64_t ScbReadyQueue : 1;                                          //0x74
                std::uint64_t ApcQueueable : 1;                                           //0x74
                std::uint64_t ReservedStackInUse : 1;                                     //0x74
                std::uint64_t UmsPerformingSyscall : 1;                                   //0x74
                std::uint64_t TimerSuspended : 1;                                         //0x74
                std::uint64_t SuspendedWaitMode : 1;                                      //0x74
                std::uint64_t SuspendSchedulerApcWait : 1;                                //0x74
                std::uint64_t CetUserShadowStack : 1;                                     //0x74
                std::uint64_t BypassProcessFreeze : 1;                                    //0x74
                std::uint64_t Reserved : 10;                                              //0x74
            };
            std::int32_t MiscFlags;                                                     //0x74
        };
        union
        {
            struct
            {
                std::uint64_t ThreadFlagsSpare : 2;                                       //0x78
                std::uint64_t AutoAlignment : 1;                                          //0x78
                std::uint64_t DisableBoost : 1;                                           //0x78
                std::uint64_t AlertedByThreadId : 1;                                      //0x78
                std::uint64_t QuantumDonation : 1;                                        //0x78
                std::uint64_t EnableStackSwap : 1;                                        //0x78
                std::uint64_t GuiThread : 1;                                              //0x78
                std::uint64_t DisableQuantum : 1;                                         //0x78
                std::uint64_t ChargeOnlySchedulingGroup : 1;                              //0x78
                std::uint64_t DeferPreemption : 1;                                        //0x78
                std::uint64_t QueueDeferPreemption : 1;                                   //0x78
                std::uint64_t ForceDeferSchedule : 1;                                     //0x78
                std::uint64_t clientReadyQueueAffinity : 1;                               //0x78
                std::uint64_t FreezeCount : 1;                                            //0x78
                std::uint64_t TerminationApcRequest : 1;                                  //0x78
                std::uint64_t AutoBoostEntriesExhausted : 1;                              //0x78
                std::uint64_t KernelStackResident : 1;                                    //0x78
                std::uint64_t TerminateRequestReason : 2;                                 //0x78
                std::uint64_t ProcessStackCountDecremented : 1;                           //0x78
                std::uint64_t RestrictedGuiThread : 1;                                    //0x78
                std::uint64_t VpBackingThread : 1;                                        //0x78
                std::uint64_t ThreadFlagsSpare2 : 1;                                      //0x78
                std::uint64_t EtwStackTraceApcInserted : 8;                               //0x78
            };
            volatile std::int32_t ThreadFlags;                                          //0x78
        };
        volatile std::uint8_t Tag;                                                     //0x7c
        std::uint8_t SystemHeteroCpuPolicy;                                            //0x7d
        std::uint8_t UserHeteroCpuPolicy : 7;                                            //0x7e
        std::uint8_t ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
        union
        {
            struct
            {
                std::uint8_t RunningNonRetpolineCode : 1;                                //0x7f
                std::uint8_t SpecCtrlSpare : 7;                                          //0x7f
            };
            std::uint8_t SpecCtrl;                                                     //0x7f
        };
        std::uint64_t SystemCallNumber;                                                 //0x80
        std::uint64_t ReadyTime;                                                        //0x84
        void* FirstArgument;                                                    //0x88
        struct _KTRAP_FRAME* TrapFrame;                                         //0x90
        union
        {
            struct kapc_state_t ApcState;                                        //0x98
            struct
            {
                std::uint8_t ApcStateFill[ 43 ];                                         //0x98
                std::uint8_t Priority;                                                  //0xc3
                std::uint64_t UserIdealProcessor;                                       //0xc4
            };
        };
        volatile std::uint64_t WaitStatus;                                           //0xc8
        struct kwait_block_t* WaitBlockList;                                     //0xd0
        union
        {
            struct list_entry_t WaitListEntry;                                   //0xd8
            struct single_list_entry_t SwapListEntry;                            //0xd8
        };
        struct dispatcher_header_t* volatile Queue;                              //0xe8
        void* Teb;                                                              //0xf0
        std::uint64_t RelativeTimerBias;                                            //0xf8
        struct ktimer_t Timer;                                                   //0x100
        union
        {
            struct kwait_block_t WaitBlock[ 4 ];                                   //0x140
            struct
            {
                std::uint8_t WaitBlockFill4[ 20 ];                                       //0x140
                std::uint64_t ContextSwitches;                                          //0x154
            };
            struct
            {
                std::uint8_t WaitBlockFill5[ 68 ];                                       //0x140
                volatile std::uint8_t State;                                           //0x184
                std::uint8_t Spare13;                                                   //0x185
                std::uint8_t WaitIrql;                                                 //0x186
                std::uint8_t WaitMode;                                                  //0x187
            };
            struct
            {
                std::uint8_t WaitBlockFill6[ 116 ];                                      //0x140
                std::uint64_t WaitTime;                                                 //0x1b4
            };
            struct
            {
                std::uint8_t WaitBlockFill7[ 164 ];                                      //0x140
                union
                {
                    struct
                    {
                        std::int16_t KernelApcDisable;                                 //0x1e4
                        std::int16_t SpecialApcDisable;                                //0x1e6
                    };
                    std::uint64_t CombinedApcDisable;                                   //0x1e4
                };
            };
            struct
            {
                std::uint8_t WaitBlockFill8[ 40 ];                                       //0x140
                struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
            };
            struct
            {
                std::uint8_t WaitBlockFill9[ 88 ];                                       //0x140
                struct _XSTATE_SAVE* XStateSave;                                //0x198
            };
            struct
            {
                std::uint8_t WaitBlockFill10[ 136 ];                                     //0x140
                void* volatile Win32Thread;                                     //0x1c8
            };
            struct
            {
                std::uint8_t WaitBlockFill11[ 176 ];                                     //0x140
                struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
                struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
            };
        };
        union
        {
            volatile std::int32_t ThreadFlags2;                                         //0x200
            struct
            {
                std::uint64_t BamQosLevel : 8;                                            //0x200
                std::uint64_t ThreadFlags2Reserved : 24;                                  //0x200
            };
        };
        std::uint64_t Spare21;                                                          //0x204
        struct list_entry_t QueueListEntry;                                      //0x208
        union
        {
            volatile std::uint64_t NextProcessor;                                       //0x218
            struct
            {
                std::uint64_t NextProcessorNumber : 31;                                   //0x218
                std::uint64_t clientReadyQueue : 1;                                       //0x218
            };
        };
        std::int32_t QueuePriority;                                                     //0x21c
        struct _KPROCESS* Process;                                              //0x220
        union
        {
            struct group_affinity_t UserAffinity;                                //0x228
            struct
            {
                std::uint8_t UserAffinityFill[ 10 ];                                     //0x228
                std::uint8_t PreviousMode;                                              //0x232
                std::uint8_t BasePriority;                                              //0x233
                union
                {
                    std::uint8_t PriorityDecrement;                                     //0x234
                    struct
                    {
                        std::uint8_t ForegroundBoost : 4;                                //0x234
                        std::uint8_t UnusualBoost : 4;                                   //0x234
                    };
                };
                std::uint8_t Preempted;                                                //0x235
                std::uint8_t AdjustReason;                                             //0x236
                std::uint8_t AdjustIncrement;                                           //0x237
            };
        };
        std::uint64_t AffinityVersion;                                              //0x238
        union
        {
            struct group_affinity_t Affinity;                                    //0x240
            struct
            {
                std::uint8_t AffinityFill[ 10 ];                                         //0x240
                std::uint8_t ApcStateIndex;                                            //0x24a
                std::uint8_t WaitBlockCount;                                           //0x24b
                std::uint64_t IdealProcessor;                                           //0x24c
            };
        };
        std::uint64_t NpxState;                                                     //0x250
        union
        {
            struct kapc_state_t SavedApcState;                                   //0x258
            struct
            {
                std::uint8_t SavedApcStateFill[ 43 ];                                    //0x258
                std::uint8_t WaitReason;                                               //0x283
                std::uint8_t SuspendCount;                                              //0x284
                std::uint8_t Saturation;                                                //0x285
                std::uint16_t SListFaultCount;                                         //0x286
            };
        };
        union
        {
            struct kapc_t SchedulerApc;                                          //0x288
            struct
            {
                std::uint8_t SchedulerApcFill0[ 1 ];                                     //0x288
                std::uint8_t ResourceIndex;                                            //0x289
            };
            struct
            {
                std::uint8_t SchedulerApcFill1[ 3 ];                                     //0x288
                std::uint8_t QuantumReset;                                             //0x28b
            };
            struct
            {
                std::uint8_t SchedulerApcFill2[ 4 ];                                     //0x288
                std::uint64_t KernelTime;                                               //0x28c
            };
            struct
            {
                std::uint8_t SchedulerApcFill3[ 64 ];                                    //0x288
                struct _KPRCB* volatile WaitPrcb;                               //0x2c8
            };
            struct
            {
                std::uint8_t SchedulerApcFill4[ 72 ];                                    //0x288
                void* LegoData;                                                 //0x2d0
            };
            struct
            {
                std::uint8_t SchedulerApcFill5[ 83 ];                                    //0x288
                std::uint8_t CallbackNestingLevel;                                     //0x2db
                std::uint64_t UserTime;                                                 //0x2dc
            };
        };
        struct kevent_t SuspendEvent;                                            //0x2e0
        struct list_entry_t ThreadListEntry;                                     //0x2f8
        struct list_entry_t MutantListHead;                                      //0x308
        std::uint8_t AbEntrySummary;                                                   //0x318
        std::uint8_t AbWaitEntryCount;                                                 //0x319
        std::uint8_t AbAllocationRegionCount;                                          //0x31a
        std::uint8_t SystemPriority;                                                    //0x31b
        std::uint64_t SecureThreadCookie;                                               //0x31c
        struct _KLOCK_ENTRY* LockEntries;                                       //0x320
        struct single_list_entry_t PropagateBoostsEntry;                         //0x328
        struct single_list_entry_t IoSelfBoostsEntry;                            //0x330
        std::uint8_t PriorityFloorCounts[ 16 ];                                          //0x338
        std::uint8_t PriorityFloorCountsReserved[ 16 ];                                  //0x348
        std::uint64_t PriorityFloorSummary;                                             //0x358
        volatile std::int32_t AbCompletedIoBoostCount;                                  //0x35c
        volatile std::int32_t AbCompletedIoQoSBoostCount;                               //0x360
        volatile std::int16_t KeReferenceCount;                                        //0x364
        std::uint8_t AbOrphanedEntrySummary;                                           //0x366
        std::uint8_t AbOwnedEntryCount;                                                //0x367
        std::uint64_t ForegroundLossTime;                                               //0x368
        union
        {
            struct list_entry_t GlobalForegroundListEntry;                       //0x370
            struct
            {
                struct single_list_entry_t ForegroundDpcStackListEntry;          //0x370
                std::uint64_t InGlobalForegroundList;                               //0x378
            };
        };
        std::uint64_t ReadOperationCount;                                            //0x380
        std::uint64_t WriteOperationCount;                                           //0x388
        std::uint64_t OtherOperationCount;                                           //0x390
        std::uint64_t ReadTransferCount;                                             //0x398
        std::uint64_t WriteTransferCount;                                            //0x3a0
        std::uint64_t OtherTransferCount;                                            //0x3a8
        struct _KSCB* QueuedScb;                                                //0x3b0
        volatile std::uint64_t ThreadTimerDelay;                                        //0x3b8
        union
        {
            volatile std::int32_t ThreadFlags3;                                         //0x3bc
            struct
            {
                std::uint64_t ThreadFlags3Reserved : 8;                                   //0x3bc
                std::uint64_t PpmPolicy : 2;                                              //0x3bc
                std::uint64_t ThreadFlags3Reserved2 : 22;                                 //0x3bc
            };
        };
        std::uint64_t TracingPrivate[ 1 ];                                            //0x3c0
        void* SchedulerAssist;                                                  //0x3c8
        void* volatile AbWaitObject;                                            //0x3d0
        std::uint64_t ReservedPreviousReadyTimeValue;                                   //0x3d8
        std::uint64_t KernelWaitTime;                                               //0x3e0
        std::uint64_t UserWaitTime;                                                 //0x3e8
        union
        {
            struct list_entry_t GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
            struct
            {
                struct single_list_entry_t UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
                std::uint64_t InGlobalUpdateVpThreadPriorityList;                   //0x3f8
            };
        };
        std::int32_t SchedulerAssistPriorityFloor;                                      //0x400
        std::uint64_t Spare28;                                                          //0x404
        std::uint64_t EndPadding[ 5 ];                                                //0x408
    };

    //0x10 bytes (sizeof)
    struct _DISPATCHER_HEADER
    {
        union
        {
            struct
            {
                std::uint8_t Type;                                                     //0x0
                union
                {
                    std::uint8_t TimerControlFlags;                                    //0x1
                    struct
                    {
                        std::uint8_t Absolute : 1;                                       //0x1
                        std::uint8_t Coalescable : 1;                                    //0x1
                        std::uint8_t KeepShifting : 1;                                   //0x1
                        std::uint8_t EncodedTolerableDelay : 5;                          //0x1
                    };
                    std::uint8_t Abandoned;                                            //0x1
                    std::uint8_t Signalling;                                           //0x1
                };
                union
                {
                    std::uint8_t ThreadControlFlags;                                   //0x2
                    struct
                    {
                        std::uint8_t CpuThrottled : 1;                                   //0x2
                        std::uint8_t CycleProfiling : 1;                                 //0x2
                        std::uint8_t CounterProfiling : 1;                               //0x2
                        std::uint8_t Reserved : 5;                                       //0x2
                    };
                    std::uint8_t Hand;                                                 //0x2
                    std::uint8_t Size;                                                 //0x2
                };
                union
                {
                    std::uint8_t TimerMiscFlags;                                       //0x3
                    struct
                    {
                        std::uint8_t Index : 1;                                          //0x3
                        std::uint8_t Processor : 5;                                      //0x3
                        std::uint8_t Inserted : 1;                                       //0x3
                        volatile std::uint8_t Expired : 1;                               //0x3
                    };
                    std::uint8_t DebugActive;                                          //0x3
                    struct
                    {
                        std::uint8_t ActiveDR7 : 1;                                      //0x3
                        std::uint8_t Instrumented : 1;                                   //0x3
                        std::uint8_t Reserved2 : 4;                                      //0x3
                        std::uint8_t UmsScheduled : 1;                                   //0x3
                        std::uint8_t UmsPrimary : 1;                                     //0x3
                    };
                    std::uint8_t DpcActive;                                            //0x3
                };
            };
            volatile long Lock;                                                 //0x0
        };
        long SignalState;                                                       //0x4
        struct list_entry_t WaitListHead;                                        //0x8
    };

    //0x20 bytes (sizeof)
    struct _KSEMAPHORE
    {
        struct _DISPATCHER_HEADER Header;                                       //0x0
        long Limit;                                                             //0x18
    };

    //0x10 bytes (sizeof)
    struct _CLIENT_ID
    {
        void* UniqueProcess;                                                    //0x0
        void* UniqueThread;                                                     //0x8
    };

    //0x18 bytes (sizeof)
    struct _PS_PROPERTY_SET
    {
        struct list_entry_t ListHead;                                            //0x0
        std::uint64_t Lock;                                                         //0x10
    };

    //0x8 bytes (sizeof)
    struct _EX_RUNDOWN_REF
    {
        union
        {
            std::uint64_t Count;                                                    //0x0
            void* Ptr;                                                          //0x0
        };
    };

    //0x8 bytes (sizeof)
    union _PS_CLIENT_SECURITY_CONTEXT
    {
        std::uint64_t ImpersonationData;                                            //0x0
        void* ImpersonationToken;                                               //0x0
        std::uint64_t ImpersonationLevel : 2;                                         //0x0
        std::uint64_t EffectiveOnly : 1;                                              //0x0
    };

    //0x4 bytes (sizeof)
    struct _EX_PUSH_LOCK
    {
        union
        {
            struct
            {
                unsigned long Locked : 1;                                                 //0x0
                unsigned long Waiting : 1;                                                //0x0
                unsigned long Waking : 1;                                                 //0x0
                unsigned long MultipleShared : 1;                                         //0x0
                unsigned long Shared : 28;                                                //0x0
            };
            unsigned long Value;                                                        //0x0
            void* Ptr;                                                          //0x0
        };
    };

    //0x10 bytes (sizeof)
    struct _RTL_RB_TREE
    {
        struct _RTL_BALANCED_NODE* Root;                                        //0x0
        union
        {
            std::uint8_t Encoded : 1;                                                    //0x8
            struct _RTL_BALANCED_NODE* Min;                                     //0x8
        };
    };

    //0x10 bytes (sizeof)
    struct _KLOCK_ENTRY_LOCK_STATE
    {
        union
        {
            struct
            {
                std::uint64_t CrossThreadReleasable : 1;                              //0x0
                std::uint64_t Busy : 1;                                               //0x0
                std::uint64_t Reserved : 61;                                          //0x0
                std::uint64_t InTree : 1;                                             //0x0
            };
            void* LockState;                                                    //0x0
        };
        union
        {
            void* SessionState;                                                 //0x8
            struct
            {
                unsigned long SessionId;                                                //0x8
                unsigned long SessionPad;                                               //0xc
            };
        };
    };

    //0xc bytes (sizeof)
    struct _RTL_BALANCED_NODE
    {
        union
        {
            struct _RTL_BALANCED_NODE* Children[ 2 ];                             //0x0
            struct
            {
                struct _RTL_BALANCED_NODE* Left;                                //0x0
                struct _RTL_BALANCED_NODE* Right;                               //0x4
            };
        };
        union
        {
            struct
            {
                std::uint8_t Red : 1;                                                    //0x8
                std::uint8_t Balance : 2;                                                //0x8
            };
            unsigned long ParentValue;                                                  //0x8
        };
    };

    //0x60 bytes (sizeof)
    struct _KLOCK_ENTRY
    {
        union
        {
            struct _RTL_BALANCED_NODE TreeNode;                                 //0x0
            struct single_list_entry_t FreeListEntry;                            //0x0
        };
        union
        {
            unsigned long EntryFlags;                                                   //0x18
            struct
            {
                unsigned char EntryOffset;                                              //0x18
                union
                {
                    unsigned char ThreadLocalFlags;                                     //0x19
                    struct
                    {
                        unsigned char WaitingBit : 1;                                     //0x19
                        unsigned char Spare0 : 7;                                         //0x19
                    };
                };
                union
                {
                    unsigned char AcquiredByte;                                         //0x1a
                    unsigned char AcquiredBit : 1;                                        //0x1a
                };
                union
                {
                    unsigned char CrossThreadFlags;                                     //0x1b
                    struct
                    {
                        unsigned char HeadNodeBit : 1;                                    //0x1b
                        unsigned char IoPriorityBit : 1;                                  //0x1b
                        unsigned char Spare1 : 6;                                         //0x1b
                    };
                };
            };
            struct
            {
                unsigned long StaticState : 8;                                            //0x18
                unsigned long AllFlags : 24;                                              //0x18
            };
        };
        unsigned long SpareFlags;                                                       //0x1c
        union
        {
            struct _KLOCK_ENTRY_LOCK_STATE LockState;                           //0x20
            void* volatile LockUnsafe;                                          //0x20
            struct
            {
                volatile unsigned char CrossThreadReleasableAndBusyByte;                //0x20
                unsigned char Reserved[ 6 ];                                              //0x21
                volatile unsigned char InTreeByte;                                      //0x27
                union
                {
                    void* SessionState;                                         //0x28
                    struct
                    {
                        unsigned long SessionId;                                        //0x28
                        unsigned long SessionPad;                                       //0x2c
                    };
                };
            };
        };
        union
        {
            struct
            {
                struct _RTL_RB_TREE OwnerTree;                                  //0x30
                struct _RTL_RB_TREE WaiterTree;                                 //0x40
            };
            char CpuPriorityKey;                                                //0x30
        };
        std::uint64_t EntryLock;                                                    //0x50
        union
        {
            unsigned short AllBoosts;                                                   //0x58
            struct
            {
                unsigned short IoBoost : 1;                                               //0x58
                unsigned short CpuBoostsBitmap : 15;                                      //0x58
            };
        };
        unsigned short IoNormalPriorityWaiterCount;                                     //0x5a
        unsigned short SparePad;                                                        //0x5c
    };

    //0x898 bytes (sizeof)
    struct ethread
    {
        struct kthread Tcb;                                                    //0x0
        union ularge_integer_t CreateTime;                                        //0x430
        union
        {
            union ularge_integer_t ExitTime;                                      //0x438
            struct list_entry_t KeyedWaitChain;                                  //0x438
        };
        union
        {
            struct list_entry_t PostBlockList;                                   //0x448
            struct
            {
                void* ForwardLinkShadow;                                        //0x448
                void* StartAddress;                                             //0x450
            };
        };
        union
        {
            struct _TERMINATION_PORT* TerminationPort;                          //0x458
            struct _ETHREAD* ReaperLink;                                        //0x458
            void* KeyedWaitValue;                                               //0x458
        };
        std::uint64_t ActiveTimerListLock;                                          //0x460
        struct list_entry_t ActiveTimerListHead;                                 //0x468
        struct _CLIENT_ID Cid;                                                  //0x478
        union
        {
            struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x488
            struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x488
        };
        union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x4a8
        struct list_entry_t IrpList;                                             //0x4b0
        std::uint64_t TopLevelIrp;                                                  //0x4c0
        struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x4c8
        void* Win32StartAddress;                                                //0x4d0
        void* ChargeOnlySession;                                                //0x4d8
        void* LegacyPowerObject;                                                //0x4e0
        struct list_entry_t ThreadListEntry;                                     //0x4e8
        struct _EX_RUNDOWN_REF RundownProtect;                                  //0x4f8
        struct _EX_PUSH_LOCK ThreadLock;                                        //0x500
        std::uint32_t ReadClusterSize;                                                  //0x508
        volatile long MmLockOrdering;                                           //0x50c
        union
        {
            std::uint32_t CrossThreadFlags;                                             //0x510
            struct
            {
                std::uint32_t Terminated : 1;                                             //0x510
                std::uint32_t ThreadInserted : 1;                                         //0x510
                std::uint32_t HideFromDebugger : 1;                                       //0x510
                std::uint32_t ActiveImpersonationInfo : 1;                                //0x510
                std::uint32_t HardErrorsAreDisabled : 1;                                  //0x510
                std::uint32_t BreakOnTermination : 1;                                     //0x510
                std::uint32_t SkipCreationMsg : 1;                                        //0x510
                std::uint32_t SkipTerminationMsg : 1;                                     //0x510
                std::uint32_t CopyTokenOnOpen : 1;                                        //0x510
                std::uint32_t ThreadIoPriority : 3;                                       //0x510
                std::uint32_t ThreadPagePriority : 3;                                     //0x510
                std::uint32_t RundownFail : 1;                                            //0x510
                std::uint32_t UmsForceQueueTermination : 1;                               //0x510
                std::uint32_t IndirectCpuSets : 1;                                        //0x510
                std::uint32_t DisableDynamicCodeOptOut : 1;                               //0x510
                std::uint32_t ExplicitCaseSensitivity : 1;                                //0x510
                std::uint32_t PicoNotifyExit : 1;                                         //0x510
                std::uint32_t DbgWerUserReportActive : 1;                                 //0x510
                std::uint32_t ForcedSelfTrimActive : 1;                                   //0x510
                std::uint32_t SamplingCoverage : 1;                                       //0x510
                std::uint32_t ReservedCrossThreadFlags : 8;                               //0x510
            };
        };
        union
        {
            std::uint32_t SameThreadPassiveFlags;                                       //0x514
            struct
            {
                std::uint32_t ActiveExWorker : 1;                                         //0x514
                std::uint32_t MemoryMaker : 1;                                            //0x514
                std::uint32_t StoreLockThread : 2;                                        //0x514
                std::uint32_t ClonedThread : 1;                                           //0x514
                std::uint32_t KeyedEventInUse : 1;                                        //0x514
                std::uint32_t SelfTerminate : 1;                                          //0x514
                std::uint32_t RespectIoPriority : 1;                                      //0x514
                std::uint32_t ActivePageLists : 1;                                        //0x514
                std::uint32_t SecureContext : 1;                                          //0x514
                std::uint32_t ZeroPageThread : 1;                                         //0x514
                std::uint32_t WorkloadClass : 1;                                          //0x514
                std::uint32_t ReservedSameThreadPassiveFlags : 20;                        //0x514
            };
        };
        union
        {
            std::uint32_t SameThreadApcFlags;                                           //0x518
            struct
            {
                std::uint8_t OwnsProcessAddressSpaceExclusive : 1;                       //0x518
                std::uint8_t OwnsProcessAddressSpaceShared : 1;                          //0x518
                std::uint8_t HardFaultBehavior : 1;                                      //0x518
                volatile std::uint8_t StartAddressInvalid : 1;                           //0x518
                std::uint8_t EtwCalloutActive : 1;                                       //0x518
                std::uint8_t SuppressSymbolLoad : 1;                                     //0x518
                std::uint8_t Prefetching : 1;                                            //0x518
                std::uint8_t OwnsVadExclusive : 1;                                       //0x518
                std::uint8_t SystemPagePriorityActive : 1;                               //0x519
                std::uint8_t SystemPagePriority : 3;                                     //0x519
                std::uint8_t AllowUserWritesToExecutableMemory : 1;                      //0x519
                std::uint8_t AllowKernelWritesToExecutableMemory : 1;                    //0x519
                std::uint8_t OwnsVadShared : 1;                                          //0x519
            };
        };
        std::uint8_t CacheManagerActive;                                               //0x51c
        std::uint8_t DisablePageFaultClustering;                                       //0x51d
        std::uint8_t ActiveFaultCount;                                                 //0x51e
        std::uint8_t LockOrderState;                                                   //0x51f
        std::uint32_t PerformanceCountLowReserved;                                      //0x520
        long PerformanceCountHighReserved;                                      //0x524
        std::uint64_t AlpcMessageId;                                                //0x528
        union
        {
            void* AlpcMessage;                                                  //0x530
            std::uint32_t AlpcReceiveAttributeSet;                                      //0x530
        };
        struct list_entry_t AlpcWaitListEntry;                                   //0x538
        long ExitStatus;                                                        //0x548
        std::uint32_t CacheManagerCount;                                                //0x54c
        std::uint32_t IoBoostCount;                                                     //0x550
        std::uint32_t IoQoSBoostCount;                                                  //0x554
        std::uint32_t IoQoSThrottleCount;                                               //0x558
        std::uint32_t KernelStackReference;                                             //0x55c
        struct list_entry_t BoostList;                                           //0x560
        struct list_entry_t DeboostList;                                         //0x570
        std::uint64_t BoostListLock;                                                //0x580
        std::uint64_t IrpListLock;                                                  //0x588
        void* ReservedForSynchTracking;                                         //0x590
        struct single_list_entry_t CmCallbackListHead;                           //0x598
        struct _GUID* ActivityId;                                               //0x5a0
        struct single_list_entry_t SeLearningModeListHead;                       //0x5a8
        void* VerifierContext;                                                  //0x5b0
        void* AdjustedClientToken;                                              //0x5b8
        void* WorkOnBehalfThread;                                               //0x5c0
        struct _PS_PROPERTY_SET PropertySet;                                    //0x5c8
        void* PicoContext;                                                      //0x5e0
        std::uint64_t UserFsBase;                                                   //0x5e8
        std::uint64_t UserGsBase;                                                   //0x5f0
        struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x5f8
        union
        {
            std::uint64_t SelectedCpuSets;                                          //0x600
            std::uint64_t* SelectedCpuSetsIndirect;                                 //0x600
        };
        struct _EJOB* Silo;                                                     //0x608
        struct unicode_string_t* ThreadName;                                     //0x610
        struct _CONTEXT* SetContextState;                                       //0x618
        std::uint32_t LastExpectedRunTime;                                              //0x620
        std::uint32_t HeapData;                                                         //0x624
        struct list_entry_t OwnerEntryListHead;                                  //0x628
        std::uint64_t DisownedOwnerEntryListLock;                                   //0x638
        struct list_entry_t DisownedOwnerEntryListHead;                          //0x640
        struct _KLOCK_ENTRY LockEntries[ 6 ];                                     //0x650
        void* CmDbgInfo;                                                        //0x890
    };

    typedef struct _NMI_CONTEXT
    {
        std::uint64_t  interrupted_rip;
        std::uint64_t  interrupted_rsp;
        kthread* kthread;
        std::uint32_t  callback_count;
        bool user_thread;
    } NMI_CONTEXT , * PNMI_CONTEXT;

	typedef struct
	{
		/**
		 * Reserved bits. Set to 0.
		 */
		std::uint32_t Reserved0;

		/**
		 * Stack pointer for privilege level 0.
		 */
		std::uint64_t Rsp0;

		/**
		 * Stack pointer for privilege level 1.
		 */
		std::uint64_t Rsp1;

		/**
		 * Stack pointer for privilege level 2.
		 */
		std::uint64_t Rsp2;

		/**
		 * Reserved bits. Set to 0.
		 */
		std::uint64_t Reserved1;

		/**
		 * Interrupt stack table pointer (1).
		 */
		std::uint64_t Ist1;

		/**
		 * Interrupt stack table pointer (2).
		 */
		std::uint64_t Ist2;

		/**
		 * Interrupt stack table pointer (3).
		 */
		std::uint64_t Ist3;

		/**
		 * Interrupt stack table pointer (4).
		 */
		std::uint64_t Ist4;

		/**
		 * Interrupt stack table pointer (5).
		 */
		std::uint64_t Ist5;

		/**
		 * Interrupt stack table pointer (6).
		 */
		std::uint64_t Ist6;

		/**
		 * Interrupt stack table pointer (7).
		 */
		std::uint64_t Ist7;

		/**
		 * Reserved bits. Set to 0.
		 */
		std::uint64_t Reserved2;

		/**
		 * Reserved bits. Set to 0.
		 */
		std::uint16_t Reserved3;

		/**
		 * The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
		 */
		std::uint16_t IoMapBase;
	} TASK_STATE_SEGMENT_64;

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS;
}