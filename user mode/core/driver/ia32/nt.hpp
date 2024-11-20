#pragma once

#define KUSER_SHARED_DATA (DWORD)0x7FFE0000
#define P_KUSER_SHARED_DATA_COOKIE reinterpret_cast<DWORD *>(KUSER_SHARED_DATA + 0x0330)

#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

////////////////////////////////////////////////////////////////////////////////////////////////
//Error Codes
////////////////////////////////////////////////////////////////////////////////////////////////

//Process  0x400001
#define PROCESS_UNABLE_TO_GET_HANDLE 0x400001
#define PROCESS_UNABLE_CREATE_SNAPSHOT 0x400002
#define PROCESS_READPROCESSMEMORY_FAILED_IN_AOB_SCAN 0x400002
#define PROCESS_FAILED_TO_ADJUST_TOKEN_PRIVILEGE 0x400003
#define PROCESS_FAILED_TO_LOOKUP_PRIVILEGE_VALUE 0x400004
#define PROCESS_OPEN_PROCESS_TOKEN_FAILED 0x400005
#define PROCESS_FAILED_TO_GET_PEB_OR_LDR 0x400006
#define PROCESS_FAILED_TO_ENABLE_DEBUG_PRIV 0x400007



//Memory 0x500001
#define MEMORY_CREATE_SECTION_FAILED 0x500001
#define MEMORY_MAP_VIEW_OF_SECTION_FAILED 0x500002
#define MEMORY_UNMAP_VIEW_OF_SECTION_FAILED 0x500003
#define MEMORY_ALLOCATE_VIRTUAL_MEMORY_FAILED 0x500004
#define MEMORY_FREE_VIRTUAL_MEMORY_FAILED 0x500005
#define MEMORY_PROTECT_VIRTUAL_MEMORY_FAILED 0x500006
#define MEMORY_QUERY_VIRTUAL_MEMORY_FAILED 0x500007
#define MEMORY_WRITE_VIRTUAL_MEMORY_FAILED 0x500008
#define MEMORY_READ_VIRTUAL_MEMORY_FAILED 0x500009

//Instrumentation Callback 0x600001
#define IC_FAILED_TO_FIND_OLD_IC 0x600001
#define IC_FAILED_TO_SET_PROCESS_INFORMATION 0x600002
#define IC_SHELL_FAILED_TO_CREATE_WORK 0x600003
#define IC_SHELL_FACTORY_NOT_READY_RETRYING 0x600004

//Mapping 0x700001
#define MAPPING_FAILED_TO_LOAD_DLL_STREAM 0x700001
#define MAPPING_DLL_FILE_SIZE_INVALID 0x700002
#define MAPPING_FAILED_TO_MALLOC 0x700003
#define MAPPING_INVALID_IMAGE_FORMAT 0x700004
#define MAPPING_FAILED_TO_WHITELIST_DLL_MEMORY 0x700005
#define MAPPING_INVALID_IMAGE_HASH 0x700006
#define MAPPING_SXS_NOT_SUPPORTED 0x700007
#define MAPPING_FAILED_TO_ALLOCATE_VEH_MOD_LIST 0x700008
#define MAPPING_FAILED_TO_READ_VEH_MOD_LIST 0x700009
#define MAPPING_FAILED_TO_WRITE_VEH_MOD_LIST 0x70000A

//Name Resolve 0x800001
#define NAME_RESOLVE_FAILED_INIT 0x800001

//Internals 0x900001
#define INTERNALS_FAILED_TO_ALLOC_HEAP_FOR_DUMMY_LDR 0x900001
#define INTERNALS_FAILED_TO_ACTIVATE_SEH_EXCEPTIONS 0x900002

namespace riot
{
	typedef enum _WORKERFACTORYINFOCLASS
	{
		WorkerFactoryTimeout , // LARGE_INTEGER
		WorkerFactoryRetryTimeout , // LARGE_INTEGER
		WorkerFactoryIdleTimeout , // s: LARGE_INTEGER
		WorkerFactoryBindingCount , // s: ULONG
		WorkerFactoryThreadMinimum , // s: ULONG
		WorkerFactoryThreadMaximum , // s: ULONG
		WorkerFactoryPaused , // ULONG or BOOLEAN
		WorkerFactoryBasicInformation , // q: WORKER_FACTORY_BASIC_INFORMATION
		WorkerFactoryAdjustThreadGoal ,
		WorkerFactoryCallbackType ,
		WorkerFactoryStackInformation , // 10
		WorkerFactoryThreadBasePriority , // s: ULONG
		WorkerFactoryTimeoutWaiters , // s: ULONG, since THRESHOLD
		WorkerFactoryFlags , // s: ULONG
		WorkerFactoryThreadSoftMaximum , // s: ULONG
		WorkerFactoryThreadCpuSets , // since REDSTONE5
		MaxWorkerFactoryInfoClass
	} WORKERFACTORYINFOCLASS , * PWORKERFACTORYINFOCLASS;

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS;

	typedef struct _TLS_ENTRY
	{
		LIST_ENTRY				TlsEntryLinks;
		IMAGE_TLS_DIRECTORY		TlsDirectory;
		PVOID 					ModuleEntry; //LdrDataTableEntry
		SIZE_T					TlsIndex;
	} TLS_ENTRY , * PTLS_ENTRY;

	using f_CreateThreadpoolWork = PTP_WORK( __stdcall* )(
		_In_ PTP_WORK_CALLBACK pfnwk ,
		_Inout_opt_ PVOID pv ,
		_In_opt_ PTP_CALLBACK_ENVIRON pcbe
		);

	using f_TpAllocWork = NTSTATUS( __stdcall* )(
		PTP_WORK* a ,
		_In_ PTP_WORK_CALLBACK pfnwk ,
		_Inout_opt_ PVOID pv ,
		_In_opt_ PTP_CALLBACK_ENVIRON pcbe
		);

	using f_SubmitThreadpoolWork = VOID( __stdcall* )(
		_Inout_ PTP_WORK pwk
		);

	using f_CloseThreadpoolWork = VOID( __stdcall* )(
		_Inout_ PTP_WORK pwk
		);

	using f_CreateThreadpool = PTP_POOL( __stdcall* )(
		_Reserved_ PVOID reserved
		);

	using f_WaitForThreadpoolWorkCallbacks = void( __stdcall* )(
		_Inout_ PTP_WORK pwk ,
		_In_ BOOL fCancelPendingCallbacks
		);

	using f_RtlRestoreContext = VOID( __cdecl* )( PCONTEXT ContextRecord , _EXCEPTION_RECORD* ExceptionRecord );

	using f_NtQueryInformationProcess = NTSTATUS( __stdcall* )(
		HANDLE ProcessHandle ,
		PROCESSINFOCLASS ProcessInformationClass ,
		PVOID ProcessInformation ,
		ULONG ProcessInformationLength ,
		PULONG ReturnLength
		);

	using f_RtlAnsiStringToUnicodeString = NTSTATUS( __stdcall* )
		(
			UNICODE_STRING* DestinationString ,
			const ANSI_STRING* SourceString ,
			BOOLEAN					AllocateDestinationString
			);

	typedef NTSTATUS( NTAPI* f_NtOpenProcess )(
		PHANDLE            ProcessHandle ,
		ACCESS_MASK        DesiredAccess ,
		POBJECT_ATTRIBUTES ObjectAttributes ,
		CLIENT_ID* ClientId
		);

	typedef NTSTATUS( NTAPI* f_NtQueryVirtualMemory )( HANDLE ProcessHandle ,
		PVOID BaseAddress ,
		MEMORY_INFORMATION_CLASS MemoryInformationClass ,
		PVOID MemoryInformation ,
		SIZE_T MemoryInformationLength ,
		PSIZE_T ReturnLength );

	typedef NTSTATUS( NTAPI* f_NtProtectVirtualMemory )(
		IN HANDLE               ProcessHandle ,
		IN OUT PVOID* BaseAddress ,
		IN OUT PULONG           NumberOfBytesToProtect ,
		IN ULONG                NewAccessProtection ,
		OUT PULONG              OldAccessProtection );

	typedef NTSTATUS( NTAPI* f_NtAllocateVirtualMemory ) (
		HANDLE ProcessHandle ,
		PVOID* BaseAddress ,
		ULONG_PTR ZeroBits ,
		PSIZE_T RegionSize ,
		ULONG AllocationType ,
		ULONG Protect );

	//NtSetInformationWorkerFactory
	using f_NtSetInformationWorkerFactory = NTSTATUS( __stdcall* )
		(
			__in HANDLE WorkerFactoryHandle ,
			__in WORKERFACTORYINFOCLASS WorkerFactoryInformationClass ,
			__in_bcount( WorkerFactoryInformationLength ) PVOID WorkerFactoryInformation ,
			__in ULONG WorkerFactoryInformationLength
			);

	using f_NtFreeVirtualMemory = NTSTATUS( __stdcall* )
		(
			HANDLE		ProcessHandle ,
			PVOID* BaseAddress ,
			SIZE_T* RegionSize ,
			ULONG		FreeType
			);

	using f_NtQueryObject = NTSTATUS( __stdcall* )
		(
			HANDLE                   Handle ,
			OBJECT_INFORMATION_CLASS ObjectInformationClass ,
			PVOID                    ObjectInformation ,
			ULONG                    ObjectInformationLength ,
			PULONG                   ReturnLength
			);

	//NtWorkerFactoryWorkerReady

	using f_NtWorkerFactoryWorkerReady = NTSTATUS( __stdcall* )
		(
			HANDLE                   Handle
			);

	using f_NtQueryInformationWorkerFactory = NTSTATUS( __stdcall* )
		(
			_In_ HANDLE WorkerFactoryHandle ,
			_In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass ,
			_In_reads_bytes_( WorkerFactoryInformationLength ) PVOID WorkerFactoryInformation ,
			_In_ ULONG WorkerFactoryInformationLength ,
			_Out_opt_ PULONG ReturnLength
			);

	using f_LdrGetProcedureAddress = NTSTATUS( __stdcall* )
		(
			PVOID				BaseAddress ,
			ANSI_STRING* Name ,
			ULONG				Ordinal ,
			PVOID* ProcedureAddress
			);

	using f_NtOpenSection = NTSTATUS( __stdcall* )
		(
			PHANDLE            SectionHandle ,
			ACCESS_MASK        DesiredAccess ,
			OBJECT_ATTRIBUTES* ObjectAttributes
			);

	using f_NtOpenFile = NTSTATUS( __stdcall* )
		(
			PHANDLE            FileHandle ,
			ACCESS_MASK        DesiredAccess ,
			POBJECT_ATTRIBUTES ObjectAttributes ,
			PIO_STATUS_BLOCK   IoStatusBlock ,
			ULONG              ShareAccess ,
			ULONG              OpenOptions
			);

	using f_NtCreateThreadEx = NTSTATUS( __stdcall* )
		(
			HANDLE* pHandle ,
			ACCESS_MASK		DesiredAccess ,
			void* pAttr ,
			HANDLE			hTargetProc ,
			void* pFunc ,
			void* pArg ,
			ULONG			Flags ,
			SIZE_T			ZeroBits ,
			SIZE_T			StackSize ,
			SIZE_T			MaxStackSize ,
			void* pAttrListOut
			);

	using f_RtlAllocateHeap = PVOID( __stdcall* )
		(
			std::uint64_t	HeapHandle ,
			ULONG	Flags ,
			SIZE_T	Size
			);

	using f_RtlFreeHeap = BOOLEAN( __stdcall* )
		(
			std::uint64_t	HeapHandle ,
			ULONG	Flags ,
			PVOID	BaseAddress
			);

	using f_memmove = VOID( __cdecl* )
		(
			PVOID	UNALIGNED	Destination ,
			LPCVOID	UNALIGNED	Source ,
			SIZE_T				Length
			);

	using f_RtlZeroMemory = VOID( __stdcall* )
		(
			PVOID	UNALIGNED	Destination ,
			SIZE_T				Length
			);

	using f_NtCreateSection = NTSTATUS( NTAPI* )( OUT PHANDLE SectionHandle , IN ULONG DesiredAccess , IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL , IN PLARGE_INTEGER MaximumSize OPTIONAL , IN ULONG PageAttributess , IN ULONG SectionAttributes , IN HANDLE FileHandle OPTIONAL );
	using f_NtMapViewOfSection = NTSTATUS( NTAPI* )( HANDLE SectionHandle , HANDLE ProcessHandle , PVOID* BaseAddress , ULONG_PTR ZeroBits , SIZE_T CommitSize , PLARGE_INTEGER SectionOffset , PSIZE_T ViewSize , DWORD InheritDisposition , ULONG AllocationType , ULONG Win32Protect );
	using f_NtUnmapViewOfSection = NTSTATUS( NTAPI* )( HANDLE ProcessHandle , PVOID BaseAddress );

	typedef NTSTATUS( NTAPI* f_NtSetInformationProcess )(
		HANDLE ProcessHandle ,
		PROCESS_INFORMATION_CLASS ProcessInformationClass ,
		PVOID ProcessInformation ,
		ULONG ProcessInformationLength
		);


	//RtlDosApplyFileIsolationRedirection_Ustr
	typedef NTSTATUS( NTAPI* f_RtlDosApplyFileIsolationRedirection_Ustr )(
		ULONG Flags ,
		PUNICODE_STRING OriginalName ,
		PUNICODE_STRING Extension ,
		PUNICODE_STRING StaticString ,
		PUNICODE_STRING DynamicString ,
		PUNICODE_STRING* NewName ,
		PULONG NewFlags ,
		PSIZE_T FileNameSize ,
		PSIZE_T RequiredLength
		);

	typedef NTSTATUS( NTAPI* f_NtSuspendProcess )(
		HANDLE ProcessHandle
		);

	typedef NTSTATUS( NTAPI* f_NtResumeProcess )(
		HANDLE ProcessHandle
		);

	typedef VOID( NTAPI* f_RtlInitUnicodeString )( PUNICODE_STRING DestinationString , PCWSTR SourceString );
	typedef VOID( NTAPI* f_RtlFreeUnicodeString )( PUNICODE_STRING UnicodeString );

	typedef VOID( __stdcall* f_WhitelistMem )( std::uintptr_t BaseAddr , std::size_t Sz , bool Active );

	typedef struct _PHYSICAL_MEMORY_RANGE {
		PHYSICAL_ADDRESS BaseAddress;
		LARGE_INTEGER NumberOfBytes;
	} PHYSICAL_MEMORY_RANGE , * PPHYSICAL_MEMORY_RANGE;

	typedef struct _SYSTEM_BIGPOOL_ENTRY
	{
		union
		{
			PVOID VirtualAddress;
			ULONG_PTR NonPaged : 1;
		};
		ULONG_PTR SizeInBytes;
		union
		{
			UCHAR Tag[ 4 ];
			ULONG TagUlong;
		};
	} SYSTEM_BIGPOOL_ENTRY , * PSYSTEM_BIGPOOL_ENTRY;

	typedef struct _SYSTEM_BIGPOOL_INFORMATION
	{
		ULONG Count;
		SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ ANYSIZE_ARRAY ];
	} SYSTEM_BIGPOOL_INFORMATION , * PSYSTEM_BIGPOOL_INFORMATION;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBigPoolInformation = 0x42
	} SSYSTEM_INFORMATION_CLASS;

	typedef NTSTATUS( WINAPI* pNtQuerySystemInformation )(
		IN _SYSTEM_INFORMATION_CLASS SystemInformationClass ,
		OUT PVOID                   SystemInformation ,
		IN ULONG                    SystemInformationLength ,
		OUT PULONG                  ReturnLength
		);

	typedef NTSTATUS( NTAPI* f_RtlDosApplyFileIsolationRedirection_Ustr )(
		ULONG Flags ,
		PUNICODE_STRING OriginalName ,
		PUNICODE_STRING Extension ,
		PUNICODE_STRING StaticString ,
		PUNICODE_STRING DynamicString ,
		PUNICODE_STRING* NewName ,
		PULONG NewFlags ,
		PSIZE_T FileNameSize ,
		PSIZE_T RequiredLength
		);

	typedef struct _list_entry {
		struct _list_entry* flink;
		struct _list_entry* blink;
	} list_entry , * plist_entry;

	template <int n>
	using const_int = std::integral_constant<int , n>;

	template<typename T>
	constexpr bool is32bit = std::is_same_v<T , uint32_t>;

	template<typename T , typename T32 , typename T64>
	using type_32_64 = std::conditional_t<is32bit<T> , T32 , T64>;

	template<typename T , int v32 , int v64>
	constexpr int int_32_64 = std::conditional_t<is32bit<T> , const_int<v32> , const_int<v64>>::value;

	template <typename T>
	struct _GDI_TEB_BATCH_T
	{
		uint32_t Offset;
		T HDC;
		uint32_t Buffer[ 310 ];
	};

	template <typename T>
	struct _ACTIVATION_CONTEXT_STACK_T
	{
		T ActiveFrame;
		list_entry FrameListCache;
		uint32_t Flags;
		uint32_t NextCookieSequenceNumber;
		uint32_t StackId;
	};

	template <typename T>
	struct _TEB_T
	{
		struct Specific32_1
		{
			uint8_t InstrumentationCallbackDisabled;
			uint8_t SpareBytes[ 23 ];
			uint32_t TxFsContext;
		};

		struct Specific64_1
		{
			uint32_t TxFsContext;
			uint32_t InstrumentationCallbackDisabled;
		};

		struct Specific64_2
		{
			T TlsExpansionSlots;
			T DeallocationBStore;
			T BStoreLimit;
		};

		struct Specific32_2
		{
			T TlsExpansionSlots;
		};

		NT_TIB NtTib;
		T EnvironmentPointer;
		CLIENT_ID ClientId;
		T ActiveRpcHandle;
		T ThreadLocalStoragePointer;
		T ProcessEnvironmentBlock;
		uint32_t LastErrorValue;
		uint32_t CountOfOwnedCriticalSections;
		T CsrClientThread;
		T Win32ThreadInfo;
		uint32_t User32Reserved[ 26 ];
		uint32_t UserReserved[ 5 ];
		T WOW32Reserved;
		uint32_t CurrentLocale;
		uint32_t FpSoftwareStatusRegister;
		T ReservedForDebuggerInstrumentation[ 16 ];
		T SystemReserved1[ int_32_64<T , 26 , 30> ];
		uint8_t PlaceholderCompatibilityMode;
		uint8_t PlaceholderReserved[ 11 ];
		uint32_t ProxiedProcessId;
		_ACTIVATION_CONTEXT_STACK_T<T> ActivationStack;
		uint8_t WorkingOnBehalfTicket[ 8 ];
		uint32_t ExceptionCode;
		T ActivationContextStackPointer;
		T InstrumentationCallbackSp;
		T InstrumentationCallbackPreviousPc;
		T InstrumentationCallbackPreviousSp;
		type_32_64<T , Specific32_1 , Specific64_1> spec1;
		_GDI_TEB_BATCH_T<T> GdiTebBatch;
		_CLIENT_ID RealClientId;
		T GdiCachedProcessHandle;
		uint32_t GdiClientPID;
		uint32_t GdiClientTID;
		T GdiThreadLocalInfo;
		T Win32ClientInfo[ 62 ];
		T glDispatchTable[ 233 ];
		T glReserved1[ 29 ];
		T glReserved2;
		T glSectionInfo;
		T glSection;
		T glTable;
		T glCurrentRC;
		T glContext;
		uint32_t LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		wchar_t StaticUnicodeBuffer[ 261 ];
		T DeallocationStack;
		T TlsSlots[ 64 ];
		list_entry TlsLinks;
		T Vdm;
		T ReservedForNtRpc;
		T DbgSsReserved[ 2 ];
		uint32_t HardErrorMode;
		T Instrumentation[ int_32_64<T , 9 , 11> ];
		GUID ActivityId;
		T SubProcessTag;
		T PerflibData;
		T EtwTraceData;
		T WinSockData;
		uint32_t GdiBatchCount;             // TEB64 pointer
		uint32_t IdealProcessorValue;
		uint32_t GuaranteedStackBytes;
		T ReservedForPerf;
		T ReservedForOle;
		uint32_t WaitingOnLoaderLock;
		T SavedPriorityState;
		T ReservedForCodeCoverage;
		T ThreadPoolData;
		type_32_64<T , Specific32_2 , Specific64_2> spec2;
		uint32_t MuiGeneration;
		uint32_t IsImpersonating;
		T NlsCache;
		T pShimData;
		uint16_t HeapVirtualAffinity;
		uint16_t LowFragHeapDataSlot;
		T CurrentTransactionHandle;
		T ActiveFrame;
		T FlsData;
		T PreferredLanguages;
		T UserPrefLanguages;
		T MergedPrefLanguages;
		uint32_t MuiImpersonation;
		uint16_t CrossTebFlags;
		union
		{
			uint16_t SameTebFlags;
			struct
			{
				uint16_t SafeThunkCall : 1;
				uint16_t InDebugPrint : 1;
				uint16_t HasFiberData : 1;
				uint16_t SkipThreadAttach : 1;
				uint16_t WerInShipAssertCode : 1;
				uint16_t RanProcessInit : 1;
				uint16_t ClonedThread : 1;
				uint16_t SuppressDebugMsg : 1;
				uint16_t DisableUserStackWalk : 1;
				uint16_t RtlExceptionAttached : 1;
				uint16_t InitialThread : 1;
				uint16_t SessionAware : 1;
				uint16_t LoadOwner : 1;
				uint16_t LoaderWorker : 1;
				uint16_t SkipLoaderInit : 1;
				uint16_t SpareSameTebBits : 1;
			};
		};
		T TxnScopeEnterCallback;
		T TxnScopeExitCallback;
		T TxnScopeContext;
		uint32_t LockCount;
		uint32_t WowTebOffset;
		T ResourceRetValue;
		T ReservedForWdf;
		uint64_t ReservedForCrt;
		GUID EffectiveContainerId;
	};

	using _TEB32 = _TEB_T<uint32_t>;
	using _TEB64 = _TEB_T<uint64_t>;
	using teb_t = _TEB_T<uintptr_t>;

	inline f_NtCreateSection NtCreateSection;
	inline f_NtMapViewOfSection NtMapViewOfSection;
	inline f_NtUnmapViewOfSection NtUnmapViewOfSection;
	inline f_RtlDosApplyFileIsolationRedirection_Ustr RtlDosApplyFileIsolationRedirection_Ustr;

	using f_LdrLockLoaderLock = NTSTATUS( __stdcall* )
		(
			ULONG			Flags ,
			ULONG* State ,
			ULONG_PTR* Cookie
			);

	using f_LdrUnlockLoaderLock = NTSTATUS( __stdcall* )
		(
			ULONG		Flags ,
			ULONG_PTR	Cookie
			);

	using f_RtlInsertInvertedFunctionTable = BOOL( __fastcall* )
		(
			void* ImageBase ,
			DWORD	SizeOfImage
			);

	using f_RtlAddVectoredExceptionHandler = PVOID( __stdcall* )
		(
			ULONG						FirstHandler ,
			PVECTORED_EXCEPTION_HANDLER VectoredHandler
			);

	using f_LdrProtectMrdata = VOID( __stdcall* )
		(
			BOOL bProtected
			);

	using f_RtlAddFunctionTable = BOOL( __stdcall* )
		(
			RUNTIME_FUNCTION* FunctionTable ,
			DWORD				EntryCount ,
			DWORD64				BaseAddress
			);

	using f_LdrpHandleTlsData = NTSTATUS( __fastcall* )
		(
			LDR_DATA_TABLE_ENTRY* pEntry
			);

	typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
	{
		IMAGE_RUNTIME_FUNCTION_ENTRY* ExceptionDirectory;
		PVOID							ImageBase;
		ULONG							ImageSize;
		ULONG							SizeOfTable;
	} RTL_INVERTED_FUNCTION_TABLE_ENTRY , * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

	typedef struct _RTL_INVERTED_FUNCTION_TABLE
	{
		ULONG Count;
		ULONG MaxCount;
		ULONG Epoch;
		UCHAR Overflow;
		RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ ANYSIZE_ARRAY ];
	} RTL_INVERTED_FUNCTION_TABLE , * PRTL_INVERTED_FUNCTION_TABLE;

	using f_GetCurrentThreadId = DWORD( __stdcall* )( );

	template <typename T>
	struct _NT_TIB_T
	{
		T ExceptionList;
		T StackBase;
		T StackLimit;
		T SubSystemTib;
		T FiberData;
		T ArbitraryUserPointer;
		T Self;
	};

	template <typename T>
	struct _CLIENT_ID_T
	{
		T UniqueProcess;
		T UniqueThread;
	};

	template <typename T>
	struct _UNICODE_STRING_T
	{
		using type = T;

		uint16_t Length;
		uint16_t MaximumLength;
		T Buffer;
	};

	template <typename T>
	struct _LIST_ENTRY_T
	{
		T Flink;
		T Blink;
	};

	template<typename T>
	struct _PEB_T
	{
		static_assert( std::is_same_v<T , uint32_t> || std::is_same_v<T , uint64_t> , "T must be uint32_t or uint64_t" );

		uint8_t InheritedAddressSpace;
		uint8_t ReadImageFileExecOptions;
		uint8_t BeingDebugged;
		union
		{
			uint8_t BitField;
			struct
			{
				uint8_t ImageUsesLargePages : 1;
				uint8_t IsProtectedProcess : 1;
				uint8_t IsImageDynamicallyRelocated : 1;
				uint8_t SkipPatchingUser32Forwarders : 1;
				uint8_t IsPackagedProcess : 1;
				uint8_t IsAppContainer : 1;
				uint8_t IsProtectedProcessLight : 1;
				uint8_t SpareBits : 1;
			};
		};
		T Mutant;
		T ImageBaseAddress;
		T Ldr;
		T ProcessParameters;
		T SubSystemData;
		T ProcessHeap;
		T FastPebLock;
		T AtlThunkSListPtr;
		T IFEOKey;
		union
		{
			T CrossProcessFlags;
			struct
			{
				uint32_t ProcessInJob : 1;
				uint32_t ProcessInitializing : 1;
				uint32_t ProcessUsingVEH : 1;
				uint32_t ProcessUsingVCH : 1;
				uint32_t ProcessUsingFTH : 1;
				uint32_t ReservedBits0 : 27;
			};
		};
		union
		{
			T KernelCallbackTable;
			T UserSharedInfoPtr;
		};
		uint32_t SystemReserved;
		uint32_t AtlThunkSListPtr32;
		T ApiSetMap;
		union
		{
			uint32_t TlsExpansionCounter;
			T Padding2;
		};
		T TlsBitmap;
		uint32_t TlsBitmapBits[ 2 ];
		T ReadOnlySharedMemoryBase;
		T SparePvoid0;
		T ReadOnlyStaticServerData;
		T AnsiCodePageData;
		T OemCodePageData;
		T UnicodeCaseTableData;
		uint32_t NumberOfProcessors;
		uint32_t NtGlobalFlag;
		LARGE_INTEGER CriticalSectionTimeout;
		T HeapSegmentReserve;
		T HeapSegmentCommit;
		T HeapDeCommitTotalFreeThreshold;
		T HeapDeCommitFreeBlockThreshold;
		uint32_t NumberOfHeaps;
		uint32_t MaximumNumberOfHeaps;
		T ProcessHeaps;
		T GdiSharedHandleTable;
		T ProcessStarterHelper;
		union
		{
			uint32_t GdiDCAttributeList;
			T Padding3;
		};
		T LoaderLock;
		uint32_t OSMajorVersion;
		uint32_t OSMinorVersion;
		uint16_t OSBuildNumber;
		uint16_t OSCSDVersion;
		uint32_t OSPlatformId;
		uint32_t ImageSubsystem;
		uint32_t ImageSubsystemMajorVersion;
		union
		{
			uint32_t ImageSubsystemMinorVersion;
			T Padding4;
		};
		T ActiveProcessAffinityMask;
		uint32_t GdiHandleBuffer[ int_32_64<T , 34 , 60> ];
		T PostProcessInitRoutine;
		T TlsExpansionBitmap;
		uint32_t TlsExpansionBitmapBits[ 32 ];
		union
		{
			uint32_t SessionId;
			T Padding5;
		};
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		T pShimData;
		T AppCompatInfo;
		_UNICODE_STRING_T<T> CSDVersion;
		T ActivationContextData;
		T ProcessAssemblyStorageMap;
		T SystemDefaultActivationContextData;
		T SystemAssemblyStorageMap;
		T MinimumStackCommit;
		T FlsCallback;
		_LIST_ENTRY_T<T> FlsListHead;
		T FlsBitmap;
		uint32_t FlsBitmapBits[ 4 ];
		uint32_t FlsHighIndex;
		T WerRegistrationData;
		T WerShipAssertPtr;
		T pUnused;
		T pImageHeaderHash;
		union
		{
			uint64_t TracingFlags;
			struct
			{
				uint32_t HeapTracingEnabled : 1;
				uint32_t CritSecTracingEnabled : 1;
				uint32_t LibLoaderTracingEnabled : 1;
				uint32_t SpareTracingBits : 29;
			};
		};
		T CsrServerReadOnlySharedMemoryBase;
	};

	using _PEB32 = _PEB_T<uint32_t>;
	using _PEB64 = _PEB_T<uint64_t>;
	using PEB_T = _PEB_T<uintptr_t>;
}