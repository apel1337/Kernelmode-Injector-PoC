#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

constexpr char piddb_lock_sig[ ] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24";
constexpr char piddb_lock_mask[ ] = "xxx????x????xxxx";

constexpr char piddb_table_sig[ ] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x1D\x00\x00\x00\x00\x48\x85\xC0\x0F";
constexpr char piddb_table_mask[ ] = "xxx????x????xxx????xxxx";

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

constexpr auto ntoskrnl_path = "C:\\Windows\\System32\\ntoskrnl.exe";
constexpr auto page_size = 0x1000;

constexpr auto SystemModuleInformation = 11;
constexpr auto SystemHandleInformation = 16;
constexpr auto SystemExtendedHandleInformation = 64;

typedef struct _SYSTEM_HANDLE
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE , * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION_EX , * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION , * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES , * PRTL_PROCESS_MODULES;

typedef LARGE_INTEGER PHYSICAL_ADDRESS , * PPHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS , * PMMCOPY_ADDRESS;

typedef struct PiDDBCacheEntry
{
    LIST_ENTRY		list;
    UNICODE_STRING	driver_name;
    ULONG			time_stamp;
    NTSTATUS		load_status;
    char			_0x0028[ 16 ]; // data from the shim engine, or uninitialized memory for custom drivers
}PIDCacheobj;

using ExAcquireResourceExclusiveLite = BOOLEAN ( __stdcall* )( void* , bool );
using RtlLookupElementGenericTableAvl = PIDCacheobj * ( __stdcall* ) ( void* , void* );
using RtlDeleteElementGenericTableAvl = bool ( __stdcall* )( void* , void* );
using ExReleaseResourceLite = bool ( __stdcall* )( void* );

typedef CCHAR KPROCESSOR_MODE;
typedef enum _MODE {
    KernelMode ,
    UserMode ,
    MaximumMode
} MODE;

typedef enum _POOL_TYPE {
    NonPagedPool ,
    NonPagedPoolExecute ,
    PagedPool ,
    NonPagedPoolMustSucceed ,
    DontUseThisType ,
    NonPagedPoolCacheAligned ,
    PagedPoolCacheAligned ,
    NonPagedPoolCacheAlignedMustS ,
    MaxPoolType ,
    NonPagedPoolBase ,
    NonPagedPoolBaseMustSucceed ,
    NonPagedPoolBaseCacheAligned ,
    NonPagedPoolBaseCacheAlignedMustS ,
    NonPagedPoolSession ,
    PagedPoolSession ,
    NonPagedPoolMustSucceedSession ,
    DontUseThisTypeSession ,
    NonPagedPoolCacheAlignedSession ,
    PagedPoolCacheAlignedSession ,
    NonPagedPoolCacheAlignedMustSSession ,
    NonPagedPoolNx ,
    NonPagedPoolNxCacheAligned ,
    NonPagedPoolSessionNx
} POOL_TYPE;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached ,
    MmCached ,
    MmWriteCombined ,
    MmHardwareCoherentCached ,
    MmNonCachedUnordered ,
    MmUSWCCached ,
    MmMaximumCacheType ,
    MmNotMapped
} MEMORY_CACHING_TYPE;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[ MaximumMode ];
    struct _KPROCESS* Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE , * PKAPC_STATE , * PRKAPC_STATE;

using PEPROCESS = PVOID;

using ZwOpenProcess = NTSYSAPI NTSTATUS ( __fastcall* )(
    PHANDLE            ProcessHandle ,
    ACCESS_MASK        DesiredAccess ,
    POBJECT_ATTRIBUTES ObjectAttributes ,
    CLIENT_ID* ClientId
    );

using ZwAllocateVirtualMemory = NTSTATUS ( __fastcall* )(
    _In_    HANDLE    ProcessHandle ,
    _Inout_ PVOID* BaseAddress ,
    _In_    ULONG_PTR ZeroBits ,
    _Inout_ PSIZE_T   RegionSize ,
    _In_    ULONG     AllocationType ,
    _In_    ULONG     Protect
    );

using MmCopyVirtualMemory = NTSTATUS ( __fastcall* )(
    IN PEPROCESS FromProcess ,
    IN PVOID FromAddress ,
    IN PEPROCESS ToProcess ,
    OUT PVOID ToAddress ,
    IN SIZE_T BufferSize ,
    IN KPROCESSOR_MODE PreviousMode ,
    OUT PSIZE_T NumberOfBytesCopied
    );

using PsLookupProcessByProcessId = NTSTATUS ( __fastcall* )(
    HANDLE    ProcessId ,
    PEPROCESS* Process
    );

using MmCopyMemory = NTSTATUS ( __stdcall* )(
    PVOID ,
    MM_COPY_ADDRESS ,
    SIZE_T ,
    ULONG ,
    PSIZE_T
    );

using MmGetVirtualForPhysical = PVOID ( __fastcall* )(
    __in PHYSICAL_ADDRESS PhysicalAddress
    );

using MmGetPhysicalAddress = PVOID ( __fastcall* )(
    __in PVOID BaseAddress
    );

using ExAllocatePool = PVOID ( __fastcall* ) (
    POOL_TYPE PoolType ,
    SIZE_T NumberOfBytes
    );

using ExFreePool = void*( __fastcall* ) (
    void* BaseAddress
    );

using IoAllocateMdl = PVOID ( __fastcall* )(
    __drv_aliasesMem PVOID VirtualAddress ,
    ULONG                  Length ,
    BOOLEAN                SecondaryBuffer ,
    BOOLEAN                ChargeQuota ,
    PVOID                  Irp
    );

using MmBuildMdlForNonPagedPool = void ( __fastcall* )(
    PVOID MemoryDescriptorList
    );

using MmMapLockedPagesSpecifyCache = PVOID ( __fastcall* )(
    PVOID                                                                         MemoryDescriptorList ,
    KPROCESSOR_MODE                                                               AccessMode ,
    MEMORY_CACHING_TYPE                                                           CacheType ,
    PVOID                                                                         RequestedAddress ,
    ULONG                                                                         BugCheckOnFailure ,
    ULONG                                                                         Priority
    );

using KeUnstackDetachProcess = void ( __fastcall* )(
    PRKAPC_STATE ApcState
    );

using KeStackAttachProcess = void ( __fastcall* )(
    PEPROCESS           PROCESS ,
    PRKAPC_STATE        ApcState
    );

using ZwLockVirtualMemory = NTSTATUS ( __fastcall* )(
    IN HANDLE ,
    IN OUT PVOID ,
    IN OUT PULONG ,
    IN ULONG
    );

using PEPROCESS = PVOID;
using ExAllocatePool = PVOID ( __stdcall* ) ( POOL_TYPE , SIZE_T );
using ExAllocatePoolWithTag = PVOID ( __stdcall* )( POOL_TYPE , SIZE_T , ULONG );
using MmCopyMemory = NTSTATUS ( __stdcall* )( PVOID , MM_COPY_ADDRESS , SIZE_T , ULONG , PSIZE_T );
using DRIVER_INITIALIZE = NTSTATUS ( __stdcall* )( std::uintptr_t , std::size_t );
using ExAcquireResourceExclusiveLite = BOOLEAN ( __stdcall* )( void* , bool );
using RtlLookupElementGenericTableAvl = PIDCacheobj * ( __stdcall* ) ( void* , void* );
using RtlDeleteElementGenericTableAvl = bool ( __stdcall* )( void* , void* );
using ExReleaseResourceLite = bool ( __stdcall* )( void* );
using PsLookupProcessByProcessId = NTSTATUS ( __fastcall* )( HANDLE , PEPROCESS* );
using PsGetProcessSectionBaseAddress = void* ( __fastcall* )( PEPROCESS );