#include <core/linkers/exports.h>

namespace riot
{
	namespace exports
	{
        template< class type_t >
        [[ nodiscard ]]
        type_t find_export( const char* export_name )
        {
            auto dos_header = reinterpret_cast< dos_header_t* >( g::ntos_base_address );
            if ( !dos_header->is_valid( ) ) {
                return false;
            }

            auto m_nt_header = reinterpret_cast< nt_headers_t* >( reinterpret_cast< std::uint64_t >( dos_header ) + dos_header->m_lfanew );
            if ( !m_nt_header->is_valid( ) ) {
                return false;
            }

            auto library{ reinterpret_cast< std::int8_t* >( dos_header ) };
            auto export_directory = 
                reinterpret_cast< export_directory_t* > ( g::ntos_base_address + m_nt_header->m_export_table.m_virtual_address );
            if ( !export_directory->m_address_of_functions
                || !export_directory->m_address_of_names
                || !export_directory->m_address_of_names_ordinals )
                return {};

            auto names{ reinterpret_cast< std::int32_t* >( library + export_directory->m_address_of_names ) };
            auto functions{ reinterpret_cast< std::int32_t* >( library + export_directory->m_address_of_functions ) };
            auto ordinals{ reinterpret_cast< std::int16_t* >( library + export_directory->m_address_of_names_ordinals ) };

            for ( std::int32_t i = 0; i < export_directory->m_number_of_names; i++ ) {
                auto current_name{ library + names[ i ] };
                auto current_function{ library + functions[ ordinals[ i ] ] };

                if ( !std::strcmp( export_name , reinterpret_cast< char* >( current_name ) ) )
                    return reinterpret_cast< type_t >( current_function );
            }

            return reinterpret_cast< type_t >( 0 );
        }

        [[nodiscard]]
        void* ex_allocate_pool(
            POOL_TYPE pool_type ,
            SIZE_T number_of_bytes
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ExAllocatePool" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                POOL_TYPE pool_type ,
                SIZE_T number_of_bytes
                );

            return reinterpret_cast< function_t* >( function_address )(
                pool_type ,
                number_of_bytes );
        }

        [[nodiscard]]
        void* ex_allocate_pool2(
            POOL_FLAGS flags ,
            SIZE_T number_of_bytes ,
            ULONG tag
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ExAllocatePool2" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                POOL_FLAGS flags ,
                SIZE_T number_of_bytes ,
                ULONG tag
                );

            return reinterpret_cast< function_t* >( function_address )(
                flags ,
                number_of_bytes ,
                tag );
        }

        [[ nodiscard ]]
        void ex_free_pool(
            void* base_address
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ExFreePool" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void (
                void* base_address
                );

             reinterpret_cast< function_t* >( function_address )(
                 base_address );
        }

        [[nodiscard]]
        void* ex_allocate_pool_with_tag(
            POOL_TYPE pool_type ,
            SIZE_T number_of_bytes ,
            ULONG tag
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ExAllocatePoolWithTag" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                POOL_TYPE pool_type ,
                SIZE_T number_of_bytes ,
                ULONG tag
                );

            return reinterpret_cast< function_t* >( function_address )(
                pool_type ,
                number_of_bytes ,
                tag );
        }

        [[ nodiscard ]]
        void ex_free_pool_with_tag(
            void* base_address ,
            ULONG tag
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ExFreePoolWithTag" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void (
                void* base_address ,
                ULONG tag
            );

            reinterpret_cast< function_t* >( function_address ) ( 
                base_address ,
                tag );
        }

        [[ nodiscard ]]
        nt_status_t mm_copy_virtual_memory(
            PEPROCESS source_process ,
            void* source_address ,
            PEPROCESS target_process ,
            void* target_address ,
            SIZE_T buffer_size ,
            KPROCESSOR_MODE previous_mode ,
            PSIZE_T return_size
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmCopyVirtualMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                PEPROCESS source_process ,
                void* source_address ,
                PEPROCESS target_process ,
                void* target_address ,
                SIZE_T buffer_size ,
                KPROCESSOR_MODE previous_mode ,
                PSIZE_T return_size
                );

            return reinterpret_cast< function_t* >( function_address ) ( source_process ,
                source_address , 
                target_process ,
                target_address ,
                buffer_size ,
                previous_mode ,
                return_size );
        }

        [[ nodiscard ]]
        nt_status_t mm_copy_memory(
            void* target_address ,
            MM_COPY_ADDRESS source_address ,
            SIZE_T number_of_bytes ,
            ULONG flags ,
            PSIZE_T number_of_bytes_transferred
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmCopyMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                void* target_address ,
                MM_COPY_ADDRESS source_address ,
                SIZE_T number_of_bytes ,
                ULONG falgs ,
                PSIZE_T number_of_bytes_transferred
            );

            return reinterpret_cast< function_t* >( function_address ) ( 
                target_address ,
                source_address ,
                number_of_bytes ,
                flags ,
                number_of_bytes_transferred );
        }

        [[ nodiscard ]]
        void* mm_map_io_space(
            std::uintptr_t physical_address ,
            SIZE_T number_of_bytes
        ) {
            PHYSICAL_ADDRESS phys_addr { physical_address };

            auto function_address = find_export<std::addr_t>( encrypt( "MmMapIoSpace" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = void* (
                PHYSICAL_ADDRESS physical_address ,
                SIZE_T number_of_bytes ,
                MEMORY_CACHING_TYPE cache_type
            );

            return reinterpret_cast< function_t* >( function_address ) (
                phys_addr ,
                number_of_bytes ,
                MmNonCached );
        }

        [[ nodiscard ]]
        void* map_io_space_ex(
            PHYSICAL_ADDRESS physical_address ,
            SIZE_T number_of_bytes ,
            ULONG protect
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmMapIoSpaceEx" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = void* (
                PHYSICAL_ADDRESS physical_address ,
                SIZE_T number_of_bytes ,
                ULONG protect
                );

            return reinterpret_cast< function_t* >( function_address ) (
                physical_address ,
                number_of_bytes ,
                protect );
        }

        [[ nodiscard ]]
        void mm_unmap_io_space(
            void* base_address ,
            SIZE_T number_of_bytes
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmUnmapIoSpace" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void (
                void* base_address ,
                SIZE_T number_of_bytes
                );

            reinterpret_cast< function_t* >( function_address ) (
                base_address ,
                number_of_bytes );
        } 

        [[ nodiscard ]]
        void rtl_init_unicode_string(
            PUNICODE_STRING destination_string ,
            PCWSTR source_string
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "RtlInitUnicodeString" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void* (
                PUNICODE_STRING destination_string ,
                PCWSTR source_string
                );

            reinterpret_cast< function_t* >( function_address ) (
                destination_string ,
                source_string );
        }

        [[nodiscard]]
        nt_status_t obf_dereference_object(
            void* Object
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ObfDereferenceObject" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                void* Object
            );

            return reinterpret_cast< function_t* >( function_address )( Object );
        }

        [[nodiscard]]
        std::uintptr_t get_physical_address(
            std::uintptr_t virtual_address
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmGetPhysicalAddress" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = PHYSICAL_ADDRESS(
                void* virtual_address
            );

            return reinterpret_cast< function_t* >( function_address )(
                reinterpret_cast< void* >( virtual_address ) 
                ).QuadPart;
        }

        [[nodiscard]]
        std::uintptr_t get_virtual_for_physical(
            std::uintptr_t physical_address
        ) {
            PHYSICAL_ADDRESS phys_addr{ };
            phys_addr.QuadPart = physical_address;

            auto function_address = find_export<std::addr_t>( encrypt( "MmGetVirtualForPhysical" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = void* (
                PHYSICAL_ADDRESS physical_address
                );

            return reinterpret_cast< std::uintptr_t >(
                reinterpret_cast< function_t* >( function_address )(
                    phys_addr
                    ) );
        }

        [[nodiscard]]
        nt_status_t zw_open_key(
            PHANDLE key_handle ,
            ACCESS_MASK desired_access ,
            POBJECT_ATTRIBUTES object_attributes
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwOpenKey" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                PHANDLE key_handle ,
                ACCESS_MASK desired_access ,
                POBJECT_ATTRIBUTES object_attributes
            );

            return reinterpret_cast< function_t* >( function_address )(
                key_handle ,
                desired_access ,
                object_attributes
                );
        }

        [[nodiscard]]
        nt_status_t zw_query_value_key(
            HANDLE key_handle ,
            PUNICODE_STRING value_name ,
            KEY_VALUE_INFORMATION_CLASS key_value_information_class ,
            void* key_value_information ,
            ULONG length ,
            PULONG result_length
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwQueryValueKey" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE key_handle ,
                PUNICODE_STRING value_name ,
                KEY_VALUE_INFORMATION_CLASS key_value_information_class ,
                void* key_value_information ,
                ULONG length ,
                PULONG result_length
            );

            return reinterpret_cast< function_t* >( function_address )(
                key_handle ,
                value_name ,
                key_value_information_class ,
                key_value_information ,
                length ,
                result_length );
        }

        [[nodiscard]]
        nt_status_t rtl_query_module_information(
            ULONG* InformationLength ,
            ULONG SizePerModule ,
            void* InformationBuffer
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "RtlQueryModuleInformation" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                ULONG* InformationLength ,
                ULONG SizePerModule ,
                void* InformationBuffer
            );

            return reinterpret_cast< function_t* >( function_address )(
                InformationLength ,
                SizePerModule ,
                InformationBuffer );
        }

        [[nodiscard]]
        nt_status_t zw_close(
            HANDLE handle
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwClose" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE handle
            );

            return reinterpret_cast< function_t* >( function_address )(
                handle
                );
        }

        [[ nodiscard ]]
        nt_status_t zw_terminate_thread(
            HANDLE ThreadHandle ,
            NTSTATUS ExitStatus
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwTerminateThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ThreadHandle ,
                NTSTATUS ExitStatus
            );

            return reinterpret_cast< function_t* >( function_address )(
                ThreadHandle ,
                ExitStatus
                );
        }

        [[nodiscard]]
        PEPROCESS ps_get_current_process( ) 
        {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetCurrentProcess" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = PEPROCESS( );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[ nodiscard ]]
        PEPROCESS io_get_current_process( )
        {
            auto function_address = find_export<std::addr_t>( encrypt( "IoGetCurrentProcess" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = PEPROCESS( );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[nodiscard]]
        HANDLE ps_get_current_thread_id( ) 
        {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetCurrentThreadId" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = HANDLE( );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[nodiscard]]
        BOOLEAN ke_are_interrupts_enabled( )
        {
            auto function_address = find_export<std::addr_t>( encrypt( "KeAreInterruptsEnabled" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = BOOLEAN( );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[nodiscard]]
        bool ps_get_thread_exit_status( ethread* thread )
        {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetThreadExitStatus" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                ethread*
            );

            return reinterpret_cast< function_t* >( function_address )( thread ) != nt_status_t::pending;
        }

        [[nodiscard]]
        PPHYSICAL_MEMORY_RANGE mm_get_physical_memory_ranges( ) 
        {
            auto function_address = find_export<std::addr_t>( encrypt( "MmGetPhysicalMemoryRanges" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = PPHYSICAL_MEMORY_RANGE( void );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[nodiscard]]
        nt_status_t zw_allocate_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            ULONG_PTR ZeroBits ,
            PSIZE_T RegionSize ,
            ULONG AllocationType ,
            ULONG Protect
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwAllocateVirtualMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ProcessHandle ,
                void** BaseAddress ,
                ULONG_PTR ZeroBits ,
                PSIZE_T RegionSize ,
                ULONG AllocationType ,
                ULONG Protect
            );

            return reinterpret_cast< function_t* >( function_address )(
                ProcessHandle ,
                BaseAddress ,
                ZeroBits ,
                RegionSize ,
                AllocationType ,
                Protect
                );
        }

        [[nodiscard]]
        nt_status_t zw_protect_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            PULONG NumberOfBytesToProtect ,
            ULONG NewAccessProtection ,
            PULONG OldAccessProtection
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwProtectVirtualMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ProcessHandle ,
                void** BaseAddress ,
                PULONG NumberOfBytesToProtect ,
                ULONG NewAccessProtection ,
                PULONG OldAccessProtection
            );

            return reinterpret_cast< function_t* >( function_address )(
                ProcessHandle ,
                BaseAddress ,
                NumberOfBytesToProtect ,
                NewAccessProtection ,
                OldAccessProtection
                );
        }

        [[nodiscard]]
        nt_status_t zw_free_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            PSIZE_T RegionSize ,
            ULONG FreeType
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwFreeVirtualMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ProcessHandle ,
                void** BaseAddress ,
                PSIZE_T RegionSize ,
                ULONG FreeType
            );

            return reinterpret_cast< function_t* >( function_address )(
                ProcessHandle ,
                BaseAddress ,
                RegionSize ,
                FreeType
                );
        }

        [[nodiscard]]
        nt_status_t zw_query_virtual_memory(
            HANDLE ProcessHandle ,
            void* BaseAddress ,
            MEMORY_INFORMATION_CLASS MemoryInformationClass ,
            void* MemoryInformation ,
            SIZE_T MemoryInformationLength ,
            PSIZE_T ReturnLength
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwQueryVirtualMemory" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ProcessHandle ,
                void* BaseAddress ,
                MEMORY_INFORMATION_CLASS MemoryInformationClass ,
                void* MemoryInformation ,
                SIZE_T MemoryInformationLength ,
                PSIZE_T ReturnLength
            );

            return reinterpret_cast< function_t* >( function_address )(
                ProcessHandle ,
                BaseAddress ,
                MemoryInformationClass ,
                MemoryInformation ,
                MemoryInformationLength ,
                ReturnLength
                );
        }

        [[nodiscard]]
        nt_status_t query_system_information(
            PVOID SystemInformation ,
            ULONG SystemInformationLength ,
            PULONG ReturnLength
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ZwQuerySystemInformation" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                ULONG SystemInformationClass ,
                PVOID SystemInformation ,
                ULONG SystemInformationLength ,
                PULONG ReturnLength
            );

            return reinterpret_cast< function_t* >( function_address )(
                11 ,
                SystemInformation ,
                SystemInformationLength ,
                ReturnLength
                );
        }

        [[nodiscard]]
        ULONG ke_query_active_processor_count(
            PKAFFINITY ActiveProcessors
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeQueryActiveProcessorCount" ) );
            if ( !function_address ) {
                return 0;
            }

            using function_t = ULONG(
                PKAFFINITY ActiveProcessors
            );

            return reinterpret_cast< function_t* >( function_address )( ActiveProcessors );
        }

        [[nodiscard]]
        void* ke_register_nmi_callback(
            PNMI_CALLBACK CallbackRoutine ,
            void* Context
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeRegisterNmiCallback" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                PNMI_CALLBACK CallbackRoutine ,
                void* Context
                );

            return reinterpret_cast< function_t* >( function_address )( CallbackRoutine , Context );
        }

        [[nodiscard]]
        void ke_initialize_affinity_ex(
            PKAFFINITY_EX affinity
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeInitializeAffinityEx" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void(
                PKAFFINITY_EX affinity
                );

            reinterpret_cast< function_t* >( function_address )( affinity );
        }

        [[nodiscard]]
        void ke_add_processor_affinity_ex(
            PKAFFINITY_EX affinity ,
            INT num
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeAddProcessorAffinityEx" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void(
                PKAFFINITY_EX affinity ,
                INT num
                );

            reinterpret_cast< function_t* >( function_address )( affinity , num );
        }

        [[nodiscard]]
        nt_status_t ke_delay_execution_thread(
            KPROCESSOR_MODE WaitMode ,
            BOOLEAN Alertable ,
            PLARGE_INTEGER Interval
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeDelayExecutionThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                KPROCESSOR_MODE WaitMode ,
                BOOLEAN Alertable ,
                PLARGE_INTEGER Interval
            );

            return reinterpret_cast< function_t* >( function_address )(
                WaitMode ,
                Alertable ,
                Interval
                );
        }

        [[nodiscard]]
        void hal_send_nmi(
            PKAFFINITY_EX affinity
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "HalSendNMI" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void(
                PKAFFINITY_EX affinity
                );

            reinterpret_cast< function_t* >( function_address )( affinity );
        }

        [[nodiscard]]
        nt_status_t ke_deregister_nmi_callback(
            void* Handle
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeDeregisterNmiCallback" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                void* Handle
            );

            return reinterpret_cast< function_t* >( function_address )( Handle );
        }

        [[nodiscard]]
        USHORT rtl_capture_stack_back_trace(
            ULONG FramesToSkip ,
            ULONG FramesToCapture ,
            void** BackTrace ,
            PULONG BackTraceHash
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "RtlCaptureStackBackTrace" ) );
            if ( !function_address ) {
                return 0;
            }

            using function_t = USHORT(
                ULONG FramesToSkip ,
                ULONG FramesToCapture ,
                void** BackTrace ,
                PULONG BackTraceHash
            );

            return reinterpret_cast< function_t* >( function_address )(
                FramesToSkip ,
                FramesToCapture ,
                BackTrace ,
                BackTraceHash
                );
        }

        [[nodiscard]]
        nt_status_t ps_create_system_thread(
            PHANDLE ThreadHandle ,
            ULONG DesiredAccess ,
            POBJECT_ATTRIBUTES ObjectAttributes ,
            HANDLE ProcessHandle ,
            PCLIENT_ID ClientId ,
            PKSTART_ROUTINE StartRoutine ,
            void* StartContext
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsCreateSystemThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                PHANDLE ThreadHandle ,
                ULONG DesiredAccess ,
                POBJECT_ATTRIBUTES ObjectAttributes ,
                HANDLE ProcessHandle ,
                PCLIENT_ID ClientId ,
                PKSTART_ROUTINE StartRoutine ,
                void* StartContext
            );

            return reinterpret_cast< function_t* >( function_address )(
                ThreadHandle ,
                DesiredAccess ,
                ObjectAttributes ,
                ProcessHandle ,
                ClientId ,
                StartRoutine ,
                StartContext
                );
        }

        [[nodiscard]]
        void* ps_get_process_section_base_address(
            PEPROCESS Process
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetProcessSectionBaseAddress" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                PEPROCESS Process
                );

            return reinterpret_cast< function_t* >( function_address )( Process );
        }

        [[nodiscard]]
        bool mm_is_address_valid(
            void* VirtualAddress
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmIsAddressValid" ) );
            if ( !function_address ) {
                return false;
            }

            using function_t = bool(
                void* VirtualAddress
                );

            return reinterpret_cast< function_t* >( function_address )( VirtualAddress );
        }

        [[nodiscard]]
        nt_status_t ps_terminate_system_thread(
            nt_status_t ExitStatus
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsTerminateSystemThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                nt_status_t ExitStatus
            );

            return reinterpret_cast< function_t* >( function_address )( ExitStatus );
        }

        [[nodiscard]]
        void* mm_allocate_contiguous_memory(
            SIZE_T NumberOfBytes 
        ) {
            PHYSICAL_ADDRESS HighestAcceptableAddress{ MAXULONG64 };

            auto function_address = find_export<std::addr_t>( encrypt( "MmAllocateContiguousMemory" ) );
            if ( !function_address ) {
                return nullptr;
            }

            using function_t = void* (
                SIZE_T NumberOfBytes ,
                PHYSICAL_ADDRESS HighestAcceptableAddress
                );

            return reinterpret_cast< function_t* >( function_address )(
                NumberOfBytes ,
                HighestAcceptableAddress
                );
        }

        [[nodiscard]]
        void* allocate_zero_contiguous_table( )
        {
            auto allocation_table_base = mm_allocate_contiguous_memory( 0x1000 );
            if ( !allocation_table_base ) {
                return nullptr;
            }

            std::memset( allocation_table_base , 0 , 0x1000 );

            return allocation_table_base;
        }

        [[nodiscard]]
        void mm_free_contiguous_memory(
            void* BaseAddress
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "MmFreeContiguousMemory" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void(
                void* BaseAddress
                );

            reinterpret_cast< function_t* >( function_address )( BaseAddress );
        }

        [[nodiscard]]
        bool ps_get_process_exit_status(
            std::uintptr_t Process
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetProcessExitStatus" ) );
            if ( !function_address ) {
                return false;
            }

            using function_t = nt_status_t(
                std::uintptr_t Process
                );

            return reinterpret_cast< function_t* >( function_address )( Process ) == nt_status_t::pending;
        }

        [[nodiscard]]
        ULONG ke_capture_persistent_thread_state(
            PCONTEXT Context ,
            ethread* Thread ,
            ULONG BugCheckCode ,
            ULONG BugCheckParameter1 ,
            ULONG BugCheckParameter2 ,
            ULONG BugCheckParameter3 ,
            ULONG BugCheckParameter4 ,
            void* VirtualAddress
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeCapturePersistentThreadState" ) );
            if ( !function_address ) {
                return 0;
            }

            using function_t = ULONG(
                PCONTEXT Context ,
                ethread* Thread ,
                ULONG BugCheckCode ,
                ULONG BugCheckParameter1 ,
                ULONG BugCheckParameter2 ,
                ULONG BugCheckParameter3 ,
                ULONG BugCheckParameter4 ,
                void* VirtualAddress
            );

            return reinterpret_cast< function_t* >( function_address )(
                Context ,
                Thread ,
                BugCheckCode ,
                BugCheckParameter1 ,
                BugCheckParameter2 ,
                BugCheckParameter3 ,
                BugCheckParameter4 ,
                VirtualAddress
                );
        }

        [[nodiscard]]
        nt_status_t ps_query_process_command_line(
            PEPROCESS Process ,
            WCHAR* Buffer ,
            ULONG NumberOfBytes ,
            INT Unknown ,
            ULONG* BytesCopied
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsQueryProcessCommandLine" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                PEPROCESS Process ,
                WCHAR* Buffer ,
                ULONG NumberOfBytes ,
                INT Unknown ,
                ULONG* BytesCopied
            );

            return reinterpret_cast< function_t* >( function_address )(
                Process ,
                Buffer ,
                NumberOfBytes ,
                Unknown ,
                BytesCopied
                );
        }

        [[nodiscard]]
        std::uintptr_t ps_initial_system_process( ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsInitialSystemProcess" ) );
            if ( !function_address ) {
                return {};
            }

            return *reinterpret_cast< std::uintptr_t* >( function_address );
        }

        [[nodiscard]]
        nt_status_t ps_lookup_thread_by_thread_id(
            std::uint32_t ThreadId ,
            ethread** Thread
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsLookupThreadByThreadId" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ThreadId ,
                ethread** Thread
            );

            return reinterpret_cast< function_t* >( function_address )(
                reinterpret_cast< HANDLE >( ThreadId ) ,
                Thread
                );
        }

        [[ nodiscard ]]
        std::uint32_t ps_get_process_id(
            std::uint64_t Process
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetProcessId" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = HANDLE(
                PEPROCESS Process
            );

            return reinterpret_cast< std::uint32_t >(
                reinterpret_cast< function_t* >( function_address )(
                    reinterpret_cast< PEPROCESS >( Process ) )
                );
        }

        [[nodiscard]]
        HANDLE ps_get_thread_id(
            PETHREAD Thread
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetThreadId" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = HANDLE(
                PETHREAD Thread
            );

            return reinterpret_cast< function_t* >( function_address )( Thread );
        }

        [[ nodiscard ]]
        ethread* ps_get_current_thread( )
        {
            auto function_address = find_export<std::addr_t>( encrypt( "PsGetCurrentThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = ethread * ( );

            return reinterpret_cast< function_t* >( function_address )( );
        }

        [[ nodiscard ]]
        nt_status_t get_kthread_from_handle(
            HANDLE thread_handle ,
            ethread** out_kthread
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ObReferenceObjectByHandle" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE Handle ,
                ACCESS_MASK DesiredAccess ,
                POBJECT_TYPE ObjectType ,
                KPROCESSOR_MODE AccessMode ,
                PVOID* Object ,
                POBJECT_HANDLE_INFORMATION HandleInformation
            );

            return reinterpret_cast< function_t* >( function_address )(
                thread_handle , 
                0x40 /*THREAD_QUERY_INFORMATION */ ,
                *PsThreadType ,
                KernelMode,
                reinterpret_cast<void**>( &out_kthread ) ,
                0 );
        }

        [[nodiscard]]
        BOOLEAN ps_is_system_thread(
            ethread* Thread
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "PsIsSystemThread" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = BOOLEAN(
                ethread* Thread
            );

            return reinterpret_cast< function_t* >( function_address )( Thread );
        }

        [[ nodiscard ]]
        nt_status_t ob_close_handle(
            HANDLE Handle ,
            KPROCESSOR_MODE PreviousMode
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ObCloseHandle" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE Handle ,
                KPROCESSOR_MODE PreviousMode
            );

            return reinterpret_cast< function_t* >( function_address )( Handle ,
                PreviousMode );
        }

        [[ nodiscard ]]
        nt_status_t ob_open_object_by_pointer(
            PVOID Object ,
            ULONG HandleAttributes ,
            PACCESS_STATE PassedAccessState ,
            ACCESS_MASK DesiredAccess ,
            POBJECT_TYPE ObjectType ,
            KPROCESSOR_MODE AccessMode ,
            PHANDLE Handle
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "ObOpenObjectByPointer" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                PVOID Object ,
                ULONG HandleAttributes ,
                PACCESS_STATE PassedAccessState ,
                ACCESS_MASK DesiredAccess ,
                POBJECT_TYPE ObjectType ,
                KPROCESSOR_MODE AccessMode ,
                PHANDLE Handle
            );

            return reinterpret_cast< function_t* >( function_address )( Object , 
                HandleAttributes , 
                PassedAccessState  , 
                DesiredAccess , 
                ObjectType ,
                AccessMode ,
                Handle );
        }

        [[ nodiscard ]]
        nt_status_t enable_instrumentation_callbacks(
            PEPROCESS process ,
            PVOID Callback
        ) {
            PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana = { 0 };
            nirvana.Callback = Callback;
            nirvana.Reserved = 0;
            nirvana.Version = 0;

            auto function_address = find_export<std::addr_t>( encrypt( "ZwSetInformationProcess" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = nt_status_t(
                HANDLE ProcessHandle ,
                PROCESSINFOCLASS ProcessInformationClass ,
                PVOID ProcessInformation ,
                ULONG ProcessInformationLength
            );

            HANDLE process_handle = nullptr;
            auto status = ob_open_object_by_pointer(
                process ,
                OBJ_KERNEL_HANDLE ,
                nullptr ,
                PROCESS_ALL_ACCESS ,
                *PsProcessType ,
                KernelMode ,
                &process_handle
            );
            if ( process_handle == nullptr || status != nt_status_t::success ) {
                return status;
            }

            status = reinterpret_cast< function_t* >( function_address )( 
                process_handle ,
                ProcessInstrumentationCallback ,
                &nirvana ,
                sizeof( nirvana )
                );

            ob_close_handle( process_handle , KernelMode );

            return status;
        }

        [[ nodiscard ]]
        std::int32_t nt_build_number( )
        {
            auto function_address = find_export<std::addr_t>( encrypt( "KeCapturePersistentThreadState" ) );
            if ( !function_address ) {
                return {};
            }

            while ( function_address[ 0x0 ] != 0x0f
                || function_address[ 0x1 ] != 0xb7
                || function_address[ 0x2 ] != 0x05 )
                function_address++;

            return *reinterpret_cast< std::int32_t* >
                ( &function_address[ 0x7 ] + *reinterpret_cast< std::int32_t* >( &function_address[ 0x3 ] ) ) & 0xffff;
        }

        [[ nodiscard ]]
        list_entry_t* ps_active_process_head( )
        {
            static auto function_address = find_export<std::addr_t>( encrypt( "KeCapturePersistentThreadState" ) );
            if ( !function_address ) {
                return { };
            }

            while ( function_address[ 0x0 ] != 0x20
                || function_address[ 0x1 ] != 0x48
                || function_address[ 0x2 ] != 0x8d )
                function_address++;

            return *reinterpret_cast< list_entry_t** >
                ( &function_address[ 0x8 ] + *reinterpret_cast< std::int32_t* >( &function_address[ 0x4 ] ) );
        }

        [[ nodiscard ]]
        ULONG rtl_random_ex(
            PULONG Seed
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "RtlRandomEx" ) );
            if ( !function_address ) {
                return 0;
            }

            using function_t = ULONG(
                PULONG Seed
                );

            reinterpret_cast< function_t* >( function_address )(
                Seed
                );
        }

        [[ nodiscard ]]
        unsigned int get_random( )
        {
            unsigned int low = *reinterpret_cast< unsigned int* >( oxorany( 0xFFFFF78000000000 ) );
            unsigned int mul = *reinterpret_cast< unsigned int* >( oxorany( 0xFFFFF78000000004 ) );
            std::uint64_t seed = ( ( std::uint64_t ) ( low ) * ( std::uint64_t ) ( mul ) ) >> oxorany( 24 );

            return exports::rtl_random_ex( ( unsigned long* ) &seed );
        }

        [[ nodiscard ]]
        void ke_initialize_dpc(
            PRKDPC Dpc ,
            PKDEFERRED_ROUTINE DeferredRoutine ,
            PVOID DeferredContext
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeInitializeDpc" ) );
            if ( !function_address ) {
                return;
            }

            using function_t = void(
                PRKDPC Dpc ,
                PKDEFERRED_ROUTINE DeferredRoutine ,
                PVOID DeferredContext
            );

            reinterpret_cast< function_t* >( function_address )( 
                Dpc , 
                DeferredRoutine , 
                DeferredContext 
            );
        }

        [[ nodiscard ]]
        bool ke_insert_queue_dpc(
            PRKDPC Dpc ,
            PVOID SystemArgument1 ,
            PVOID SystemArgument2
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "KeInsertQueueDpc" ) );
            if ( !function_address ) {
                return false;
            }

            using function_t = bool(
                PRKDPC Dpc ,
                PVOID SystemArgument1 ,
                PVOID SystemArgument2
           );

            return reinterpret_cast< function_t* >( function_address )(
                Dpc ,
                SystemArgument1 ,
                SystemArgument2 
            );
        }

        [[nodiscard]]
        unicode_string_t* ps_query_full_process_image_name( 
            std::uintptr_t process 
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "SeLocateProcessImageName" ) );
            if ( !function_address ) return { };

            while ( function_address[ 0x0 ] != 0xec
                || function_address[ 0x1 ] != 0x28
                || function_address[ 0x2 ] != 0xe8 )
                function_address++;

            auto ps_rva{ &function_address[ 0x7 ] + *reinterpret_cast< std::int32_t* >( &function_address[ 0x3 ] ) };
            if ( !ps_rva )
                return {};

            while ( ps_rva[ 0x0 ] != 0x0f
                || ps_rva[ 0x1 ] != 0x85
                || ps_rva[ 0x6 ] != 0x48 )
                ps_rva++;

            return *reinterpret_cast< unicode_string_t** >
                ( process + *reinterpret_cast< std::int32_t* >( &ps_rva[ 0x9 ] ) );
        }
	}
}