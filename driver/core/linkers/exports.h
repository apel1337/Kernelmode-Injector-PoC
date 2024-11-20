#pragma once
#include <core/backend/rtl/rtl.h>

namespace riot
{
    namespace exports
    {
        template< class type_t >
        [[ nodiscard ]]
        type_t find_export(
            const char* export_name
        );

        [[ nodiscard ]]
        void* ex_allocate_pool(
            POOL_TYPE pool_type ,
            SIZE_T number_of_bytes
        );

        [[ nodiscard ]]
        void* ex_allocate_pool2(
            POOL_FLAGS flags ,
            SIZE_T number_of_bytes ,
            ULONG tag
        );

        [[ nodiscard ]]
        void ex_free_pool(
            void* base_address 
        );

        [[ nodiscard ]]
        void* ex_allocate_pool_with_tag(
            POOL_TYPE pool_type ,
            SIZE_T number_of_bytes ,
            ULONG tag
        );

        [[ nodiscard ]]
        void ex_free_pool_with_tag(
            void* base_address ,
            ULONG tag
        );

        [[ nodiscard ]]
        nt_status_t mm_copy_virtual_memory(
            PEPROCESS source_process ,
            void* source_address ,
            PEPROCESS target_process ,
            void* target_address ,
            SIZE_T buffer_size ,
            KPROCESSOR_MODE previous_mode ,
            PSIZE_T return_size
        );

        [[ nodiscard ]]
        nt_status_t mm_copy_memory(
            void* target_address ,
            MM_COPY_ADDRESS source_address ,
            SIZE_T number_of_bytes ,
            ULONG flags ,
            PSIZE_T number_of_bytes_transferred
        );

        [[ nodiscard ]]
        void* mm_map_io_space(
            std::uintptr_t physical_address ,
            SIZE_T number_of_bytes 
        );

        [[ nodiscard ]]
        void* map_io_space_ex(
            PHYSICAL_ADDRESS physical_address ,
            SIZE_T number_of_bytes ,
            ULONG protect
        );

        [[ nodiscard ]]
        void mm_unmap_io_space(
            void* base_address ,
            SIZE_T number_of_bytes
        );

        [[ nodiscard ]]
        void rtl_init_unicode_string(
            PUNICODE_STRING destination_string ,
            PCWSTR source_string
        );

        [[ nodiscard ]]
        nt_status_t obf_dereference_object(
            void* object
        );

        [[ nodiscard ]]
        std::uintptr_t get_physical_address(
            std::uintptr_t virtual_address
        );

        [[ nodiscard ]]
        std::uintptr_t get_virtual_for_physical(
            std::uintptr_t physical_address );

        [[ nodiscard ]]
        nt_status_t zw_open_key(
            PHANDLE key_handle ,
            ACCESS_MASK descired_access ,
            POBJECT_ATTRIBUTES object_attributes
        );

        [[ nodiscard ]]
        nt_status_t zw_query_value_key(
            HANDLE key_handle ,
            PUNICODE_STRING value_name ,
            KEY_VALUE_INFORMATION_CLASS key_value_information_classs ,
            void* key_value_information ,
            ULONG length ,
            PULONG result_length
        );

        [[ nodiscard ]]
        nt_status_t rtl_query_module_information(
            ULONG* InformationLength ,
            ULONG SizePerModule ,
            void* InformationBuffer );

        [[ nodiscard ]]
        nt_status_t zw_close(
            HANDLE Handle
        );

        [[ nodiscard ]]
        nt_status_t zw_terminate_thread(
            HANDLE ThreadHandle ,
            NTSTATUS ExitStatus
        );

        [[ nodiscard ]]
        PEPROCESS ps_get_current_process( );
        
        [[ nodiscard ]]
        PEPROCESS io_get_current_process( );

        [[nodiscard]]
        HANDLE ps_get_current_thread_id( );

        [[nodiscard]]
        BOOLEAN ke_are_interrupts_enabled( );

        [[nodiscard]]
        bool ps_get_thread_exit_status( ethread* thread );

        [[ nodiscard ]]
        PPHYSICAL_MEMORY_RANGE mm_get_physical_memory_ranges( );

        [[ nodiscard ]]
        nt_status_t zw_allocate_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            ULONG_PTR ZeroBits ,
            PSIZE_T RegionSize ,
            ULONG AllocationType ,
            ULONG Protect
        );

        [[ nodiscard ]]
        nt_status_t zw_protect_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            PULONG NumberOfBytesToProtect ,
            ULONG NewAccessProtection ,
            PULONG OldAccessProtection
        );

        [[ nodiscard ]]
        nt_status_t zw_free_virtual_memory(
            HANDLE ProcessHandle ,
            void** BaseAddress ,
            PSIZE_T RegionSize ,
            ULONG FreeType
        );

        [[ nodiscard ]]
        nt_status_t zw_query_virtual_memory(
            HANDLE ProcessHandle ,
            void* BaseAddress ,
            MEMORY_INFORMATION_CLASS MemoryInformationClass ,
            void* MemoryInformation ,
            SIZE_T MemoryInformationLength ,
            PSIZE_T ReturnLength
        );

        [[ nodiscard ]]
        nt_status_t query_system_information(
            PVOID SystemInformation ,
            ULONG SystemInformationLength ,
            PULONG ReturnLength
        );

        [[ nodiscard ]]
        ULONG ke_query_active_processor_count(
            PKAFFINITY ActiveProcessors
        );

        [[ nodiscard ]]
        void* ke_register_nmi_callback(
            PNMI_CALLBACK CallbackRoutine ,
            void* Context
        );

        [[ nodiscard ]]
        void ke_initialize_affinity_ex(
            PKAFFINITY_EX affinity
        );

        [[ nodiscard ]]
        void ke_add_processor_affinity_ex(
            PKAFFINITY_EX affinity ,
            INT num
        );

        [[ nodiscard ]]
        nt_status_t ke_delay_execution_thread(
            KPROCESSOR_MODE WaitMode ,
            BOOLEAN Alertable ,
            PLARGE_INTEGER Interval
        );

        [[ nodiscard ]]
        void hal_send_nmi(
            PKAFFINITY_EX affinity
        );

        [[ nodiscard ]]
        nt_status_t ke_deregister_nmi_callback(
            void* Handle
        );

        [[ nodiscard ]]
        USHORT rtl_capture_stack_back_trace(
            ULONG FramesToSkip ,
            ULONG FramesToCapture ,
            void** BackTrace ,
            PULONG BackTraceHash
        );

        [[ nodiscard ]]
        nt_status_t ps_create_system_thread(
            PHANDLE ThreadHandle ,
            ULONG DesiredAccess ,
            POBJECT_ATTRIBUTES ObjectAttributes ,
            HANDLE ProcessHandle ,
            PCLIENT_ID ClientId ,
            PKSTART_ROUTINE StartRoutine ,
            void* StartContext
        );

        [[ nodiscard ]]
        void* ps_get_process_section_base_address(
            PEPROCESS Process
        );

        [[ nodiscard ]]
        bool mm_is_address_valid(
            void* VirtualAddress
        );

        [[ nodiscard ]]
        nt_status_t ps_terminate_system_thread(
            nt_status_t ExitStatus
        );

        [[ nodiscard ]]
        void* mm_allocate_contiguous_memory(
            SIZE_T NumberOfBytes 
        );

        [[ nodiscard ]]
        void* allocate_zero_contiguous_table( );

        [[ nodiscard ]]
        void mm_free_contiguous_memory(
            void* BaseAddress
        );

        [[ nodiscard ]]
        bool ps_get_process_exit_status(
            std::uintptr_t Process
        );

        [[ nodiscard ]]
        ULONG ke_capture_persistent_thread_state(
            PCONTEXT Context ,
            ethread* Thread ,
            ULONG BugCheckCode ,
            ULONG BugCheckParameter1 ,
            ULONG BugCheckParameter2 ,
            ULONG BugCheckParameter3 ,
            ULONG BugCheckParameter4 ,
            void* VirtualAddress );

        [[ nodiscard ]]
        nt_status_t ps_query_process_command_line(
            PEPROCESS Process ,
            WCHAR* Buffer ,
            ULONG NumberOfBytes ,
            INT Unknown ,
            ULONG* BytesCopied );

        [[ nodiscard ]]
        std::uintptr_t ps_initial_system_process( );

        [[ nodiscard ]]
        unicode_string_t* ps_query_full_process_image_name(
            std::uintptr_t process 
        );

        [[ nodiscard ]]
        nt_status_t ps_lookup_thread_by_thread_id(
            std::uint32_t ThreadId ,
            ethread** Thread
        );

        [[ nodiscard ]]
        std::uint32_t ps_get_process_id(
            std::uint64_t Process
        );

        [[ nodiscard ]]
        HANDLE ps_get_thread_id(
            PETHREAD Thread 
        );

        [[ nodiscard ]]
        ethread* ps_get_current_thread( );

        [[ nodiscard ]]
        nt_status_t get_kthread_from_handle(
            HANDLE thread_handle , 
            ethread** out_kthread
        );

        [[ nodiscard ]]
        BOOLEAN ps_is_system_thread(
            ethread* Thread
        );

        [[ nodiscard ]]
        nt_status_t ob_close_handle(
            HANDLE Handle ,
            KPROCESSOR_MODE PreviousMode
        );

        [[ nodiscard ]]
        nt_status_t ob_open_object_by_pointer(
            PVOID Object ,
            ULONG HandleAttributes ,
            PACCESS_STATE PassedAccessState ,
            ACCESS_MASK DesiredAccess ,
            POBJECT_TYPE ObjectType ,
            KPROCESSOR_MODE AccessMode ,
            PHANDLE Handle
        );

        [[ nodiscard ]]
        nt_status_t enable_instrumentation_callbacks(
            PEPROCESS process ,
            PVOID Callback
        );

        [[ nodiscard ]]
        std::int32_t nt_build_number( );

        [[ nodiscard ]]
        list_entry_t* ps_active_process_head( );

        [[ nodiscard ]]
        ULONG rtl_random_ex(
            PULONG Seed
        );

        [[ nodiscard ]]
        unsigned int get_random( );

        [[ nodiscard ]]
        void ke_initialize_dpc(
            PRKDPC Dpc,
            PKDEFERRED_ROUTINE DeferredRoutine ,
            PVOID DeferredContext
        );

        [[ nodiscard ]]
        bool ke_insert_queue_dpc(
            PRKDPC Dpc ,
            PVOID SystemArgument1 ,
            PVOID SystemArgument2
        );

        template< class... args_t >
        [[ nodiscard ]]
        std::int8_t dbg_print(
            const char* format ,
            args_t... va_args
        ) {
            auto function_address = find_export<std::addr_t>( encrypt( "DbgPrintEx" ) );
            if ( !function_address ) {
                return {};
            }

            using function_t = std::int32_t(
                std::uint32_t flag ,
                std::uint32_t level ,
                const char* format ,
                args_t... va_args
            );

            return reinterpret_cast< function_t* >( function_address )( 0 , 0 , format , va_args... ) == nt_status_t::success;
        }
    }
}