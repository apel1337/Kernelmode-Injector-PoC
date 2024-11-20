#include <core/linkers/stdafx.h>

#define max_messages 512
#define max_message_size 256

namespace riot
{
	namespace server
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

		enum request_type : unsigned char
		{
			read_virtual ,
			write_virtual ,
			read_physical ,
			write_physical ,
			allocate_virtual ,
			protect_virtual ,
			free_virtual ,
			free_physical ,
			swap_virtual ,
			query_virtual ,
			translate_linear ,
			get_virtual ,
			get_physical ,
			get_eprocess ,
			get_memory_base ,
			get_base_address ,
			get_free_2mb_memory_base ,
			get_free_1gb_memory_base ,
			get_directory_table_base ,
			create_instrum_callback ,
			unload
		};

		struct log_entry_t {
			bool present;
			char payload[ max_message_size ];
		};

		typedef struct _request_data
		{
			bool is_client_running;
			bool is_operation_completed;

			request_type operation_type;
			nt_status_t operation_status;

			int target_pid;
			uintptr_t address;
			uintptr_t address2;

			PVOID buffer;
			uintptr_t size;
			unsigned int flags;
			unsigned int protection;

			uintptr_t dirbase;
			MEMORY_BASIC_INFORMATION mbi;
		} request_data , * prequest_data;
	}
}