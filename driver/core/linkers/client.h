#include <core/linkers/logs.h>

namespace riot
{
	namespace client
	{
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

		typedef struct _request_data
		{
			bool is_client_running;
			bool is_operation_completed;

			request_type operation_type;
			nt_status_t operation_status;

			int target_pid;
			uintptr_t address;
			uintptr_t address2;

			void* buffer;
			uintptr_t size;
			unsigned int flags;
			unsigned int protection;

			uintptr_t dirbase;
			memory_basic_information mbi;
		} request_data , * prequest_data;

		class c_interface
		{
		public:
			bool setup( );
			void cleanup( );
			void flush_logs( );

			bool send( prequest_data request );
			bool get( prequest_data request );

			template <typename type>
			bool get_value( const wchar_t* value_name , type& result_value );
			void log_print( const char* format , ... );

			PEPROCESS get_client_process( );

			void set_key_path( 
				const wchar_t* key_path 
			) {
				this->key_path = key_path; 
			}

			c_interface* operator->( ) 
			{
				return this;
			}

		private:
			cr3 process_cr3{ };
			PEPROCESS client_process{ };

			unsigned int client_id = 0;
			void* log_buffer = nullptr;
			void* target_buffer = nullptr;

			const wchar_t* key_path;

		};

		inline client::c_interface m_client { };
	}
}