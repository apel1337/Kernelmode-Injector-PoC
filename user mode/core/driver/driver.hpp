#include <core/driver/server.h>
#include <core/driver/phys/map.hpp>

namespace riot
{
	namespace driver
	{
		class c_interface
		{
		public:
			c_interface( const char* key_path )
				: key_path( key_path ) { }
			~c_interface( ) { }

			std::mutex mutex{ };
			std::condition_variable condition{ };

		public:
			bool setup( );
			void flush_logs( );
			void unload_driver( );

			template <typename type>
			bool create_value( const char* value_name , type request );
			void send_cmd( server::request_data& request );

			bool read_virtual( uintptr_t address , void* buffer , size_t size );
			bool write_virtual( uintptr_t address , void* buffer , size_t size );
			bool read_physical_km( uintptr_t address , void* buffer , size_t size );
			bool write_physical_km( uintptr_t address , void* buffer , size_t size );

			std::uintptr_t translate_linear( uintptr_t virtual_address );
			bool read_physical( const uintptr_t address , void* buffer , const std::uintptr_t size );
			bool write_physical( const uintptr_t address , void* buffer , const std::uintptr_t size );

			std::pair<std::uintptr_t , nt_status_t> allocate_virtual( size_t size , int flags , int protection );
			std::pair<std::uintptr_t , nt_status_t> protect_virtual( uintptr_t address , size_t size , int protection );
			void free_virtual( uintptr_t address , int flags );
			void free_physical( uintptr_t address , size_t size );
			void swap_virtual( uintptr_t source , uintptr_t destination );
			MEMORY_BASIC_INFORMATION query_virtual( uintptr_t address );

			const std::uintptr_t physical_for_virtual( uintptr_t physical_address );
			const std::uintptr_t virtual_for_physical( uintptr_t virtual_address );

			const std::uintptr_t get_kernel_export( const char* image_name , const char* module_name );
			const std::uintptr_t get_kernel_image( const char* module_name );

			const std::uintptr_t get_eprocess( std::uint32_t process_id );
			const std::uintptr_t get_base_address( const std::uintptr_t e_process );
			const std::uintptr_t get_text_section( uintptr_t module_base );
			bool get_process_pid( std::wstring module_name , std::uint32_t* process_id );
			void set_process_pid( std::uint32_t process_id );
			std::uint32_t get_process_pid( );

			void resolve_directory_table_base( uintptr_t module_base );
			const std::uintptr_t get_directory_table_base( uintptr_t module_base );
			const std::uintptr_t get_directory_table_base( );
			const std::uintptr_t get_free_2mb_memory_base( );
			const std::uintptr_t get_free_1gb_memory_base( );

			void cleanup_partial_allocation( const std::vector<std::uintptr_t>& allocated_pages );
			const std::pair<std::uintptr_t , nt_status_t> allocate_2mb_fallback( std::size_t aligned_size );
			const std::pair<std::uintptr_t , nt_status_t> create_allocation( std::size_t allocation_size );
			const mapping::physical_mapping* find_mapping( std::uintptr_t virtual_address );
			const std::size_t& get_remaining_space( std::uintptr_t base_address );
			bool is_address_in_usable_range( std::uintptr_t address );
			nt_status_t cleanup_allocation( std::uintptr_t virtual_base );
			void cleanup_all_allocations( );

			PSYSTEM_BIGPOOL_INFORMATION query_bigpools( );
			const std::uintptr_t get_guarded_region( );
			void set_guarded_region( uintptr_t guarded_region );

			const nt_status_t create_instrumentation_callback( uintptr_t callback );

			std::uintptr_t find_min( std::uint32_t g , std::size_t f ) 
			{
				std::uint32_t h = ( std::uint32_t ) f;

				return ( ( ( g ) < ( h ) ) ? ( g ) : ( h ) );
			}

			template <typename type>
			type read( uintptr_t address )
			{
				type return_value{ };
				read_virtual( address , &return_value , sizeof( type ) );
				return return_value;
			}

			template <typename type>
			type read_physical( uintptr_t address )
			{
				type return_value{ };
				read_physical( address , &return_value , sizeof( return_value ) );
				return return_value;
			}

			template <typename type>
			type read_kernel_memory( uintptr_t address )
			{
				type return_value{ };
				read_physical_km( address , &return_value , sizeof( return_value ) );
				return return_value;
			}

			template <typename type>
			bool write( uintptr_t address , type value )
			{
				return write_virtual( address , &value , sizeof( value ) );
			}

			template <typename type>
			bool write_physical( uintptr_t address , type value )
			{
				return write_physical( address , &value , sizeof( value ) );
			}

			template <typename type>
			bool is_guarded( type pointer )
			{
				constexpr auto filter = 0xFFFFFFFF00000000;
				auto result = pointer & filter;
				return result == 0x8000000000 || result == 0x10000000000;
			}

			template <typename type>
			bool is_guarded_tm( type pointer )
			{
				constexpr auto filter = 0xFFFFFFFF00000000ULL;
				auto address_as_int = reinterpret_cast< uintptr_t >( pointer );
				auto result = address_as_int & filter;
				return result == 0x8000000000 || result == 0x10000000000;
			}

			template <typename type>
			type validate_pointer( type address )
			{
				if ( is_guarded( address ) )
					return guarded_region + ( address & 0xFFFFFF );
				return address;
			}

			template <typename type>
			type validate_guarded( type address )
			{
				if ( is_guarded_tm( address ) )
					return reinterpret_cast< type >( guarded_region + ( reinterpret_cast< uintptr_t >( address ) & 0xFFFFFF ) );
				return address;
			}

			c_interface* get( )
			{
				return this;
			}

		private:
			void* log_buffer;
			void* memory_buffer;
			const char* key_path;

			int target_pid;

			uintptr_t guarded_region;
			std::atomic<uintptr_t> dirbase { };

			std::vector< mapping::physical_mapping > m_physical_mappings;
		};

		inline uintptr_t module_handle;
		inline c_interface* m_vm;
	}
}