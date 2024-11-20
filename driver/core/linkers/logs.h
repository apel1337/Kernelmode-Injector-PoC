#include <core/linkers/proc.h>

#define max_messages 512
#define max_message_size 256

namespace riot
{
	namespace logs
	{
		struct log_entry_t {
			bool present;
			char payload[ max_message_size ];
		};

		inline log_entry_t m_log_entries[ max_messages ] { 0 };

		inline std::uint32_t m_head_index = 0;
		inline std::uint32_t m_tail_index = 0;

		[[ nodiscard ]] void move_tail_ahead( );
		[[ nodiscard ]] void move_head_ahead( );

		[[ nodiscard ]] bool copy_str(
			char* const buffer ,
			char const* const source ,
			std::uint32_t& index
		);

		[[ nodiscard ]] void format( 
			char* const buffer , 
			char const* const format , 
			va_list& args 
		);

		template <class type>
		[[ nodiscard ]] char* lukas_itoa(
			type value ,
			char* result ,
			int base ,
			bool upper = false 
		);
	}
}