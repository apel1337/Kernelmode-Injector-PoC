#include <core/linkers/logs.h>

namespace riot
{
	namespace logs
	{
		[[ nodiscard ]] void move_tail_ahead( )
		{
			if ( ( m_head_index + 1 ) % max_messages == m_tail_index ) {
				m_tail_index = ( m_tail_index + 1 ) % max_messages;
			}
		}

		[[ nodiscard ]] void move_head_ahead( )
		{
			m_head_index = ( m_head_index + 1 ) % max_messages;
		}

		[[ nodiscard ]] bool copy_str(
			char* const buffer ,
			char const* const source ,
			std::uint32_t& index 
		) {
			for ( std::uint32_t i = 0; source[ i ]; ++i ) {
				buffer[ index++ ] = source[ i ];

				if ( index >= max_message_size - 1 ) {
					buffer[ max_message_size ] = '\0';
					return true;
				}
			}

			return false;
		}

		[[ nodiscard ]] void format(
			char* const buffer ,
			char const* const format ,
			va_list& args
		) {
			std::uint32_t buffer_index = 0;
			std::uint32_t format_index = 0;

			bool last_character_was_pecentage = false;

			while ( true ) {
				auto const current_character = format[ format_index++ ];
				if ( current_character == '\0' ) {
					break;
				}

				if ( current_character == '%' ) {
					last_character_was_pecentage = true;
					continue;
				}

				if ( !last_character_was_pecentage ) {
					buffer[ buffer_index++ ] = current_character;

					if ( buffer_index >= max_message_size - 1 )
						break;

					last_character_was_pecentage = false;
					continue;
				}

				char format_buffer[ 128 ] {};

				if ( current_character == 'l' && format[ format_index ] == 'l' ) 
				{
					format_index++;

					switch ( format[ format_index++ ] ) 
					{
					case 'x': {
						if ( copy_str( buffer , "0x" , buffer_index ) ) {
							return;
						}

						if ( copy_str( buffer ,
							lukas_itoa( va_arg( args , std::uint64_t ) , format_buffer , 16 ) ,
							buffer_index ) ) {
							return;
						}
						break;
					}
					}
				}

				switch ( current_character )
				{
				case 's': {
					if ( copy_str(
						buffer ,
						va_arg( args , char const* ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				case 'd':
				case 'i': {
					if ( copy_str(
						buffer ,
						lukas_itoa( va_arg( args , int ) ,  format_buffer , 10 ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				case 'u': {
					if ( copy_str( buffer ,
						lukas_itoa( va_arg( args , unsigned int ) , format_buffer , 10 ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				case 'x': {
					if ( copy_str(
						buffer ,
						"0x" ,
						buffer_index
					) ) {
						return;
					}

					if ( copy_str( buffer ,
						lukas_itoa( va_arg( args , unsigned int ) , format_buffer , 16 ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				case 'X': {
					if ( copy_str(
						buffer ,
						"0x" ,
						buffer_index
					) ) {
						return;
					}

					if ( copy_str( buffer ,
						lukas_itoa( va_arg( args , unsigned int ) , format_buffer , 16 , true ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				case 'p': {
					if ( copy_str(
						buffer ,
						"0x" ,
						buffer_index
					) ) {
						return;
					}

					if ( copy_str( buffer ,
						lukas_itoa( va_arg( args , std::uint64_t ) , format_buffer , 16 , true ) ,
						buffer_index
					) ) {
						return;
					}

					break;
				}
				}

				last_character_was_pecentage = false;
			}

			buffer[ buffer_index ] = '\0';
		}

		template <class type>
		[[ nodiscard ]] char* lukas_itoa(
			type value ,
			char* result ,
			int base ,
			bool upper
		) {
			if ( base < 2 || base > 36 ) {
				*result = '\0';
				return result;
			}

			char* ptr = result , * ptr1 = result , tmp_char;
			type tmp_value;

			if ( upper )
			{
				do
				{
					tmp_value = value;
					value /= base;
					*ptr++ = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						[ 35 + ( tmp_value - value * base ) ];
				} while ( value );
			}
			else
			{
				do
				{
					tmp_value = value;
					value /= base;
					*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"
						[ 35 + ( tmp_value - value * base ) ];
				} while ( value );
			}

			// Apply negative sign
			if ( tmp_value < 0 )
				*ptr++ = '-';

			*ptr-- = '\0';
			while ( ptr1 < ptr )
			{
				tmp_char = *ptr;
				*ptr-- = *ptr1;
				*ptr1++ = tmp_char;
			}

			return result;
		}
	}
}