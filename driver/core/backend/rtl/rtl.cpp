#include <core/backend/rtl/rtl.h>

namespace riot
{
	namespace std
	{
		[[ nodiscard ]] char chrlwr ( 
			char c 
		) {
			if ( c >= 'A' && c <= 'Z' ) return c - 'A' + 'a';
			return c;
		}

		[[ nodiscard ]] int stricmp ( 
			const char* cs , const char* ct 
		) {
			if ( cs && ct ) {
				while ( chrlwr ( *cs ) == chrlwr ( *ct ) ) {
					if ( *cs == 0 && *ct == 0 ) return 0;
					if ( *cs == 0 || *ct == 0 ) break;
					cs++;
					ct++;
				}
				return chrlwr ( *cs ) - chrlwr ( *ct );
			}
			return -1;
		}

		[[ nodiscard ]] int lower (
			int c 
		) {
			if ( c >= 'A' && c <= 'Z' )
				return c + 'a' - 'A';
			else
				return c;
		}

		[[ nodiscard ]] int wcscmp (
			const wchar_t* s1 , const wchar_t* s2
		) {
			while ( *s1 == *s2++ )
				if ( *s1++ == '\0' )
					return ( 0 );

			return ( *( const unsigned int* ) s1 - *( const unsigned int* )--s2 );
		}

		[[ nodiscard ]] char* lowerstr (
			char* Str 
		) {
			for ( CHAR* S = Str; *S; ++S )
			{
				*S = ( CHAR ) lower ( *S );
			}
			return Str;
		}

		[[ nodiscard ]] size_t strlen (
			const char* str 
		) {
			const char* s;
			for ( s = str; *s; ++s );
			return ( s - str );
		}

		[[ nodiscard ]] int strncmp (
			const char* s1 ,
			const char* s2 ,
			size_t n 
		) {
			if ( n == 0 )
				return ( 0 );
			do {
				if ( *s1 != *s2++ )
					return ( *( unsigned char* ) s1 - *( unsigned char* )--s2 );
				if ( *s1++ == 0 )
					break;
			} while ( --n != 0 );
			return ( 0 );
		}

		[[ nodiscard ]] int strcmp ( 
			const char* s1 , 
			const char* s2 
		) {
			while ( *s1 == *s2++ )
				if ( *s1++ == 0 )
					return ( 0 );
			return ( *( unsigned char* ) s1 - *( unsigned char* )--s2 );
		}

		[[ nodiscard ]] char* strstr (
			const char* s ,
			const char* find 
		) {
			char c , sc;
			size_t len;
			if ( ( c = *find++ ) != 0 )
			{
				len = strlen ( find );
				do
				{
					do
					{
						if ( ( sc = *s++ ) == 0 )
						{
							return ( NULL );
						}
					} while ( sc != c );
				} while ( strncmp ( s , find , len ) != 0 );
				s--;
			}
			return ( ( char* ) s );
		}

		[[ nodiscard ]] int memcmp ( 
			const void* s1 ,
			const void* s2 ,
			size_t n 
		) {
			const unsigned char* p1 = ( const unsigned char* ) s1;
			const unsigned char* end1 = p1 + n;
			const unsigned char* p2 = ( const unsigned char* ) s2;
			int                   d = 0;
			for ( ;;) {
				if ( d || p1 >= end1 ) break;
				d = ( int ) *p1++ - ( int ) *p2++;
				if ( d || p1 >= end1 ) break;
				d = ( int ) *p1++ - ( int ) *p2++;
				if ( d || p1 >= end1 ) break;
				d = ( int ) *p1++ - ( int ) *p2++;
				if ( d || p1 >= end1 ) break;
				d = ( int ) *p1++ - ( int ) *p2++;
			}
			return d;
		}

		[[ nodiscard ]] void* memcpy ( 
			void* dest ,
			const void* src , 
			size_t len 
		) {
			char* d = ( char* ) dest;
			const char* s = ( const char* ) src;
			while ( len-- )
				*d++ = *s++;
			return dest;
		}

		[[ nodiscard ]] void* memset (
			void* dest , 
			UINT8 c , 
			size_t count 
		) {
			size_t blockIdx;
			size_t blocks = count >> 3;
			size_t bytesLeft = count - ( blocks << 3 );
			UINT64 cUll =
				c
				| ( ( ( UINT64 ) c ) << 8 )
				| ( ( ( UINT64 ) c ) << 16 )
				| ( ( ( UINT64 ) c ) << 24 )
				| ( ( ( UINT64 ) c ) << 32 )
				| ( ( ( UINT64 ) c ) << 40 )
				| ( ( ( UINT64 ) c ) << 48 )
				| ( ( ( UINT64 ) c ) << 56 );

			UINT64* destPtr8 = ( UINT64* ) dest;
			for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr8 [ blockIdx ] = cUll;

			if ( !bytesLeft ) return dest;

			blocks = bytesLeft >> 2;
			bytesLeft = bytesLeft - ( blocks << 2 );

			UINT32* destPtr4 = ( UINT32* ) &destPtr8 [ blockIdx ];
			for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr4 [ blockIdx ] = ( UINT32 ) cUll;

			if ( !bytesLeft ) return dest;

			blocks = bytesLeft >> 1;
			bytesLeft = bytesLeft - ( blocks << 1 );

			UINT16* destPtr2 = ( UINT16* ) &destPtr4 [ blockIdx ];
			for ( blockIdx = 0; blockIdx < blocks; blockIdx++ ) destPtr2 [ blockIdx ] = ( UINT16 ) cUll;

			if ( !bytesLeft ) return dest;

			UINT8* destPtr1 = ( UINT8* ) &destPtr2 [ blockIdx ];
			for ( blockIdx = 0; blockIdx < bytesLeft; blockIdx++ ) destPtr1 [ blockIdx ] = ( UINT8 ) cUll;

			return dest;
		}
	}
}