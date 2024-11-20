#pragma once
#include <core/linkers/stdafx.h>

namespace riot
{
	namespace std
	{
		[[ nodiscard ]] char chrlwr (
			char c );

		[[ nodiscard ]] int stricmp (
			const char* cs ,
			const char* ct );

		[[ nodiscard ]] int lower (
			int c );

		[[ nodiscard ]] int wcscmp (
			const wchar_t* s1 , 
			const wchar_t* s2 );

		[[ nodiscard ]] char* lowerstr (
			char* Str );

		[[ nodiscard ]] size_t strlen (
			const char* str );

		[[ nodiscard ]] int strncmp (
			const char* s1 , 
			const char* s2 ,
			size_t n );

		[[ nodiscard ]] int strcmp (
			const char* s1 ,
			const char* s2 );

		[[ nodiscard ]] char* strstr (
			const char* s ,
			const char* find );

		[[ nodiscard ]] int memcmp (
			const void* s1 ,
			const void* s2 ,
			size_t n );

		[[ nodiscard ]] void* memcpy (
			void* dest ,
			const void* src ,
			size_t len );

		[[ nodiscard ]] void* memset (
			void* dest ,
			UINT8 c ,
			size_t count );
	}
}