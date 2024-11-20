#include <core/linkers/injector.h>

namespace riot
{
	namespace exception
	{
		[[ nodiscard ]] long exception_filter(
			PEXCEPTION_POINTERS p_exception_pointers
		);
	}
}