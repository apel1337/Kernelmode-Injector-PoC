#include <core/linkers/kthread.h>

namespace riot
{
	namespace flush
	{
		[[ nodiscard ]] void cleaup_dpc_routine(
			PKDPC dpc ,
			PVOID deferred_context ,
			PVOID system_argument1 ,
			PVOID system_argument2
		);

		[[ nodiscard ]] void flush_traces( );
	}
}