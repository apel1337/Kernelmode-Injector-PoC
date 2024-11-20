#include <core/linkers/page.h>

#define nmi_cb_pool 'BCmN'
#define nmi_context_pool '7331'
#define stack_frames_pool 'loop'
#define invalid_driver_list_head_pool 'rwar'
#define invalid_driver_list_entry_pool 'gaah'
#define system_modules_pool 'halb'
#define thread_data_pool 'doof'
#define proc_affinity_pool 'eeee'

namespace riot
{
	namespace nmi
	{
		namespace utils
		{
			bool is_instruction_in_invalid_region(
				std::uint64_t rip_instr ,
				PSYSTEM_MODULES system_modules );

			bool analyse_nmi_data(
				PNMI_CONTEXT nmi_context ,
				PSYSTEM_MODULES system_modules
			);
		}

		bool nmi_callback(
			void* context ,
			BOOLEAN handled 
		);

		bool register_nmi_callback(
			PNMI_CONTEXT nmi_context 
		);

		bool get_system_module_information(
			PSYSTEM_MODULES module_information 
		);

		bool spoof_nmi_data( );
		bool hide_driver( );
	}
}