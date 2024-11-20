
namespace riot
{
	namespace mapping
	{
		struct physical_mapping
		{
			std::uintptr_t virtual_base;
			std::size_t mapped_size;
			std::size_t usable_size;
			bool is_1gb_mapping;

			physical_mapping( std::uintptr_t base , std::size_t mapped , std::size_t usable )
				: virtual_base( base )
				, mapped_size( mapped )
				, usable_size( usable )
				, is_1gb_mapping( mapped == 0x40000000 )
			{ }
		};
	}
}