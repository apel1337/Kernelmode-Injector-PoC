#include <core/external/dependencies/engine/engine.h>

namespace riot
{
	namespace engine
	{
		fvector u_skeletal_mesh_component::get_bone_location( std::uint32_t bone_index ) {
			auto bone_space_transforms = this->bone_space_transforms( );
			if ( !bone_space_transforms.is_valid( ) ) {
				printf( "failed to cache space transforms\n" );
				return { };
			}

			auto bone_space_transform = bone_space_transforms.get( bone_index );

			auto matrix = bone_space_transform.to_matrix( ).to_multiplication(
				this->component_to_world( ).to_matrix( )
			);

			return fvector( matrix.w_plane.x , matrix.w_plane.y , matrix.w_plane.z );
		}

		u_world* u_world::get_world( ) const {
			return m_vm->read<u_world*>( module_handle + 0x12300468 );
		}
	}
}