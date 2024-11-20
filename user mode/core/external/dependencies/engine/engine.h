#include <core/driver/driver.hpp>
#include <core/external/dependencies/engine/structs.hpp>

using namespace riot::driver;

#define current_class reinterpret_cast<std::uintptr_t>( this )

#define declare_member(type, name, offset) type name() { return m_vm->read<type>( current_class + offset ); } 
#define declare_member_bit(bit, name, offset) bool name( ) { return bool( m_vm->read<char>( current_class + offset) & (1 << bit)); }

#define apply_member(type, name, offset) void name( type val ) { m_vm->write<type>( current_class + offset, val); }
#define apply_member_bit(bit, name, offset) void name( bool value ) { m_vm->write<char>( m_vm->read<char>( current_class + offset) | (1 << bit), value); }

namespace riot
{
	namespace engine
	{
		struct fname {
			std::uint32_t idx;
		};

		class u_object
		{
		public:
			declare_member( fname , name_private , 0x18 );
		};

		class u_actor_component : public u_object
		{
		public:
		};

		class u_mesh_component : public u_object
		{
		public:
		};

		class u_skinned_mesh_component : public u_mesh_component
		{
		public:
		};

		class u_skeletal_mesh_component : public u_skinned_mesh_component
		{
		public:
			declare_member( int , is_cached , 0x5B8 );
			declare_member( tarray<ftransform> , bone_space_transforms , 0x570 + ( this->is_cached( ) * 0x10 ) );
			declare_member( ftransform , component_to_world , 0x1c0 );
			declare_member( fbox_sphere_bounds , get_bounds , 0xE8 );

			fvector get_bone_location( std::uint32_t bone_index );
		};

		class a_actor : public u_object
		{
		public:
		};

		class a_pawn : public a_actor
		{
		public:
		};

		class a_character : public a_pawn
		{
		public:
			declare_member( u_skeletal_mesh_component* , mesh , 0x310 );
		};

		class afgf_character : public a_character
		{
		public:
		};

		class a_fort_pawn : public afgf_character
		{
		public:
		};

		class a_fort_player_pawn : public a_fort_pawn
		{
		public:
		};

		class a_controller : public a_actor
		{
		public:

		};

		class a_player_controller : public a_controller
		{
		public:
			declare_member( bool , is_local_controller , 0x6bc );

			apply_member( frotator , view_angles , 0x510 );
			apply_member( frotator , rotation_reset , 0x930 );
		};

		class a_fort_player_pawn_athena : public a_fort_player_pawn
		{
		public:
			declare_member( a_player_controller* , controller , 0x2c8 );
		};

		class a_fort_player_pawn_athena_t : public a_fort_player_pawn
		{
		public:
			declare_member(a_player_controller*, controller, 0x2c8);
		};

		class a_player_state : public u_object
		{
		public:
			declare_member( a_fort_player_pawn_athena* , pawn_private , 0x308 );
		};


		class a_fort_player_state : public a_player_state
		{
		public:
		};

		class a_fort_player_state_zone : public a_fort_player_state
		{
		public:
		};

		class a_fort_player_state_athena : public a_fort_player_state_zone
		{
		public:
		};

		class u_scene_view_state : public u_object
		{
		public:
			auto get_current_class( ) {
				return current_class;
			}
		};

		class u_localplayer : public u_object
		{
		public:
			declare_member( tarray<u_scene_view_state*> , view_state , 0xd0 );
		};

		class u_game_instance : public u_object
		{
		public:
			declare_member( tarray<u_localplayer*> , localplayers , 0x38 );

			auto get_localplayer( ) -> u_localplayer* {

				return localplayers( ).get( 0 );
			}
		};

		class a_game_state_base : public u_object
		{
		public:
			declare_member( float , server_world_time , 0x2c8 );
			declare_member( tarray<a_fort_player_state_athena*> , player_array , 0x2a8 );

			bool is_in_lobby( ) { return server_world_time( ) ? false : true; }
		};

		class u_world : public u_object
		{
		public:
			declare_member( a_game_state_base* , game_state , 0x160 );
			declare_member( u_game_instance* , game_instance , 0x1d8 );

			u_world* get_world( ) const;
		};
	}
}