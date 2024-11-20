#include <core/external/features/visuals/visuals.h>
auto timer_stop = std::chrono::high_resolution_clock::now( );

namespace riot
{
	namespace entity
	{
		c_interface::c_interface(  ) {
			render_queue = [ & ] ( ) {
				update_matrix( );

				for ( const auto& it : this->m_list ) {
					this->render( it );
				}
				};
		}

		void c_interface::tick( )
		{
			for ( ;; ) {
				constexpr auto update_time = 25;

				auto timer_start = std::chrono::high_resolution_clock::now( );
				auto count = std::chrono::duration_cast< std::chrono::milliseconds >(
					timer_start - timer_stop
				).count( );

				if ( count > update_time )
				{
					std::unique_lock<std::mutex> lock( this->m_mutex );
					{
						this->get_world( );
						this->cache_actors( );
					}

					lock.unlock( );
					timer_stop = std::move( timer_start );
				}
				else {
					std::this_thread::sleep_for(
						std::chrono::milliseconds(
							update_time - count
						) );
				}
			}
		}

		void c_interface::update_matrix( )
		{
			auto projection = m_vm->read<engine::c_matrix>( std::uintptr_t( this->m_view_state ) + 0x900 );

			this->m_rotation.pitch = math::to_deg( std::asin( projection.z_plane.w ) );
			this->m_rotation.yaw = math::to_deg( std::atan2( projection.y_plane.w , projection.x_plane.w ) );
			this->m_rotation.roll = 0.0;

			this->m_location.x = projection.m[ 3 ][ 0 ];
			this->m_location.y = projection.m[ 3 ][ 1 ];
			this->m_location.z = projection.m[ 3 ][ 2 ];

			auto fov = atanf( 1 / m_vm->read<double>( std::uintptr_t( this->m_view_state ) + 0x700 ) ) * 2;
			this->m_field_of_view = math::to_deg( fov );
		}

		bool c_interface::world_to_screen( engine::fvector& world_location , engine::fvector2d* screen_position )
		{
			auto matrix = engine::c_matrix().to_rotation_matrix( this->m_rotation );

			auto axis_x = engine::fvector( matrix.x_plane.x , matrix.x_plane.y , matrix.x_plane.z );
			auto axis_y = engine::fvector( matrix.y_plane.x , matrix.y_plane.y , matrix.y_plane.z );
			auto axis_z = engine::fvector( matrix.z_plane.x , matrix.z_plane.y , matrix.z_plane.z );

			auto delta = (
				world_location - this->m_location
				);

			auto transform = engine::fvector(
				delta.vector_scalar( axis_y ) ,
				delta.vector_scalar( axis_z ) ,
				delta.vector_scalar( axis_x )
			);

			transform.z = ( transform.z < 1.f ) ? 1.f : transform.z;

			auto fov_radians = this->m_field_of_view * std::numbers::pi / 360.f;
			*screen_position = engine::fvector2d(
				overlay->m_width_center + transform.x * ( overlay->m_width_center / tan( fov_radians ) ) / transform.z ,
				overlay->m_height_center - transform.y * ( overlay->m_width_center / tan( fov_radians ) ) / transform.z 
			);

			return world_location && *screen_position;
		}

		bool c_interface::is_visible()
		{
			
		}



		void c_interface::get_world ( )
		{
			m_world = engine::u_world( ).get_world( );
			if ( !m_world ) return;

			m_game_state = m_world->game_state( );
			if ( !m_game_state ) return;

			m_owning_game_instance = m_world->game_instance( );
			if ( !m_owning_game_instance ) return;

			m_local_player = m_owning_game_instance->get_localplayer( );
			if ( !m_local_player ) return;

			m_view_state = m_local_player->view_state( ).get( 1 );
			if ( !m_view_state ) return;
		}

		void c_interface::cache_actors( )
		{
			const auto actor_array = m_game_state->player_array( ).get_itter( );

			for ( auto index = 0ul; index < actor_array.size( ); ++index ) {
				auto player_state = actor_array[ index ];
				if ( !player_state ) continue;

				auto actor = player_state->pawn_private( );
				if ( !actor ) continue;

				const auto is_same = [ & ] ( const c_list& list )
					{
						return actor == list.m_actor;
					};

				const auto it = std::find_if( m_actor_list.begin( ) , m_actor_list.end( ) , is_same );
				if ( it == m_actor_list.end( ) ) {
					m_actor_list.emplace_back( c_list{ index, actor, player_state } );
				}
			}

			this->m_list.swap( m_actor_list );
			if ( !this->m_actor_list.empty( ) )
				this->m_actor_list.clear( );
		}

		void c_interface::render( c_list const entity )
		{
			const auto player = static_cast< c_list const >( entity );
			if ( player.m_actor->controller( )->is_local_controller( ) )
			{
				printf( "is local controller\n" );
			}
			if ( !player.m_actor ) return;

			if ( !player.m_visible ) return maybe;

			auto mesh = player.m_actor->mesh( );
			if ( !mesh ) return;

			auto head_location = mesh->get_bone_location( 110 );
			if ( !head_location ) return;

			auto root_location = mesh->get_bone_location( 0 );
			if ( !root_location ) return;

			auto distance = m_location.distance_to( root_location ) / 100.f;

			auto head_position = engine::fvector2d( );
			if ( !this->world_to_screen( head_location , &head_position ) ) return;

			auto root_position = engine::fvector2d( );
			if ( !this->world_to_screen( root_location , &root_position ) ) return;

			auto bounds = mesh->get_bounds( );

			auto min_location = bounds.orgin - bounds.box_extent; // bottom
			auto max_location = bounds.orgin + bounds.box_extent; // top

			auto bounds_min_screen = engine::fvector2d( ); 
			if ( !this->world_to_screen( min_location , &bounds_min_screen ) ) return;

			auto bounds_max_screen = engine::fvector2d( );
			if ( !this->world_to_screen( max_location , &bounds_max_screen ) ) return;

			auto bounds_orgin = engine::fvector2d( );
			if ( !this->world_to_screen( bounds.orgin , &bounds_orgin ) ) return;

			bounds.box_extent *= 1.8f;

			bounds.orgin.x -= bounds.box_extent.x / 2.0;
			bounds.orgin.y -= bounds.box_extent.y / 2.0;
			bounds.orgin.z -= bounds.box_extent.z / 2.0;

			engine::fvector one = bounds.orgin;
			engine::fvector two = bounds.orgin; two.x += bounds.box_extent.x;
			engine::fvector three = bounds.orgin; three.x += bounds.box_extent.x; three.y += bounds.box_extent.y;
			engine::fvector four = bounds.orgin; four.y += bounds.box_extent.y;

			engine::fvector five = one; five.z += bounds.box_extent.z;
			engine::fvector six = two; six.z += bounds.box_extent.z;
			engine::fvector seven = three; seven.z += bounds.box_extent.z;
			engine::fvector eight = four; eight.z += bounds.box_extent.z;

			auto s1 = engine::fvector2d( );
			if ( !this->world_to_screen( one , &s1 ) ) return;

			auto s2 = engine::fvector2d( );
			if ( !this->world_to_screen( two , &s2 ) ) return;

			auto s3 = engine::fvector2d( );
			if ( !this->world_to_screen( three , &s3 ) ) return;

			auto s4 = engine::fvector2d( );
			if ( !this->world_to_screen( four , &s4 ) ) return;

			auto s5 = engine::fvector2d( );
			if ( !this->world_to_screen( five , &s5 ) ) return;

			auto s6 = engine::fvector2d( );
			if ( !this->world_to_screen( six , &s6 ) ) return;

			auto s7 = engine::fvector2d( );
			if ( !this->world_to_screen( seven , &s7 ) ) return;

			auto s8 = engine::fvector2d( );
			if ( !this->world_to_screen( eight , &s8 ) ) return;

			double x_array[ 8 ] = { s1.x, s2.x, s3.x, s4.x, s5.x, s6.x, s7.x, s8.x };
			float right = x_array[ 0 ] , left = x_array[ 0 ];

			for ( auto right_idx = 0; right_idx < 8; right_idx++ )
				if ( x_array[ right_idx ] > right )
					right = x_array[ right_idx ];

			for ( auto left_idx = 0; left_idx < 8; left_idx++ )
				if ( x_array[ left_idx ] < left )
					left = x_array[ left_idx ];

			engine::fvector min , max , size;
			min.x = left;
			min.y = root_position.y;

			max.x = right;
			max.y = head_position.y;

			size.x = min.x - max.x;
			size.y = min.y - max.y;

			ImGui::GetForegroundDrawList( )->AddLine( ImVec2( max.x , max.y ) , ImVec2( max.x + size.x , max.y ) , ImColor( 255 , 0 , 0 , 255 ) , 1.f );
			ImGui::GetForegroundDrawList( )->AddLine( ImVec2( max.x , max.y ) , ImVec2( max.x , max.y + size.y ) , ImColor( 255 , 0 , 0 , 255 ) , 1.f );
			ImGui::GetForegroundDrawList( )->AddLine( ImVec2( max.x + size.x , max.y ) , ImVec2( max.x + size.x , max.y + size.y ) , ImColor( 255 , 0 , 0 , 255 ) , 1.f );
			ImGui::GetForegroundDrawList( )->AddLine( ImVec2( max.x , max.y + size.y ) , ImVec2( max.x , max.y + size.y ) , ImColor( 255 , 0 , 0 , 255 ) , 1.f );

			//printf( encrypt( "actor : %llx\n" ) , player.m_actor );
		}
	}
}