#include <core/external/render/render.h>

#define maybe; ;

namespace riot
{
	namespace entity
	{
		class c_interface
		{
			std::mutex						m_mutex;
			std::vector <c_list>			m_actor_list;

		public:
			c_interface( );

			void update_matrix( );
			bool world_to_screen( engine::fvector& world_location , engine::fvector2d* screen_position );

			bool is_visible( );

			void get_world( );
			void cache_actors( );

			void render( c_list const entity );
			void tick( );

			engine::u_world*				m_world{ };
			engine::a_game_state_base*		m_game_state{ };
			engine::u_game_instance*		m_owning_game_instance{ };
			engine::u_localplayer*			m_local_player{ };
			engine::u_scene_view_state*		m_view_state{ };

			engine::frotator				m_rotation{ };
			engine::fvector					m_location{ };
			float							m_field_of_view = 0;

			std::vector<c_list>				m_list{ };

			std::function<void( )>			render_queue{ };
		};
	}
}