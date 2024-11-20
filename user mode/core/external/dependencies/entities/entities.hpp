
namespace riot
{
	namespace entity
	{
		class c_item {
		private:
		public:

		};

		class c_actor {
		private:
		public:

		};

		class c_list {
		private:
		public:
			c_list( ) = default;
			c_list(
				std::uint32_t index ,
				engine::a_fort_player_pawn_athena* actor ,
				engine::a_fort_player_state_athena* state )
				: m_index( index ) , m_actor( actor ) , m_state( state ) {}

			std::uint32_t								m_index;

			engine::a_fort_player_pawn_athena*			m_actor;
			engine::a_fort_player_state_athena*			m_state;
			engine::a_fort_player_pawn_athena_t*		m_visible;
		};
	}
}