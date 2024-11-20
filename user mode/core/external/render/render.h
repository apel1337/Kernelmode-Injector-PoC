#include <core/external/dependencies/engine/engine.h>
#include <core/external/dependencies/entities/entities.hpp>
#include <core/external/dependencies/math/math.hpp>

#include <core/backend/libraries/imgui/imgui.h>
#include <core/backend/libraries/imgui/imgui_impl_win32.h>
#include <core/backend/libraries/imgui/imgui_impl_dx11.h>

namespace riot
{
	namespace render
	{
		class c_interface
		{
		public:
			bool setup( std::uint32_t process_pid );

			bool create_device( );
			bool create_target( );
			bool create_imgui( );
			bool hijack_overlay( );

			bool get_window( );
			HWND get_window_handle( DWORD pid );

			void end_scene( );
			void begin_scene( );
			bool get_screen_status( );

			void clean_context( );
			void release_objects( );

			void tick( const std::function< void( )>& fn );


			int							m_width{ };
			int							m_height{ };

			int							m_width_center{ };
			int							m_height_center{ };

		private:

			HINSTANCE					m_instance{ };
			MARGINS						m_margin{ -1 };

			RECT						m_rect{ };
			ImFont*						m_font{ };

			HWND						m_window{ };
			HWND						m_overlay{ };

		private:
			MSG							m_msg { nullptr };

			std::mutex					m_mutex{};

			ID3D11Device*				m_device{ nullptr };
			IDXGISwapChain*				m_swapchain{ nullptr };
			ID3D11DeviceContext*		m_device_context{ nullptr };
			ID3D11RenderTargetView*		m_target_view{ nullptr };
		};
	} inline auto overlay = std::make_unique<render::c_interface>( );
}