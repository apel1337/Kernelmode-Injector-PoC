#include <core/external/render/render.h>

namespace riot
{
	namespace render
	{
		bool c_interface::setup( std::uint32_t process_pid )
		{
			m_window = get_window_handle( process_pid );

			auto get_window = this->get_window( );
			if ( !get_window ) {
				printf( encrypt( " > failed to get window info.\n" ) );
				return false;
			}

			auto hijack_overlay = this->hijack_overlay( );
			if ( !hijack_overlay ) {
				printf( encrypt( " > failed to hijack overlay.\n" ) );
				return false;
			}

			auto create_swapchain = create_device( );
			if ( !create_swapchain ) {
				printf( encrypt( " > failed to create swapchain.\n" ) );
				return false;
			}

			auto create_render_view = create_target( );
			if ( !create_render_view ) {
				printf( encrypt( " > failed to create target view.\n" ) );
				return false;
			}

			auto create_imgui = this->create_imgui( );
			if ( !create_imgui ) {
				printf( encrypt( " > failed to create imgui.\n" ) );
				return false;
			}

			return true;
		}

		bool c_interface::get_window( )
		{
			auto result = GetWindowRect( m_window , &m_rect );
			if ( !result ) {
				return false;
			}

			m_width = m_rect.right - m_rect.left;
			m_height = m_rect.bottom - m_rect.top;

			m_width_center = m_width / 2;
			m_height_center = m_height / 2;

			return true;
		}

		HWND c_interface::get_window_handle( DWORD pid )
		{
			std::pair<HWND , DWORD> params = { 0, pid };

			BOOL bResult = EnumWindows( [ ] ( HWND hwnd , LPARAM lParam ) -> BOOL
				{
					auto pParams = ( std::pair<HWND , DWORD>* )( lParam );

					DWORD processId;
					if ( GetWindowThreadProcessId( hwnd , &processId ) && processId == pParams->second ) {
						SetLastError( -1 );
						pParams->first = hwnd;
						return FALSE;
					}

					// Continue enumerating
					return TRUE;
				} ,
				( LPARAM ) &params );

			if ( !bResult && GetLastError( ) == -1 && params.first ) {
				return params.first;
			}

			return 0;
		}

		bool c_interface::create_target( )
		{
			ID3D11Texture2D* render_buffer{ nullptr };
			auto result = m_swapchain->GetBuffer( 0 , __uuidof( ID3D11Texture2D ) , reinterpret_cast< void** >( &render_buffer ) );
			if ( FAILED( result ) ) {
				return false;
			}

			result = m_device->CreateRenderTargetView( render_buffer , nullptr , &m_target_view );
			if ( FAILED( result ) ) {
				return false;
			}

			render_buffer->Release( );
			return true;
		}

		bool c_interface::create_device( )
		{
			// refresh rate
			DXGI_RATIONAL refresh_rate{};
			ZeroMemory( &refresh_rate , sizeof( DXGI_RATIONAL ) );
			refresh_rate.Numerator = 0;
			refresh_rate.Denominator = 1;

			// buffer
			DXGI_MODE_DESC buffer_desc{};
			ZeroMemory( &buffer_desc , sizeof( DXGI_MODE_DESC ) );
			buffer_desc.Width = m_width;
			buffer_desc.Height = m_height;
			buffer_desc.RefreshRate = refresh_rate;
			buffer_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
			buffer_desc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
			buffer_desc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;

			// sample
			DXGI_SAMPLE_DESC sample_desc{};
			ZeroMemory( &sample_desc , sizeof( DXGI_SAMPLE_DESC ) );
			sample_desc.Count = 1;
			sample_desc.Quality = 0;

			// Swapchain
			DXGI_SWAP_CHAIN_DESC swapchain_desc{};
			ZeroMemory( &swapchain_desc , sizeof( DXGI_SWAP_CHAIN_DESC ) );
			swapchain_desc.BufferDesc = buffer_desc;
			swapchain_desc.SampleDesc = sample_desc;
			swapchain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
			swapchain_desc.BufferCount = 2;
			swapchain_desc.OutputWindow = m_overlay;
			swapchain_desc.Windowed = TRUE;
			swapchain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
			swapchain_desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

			auto ret = D3D11CreateDeviceAndSwapChain(
				NULL ,
				D3D_DRIVER_TYPE_HARDWARE ,
				NULL ,
				NULL ,
				0 ,
				0 ,
				D3D11_SDK_VERSION ,
				&swapchain_desc ,
				&m_swapchain ,
				&m_device ,
				0 ,
				&m_device_context );

			if ( FAILED( ret ) ) {
				return false;
			}

			return true;
		}

		bool c_interface::create_imgui( )
		{
			ImGui::CreateContext( );

			auto imgui_win32 = ImGui_ImplWin32_Init( m_overlay );
			if ( !imgui_win32 ) {
				std::printf( encrypt( "failed to load imgui Win32.\n" ) );
				return false;
			}

			auto imgui_dx11 = ImGui_ImplDX11_Init( m_device , m_device_context );
			if ( !imgui_dx11 ) {
				std::printf( encrypt( "failed to load imgui.\n" ) );
				return false;
			}

			ImGuiIO& io = ImGui::GetIO( );
			ImFontConfig fontCfg = ImFontConfig( );
			io.DeltaTime = 1.0f / 60.0f;

			fontCfg.OversampleH = fontCfg.OversampleV = 1;
			fontCfg.PixelSnapH = true;

			m_font = ImGui::GetIO( ).Fonts->AddFontFromFileTTF( encrypt( "C:\\Windows\\Fonts\\Arial.ttf" ) , 14.0f );

			return true;
		}

		bool c_interface::hijack_overlay( )
		{
			m_overlay = FindWindowA( encrypt( "CiceroUIWndFrame" ) , encrypt( "CiceroUIWndFrame" ) );
			if ( !m_overlay ) {
				std::printf( encrypt( "failed to find overlay.\n" ) );
				return false;
			}

			ShowWindow( m_overlay , SW_SHOW );

			MARGINS margins = { -1 };
			DwmExtendFrameIntoClientArea( m_overlay , &margins );
			SetWindowLongA( m_overlay , GWL_EXSTYLE , WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_TRANSPARENT );
			SetWindowPos( m_overlay , 0 , 0 , 0 , m_width , m_height , SWP_NOREDRAW );
			UpdateWindow( m_overlay );

			return true;
		}

		void c_interface::end_scene( )
		{
			const float color[ ]{ 0, 0, 0, 0 };

			ImGui::Render( );
			ImGui::EndFrame( );

			m_device_context->OMSetRenderTargets( 1 , &m_target_view , nullptr );
			m_device_context->ClearRenderTargetView( m_target_view , color );
			ImGui_ImplDX11_RenderDrawData( ImGui::GetDrawData( ) );

			// 1, 0 for vsync.
			m_swapchain->Present( 1 , 0 );
		}

		void c_interface::release_objects( )
		{
			if ( m_target_view ) 
			{
				m_target_view->Release( );
				m_target_view = nullptr;
			}

			if ( m_device_context ) 
			{
				m_device_context->Release( );
				m_device_context = nullptr;
			}

			if ( m_device ) 
			{
				m_device->Release( );
				m_device = nullptr;
			}

			if ( m_swapchain ) 
			{
				m_swapchain->Release( );
				m_swapchain = nullptr;
			}
		}

		void c_interface::clean_context( )
		{
			ImGui_ImplDX11_Shutdown( );
			ImGui_ImplWin32_Shutdown( );
			ImGui::DestroyContext( );
			DestroyWindow( m_overlay );
		}

		void c_interface::begin_scene( )
		{
			ImGui_ImplDX11_NewFrame( );
			POINT p;
			GetCursorPos( &p );
			ImGuiIO& io = ImGui::GetIO( );
			io.MousePos = ImVec2( p.x , p.y );
			io.MouseDown[ 0 ] = ( GetKeyState( VK_LBUTTON ) & 0x8000 ) != 0;
			io.MouseDown[ 1 ] = ( GetKeyState( VK_RBUTTON ) & 0x8000 ) != 0;
			ImGui_ImplWin32_NewFrame( );
			ImGui::NewFrame( );
		}

		bool c_interface::get_screen_status( )
		{
			if ( m_window == GetForegroundWindow( ) ) {
				return true;
			}

			if ( m_window == GetActiveWindow( ) ) {
				return true;
			}

			if ( GetActiveWindow( ) == GetForegroundWindow( ) ) {
				return true;
			}

			return false;
		}

		void c_interface::tick( const std::function< void( )>& fn )
		{
			constexpr auto flag = 0x0001;
			constexpr auto wm_quit = 0x0012;

			while (
				this->m_msg.message
				!= wm_quit ) {

				if ( PeekMessageA(
					&this->m_msg ,
					this->m_overlay ,
					0 ,
					0 ,
					flag ) ) {

					TranslateMessage( &this->m_msg );
					DispatchMessageA( &this->m_msg );
				}

				this->begin_scene( );
				{
					if ( this->get_screen_status( ) )
					{
						fn( );
					}
				}
				this->end_scene( );
			}

			this->release_objects( );
			this->clean_context( );
		}
	}
}